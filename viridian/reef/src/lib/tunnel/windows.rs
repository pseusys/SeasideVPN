use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::mem::replace;
use std::net::{AddrParseError, Ipv4Addr};
use std::num::ParseIntError;
use std::sync::Arc;

use ipnet::Ipv4Net;
use log::{debug, error, info, warn};
use serde::Deserialize;
use simple_error::{bail, SimpleError};
use tokio::sync::watch::channel;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use windivert::address::WinDivertAddress;
use windivert::layer::NetworkLayer;
use windivert::packet::WinDivertPacket;
use windivert::{CloseAction, WinDivert};
use windivert::prelude::{WinDivertFlags, WinDivertShutdownMode};
use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{GetAdaptersAddresses, GetBestRoute, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH, MIB_IPFORWARDROW};
use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};
use wmi::{COMLibrary, WMIConnection};

use crate::tunnel::ptr_utils::{ConstSendPtr, LocalConstTunnelTransport, LocalMutTunnelTransport, MutSendPtr, RemoteConstTunnelTransport, RemoteMutTunnelTransport};
use crate::tunnel::Tunnelling;
use crate::{run_coroutine_in_thread, run_coroutine_sync, DynResult};


const ZERO_IP_ADDRESS: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);


unsafe fn get_default_interface_by_remote_address(destination_ip: Ipv4Addr) -> DynResult<u32> {
    let dest_ip = destination_ip.into();
    let src_ip = ZERO_IP_ADDRESS.into();

    let mut route: MIB_IPFORWARDROW = MIB_IPFORWARDROW::default();
    let result = GetBestRoute(dest_ip, src_ip, &mut route);

    if WIN32_ERROR(result) == ERROR_SUCCESS {
        Ok(route.dwForwardIfIndex)
    } else {
        bail!("Default route for ip {destination_ip} failed with error {}!", result)
    }
}

unsafe fn get_default_interface_by_local_address(local_ip: Ipv4Addr) -> DynResult<u32> {
    let mut buffer_size: u32 = 0;

    let result = GetAdaptersAddresses(AF_INET.0 as u32, GAA_FLAG_INCLUDE_PREFIX, None, None, &mut buffer_size);
    if WIN32_ERROR(result) != ERROR_BUFFER_OVERFLOW {
        bail!("Empty call to 'GetAdaptersAddresses' resulted with error {result}!");
    }

    let mut buffer: Vec<u8> = vec![0; buffer_size as usize];
    let adapter_addresses = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

    let result = GetAdaptersAddresses(AF_INET.0 as u32, GAA_FLAG_INCLUDE_PREFIX, None, Some(adapter_addresses), &mut buffer_size);
    if WIN32_ERROR(result) != ERROR_SUCCESS {
        bail!("Call to 'GetAdaptersAddresses' resulted with error {result}!");
    }

    let mut current_adapter = adapter_addresses;
    while !current_adapter.is_null() {
        let adapter = *current_adapter ;
        let mut unicast_ptr = adapter.FirstUnicastAddress;

        while !unicast_ptr.is_null() {
            let sockaddr = *(*unicast_ptr).Address.lpSockaddr;

            if sockaddr.sa_family == AF_INET {
                let sockaddr_in = *((*unicast_ptr).Address.lpSockaddr as *const SOCKADDR_IN);
                let addr = Ipv4Addr::from(u32::from_be(sockaddr_in.sin_addr.S_un.S_addr));

                if addr == local_ip {
                    return Ok(adapter.Anonymous1.Anonymous.IfIndex);
                }
            }

            unicast_ptr = (*unicast_ptr).Next;
        }

        current_adapter = adapter.Next;
    }

    bail!("No interfaces with IP address {local_ip}!")
}

unsafe fn get_interface_details(interface_index: u32) -> DynResult<(Ipv4Net, u32)> {
    let mut buffer_size: u32 = 0;

    let result = GetAdaptersAddresses(AF_INET.0 as u32, GAA_FLAG_INCLUDE_PREFIX, None, None, &mut buffer_size);
    if WIN32_ERROR(result) != ERROR_BUFFER_OVERFLOW {
        bail!("Empty call to 'GetAdaptersAddresses' resulted with error {result}!");
    }

    let mut buffer: Vec<u8> = vec![0; buffer_size as usize];
    let adapter_addresses = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

    let result = GetAdaptersAddresses(AF_INET.0 as u32, GAA_FLAG_INCLUDE_PREFIX, None, Some(adapter_addresses), &mut buffer_size);
    if WIN32_ERROR(result) != ERROR_SUCCESS {
        bail!("Call to 'GetAdaptersAddresses' resulted with error {result}!");
    }

    let mut current_adapter = adapter_addresses;
    while !current_adapter.is_null() {
        let adapter = *current_adapter;
        let mut unicast_ptr = adapter.FirstUnicastAddress;

        while !unicast_ptr.is_null() {
            let sockaddr = *(*unicast_ptr).Address.lpSockaddr;

            if sockaddr.sa_family == AF_INET && adapter.Anonymous1.Anonymous.IfIndex == interface_index {
                let sockaddr_in = *((*unicast_ptr).Address.lpSockaddr as *const SOCKADDR_IN);
                let ip_addr = Ipv4Addr::from(u32::from_be(sockaddr_in.sin_addr.S_un.S_addr));
                let prefix_len = (*unicast_ptr).OnLinkPrefixLength;
                return Ok((Ipv4Net::new(ip_addr, prefix_len)?, adapter.Mtu));
            }

            unicast_ptr = (*unicast_ptr).Next;
        }

        current_adapter = adapter.Next;
    }

    bail!("No IP addresses found for interface with index {interface_index}!")
}


#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
struct AdapterConfig {
    index: u32,
    ip_enabled: bool,
    dns_server_search_order: Vec<String>
}

pub fn set_dns_addresses(interface_indexes: HashSet<u32>, dns_address: Option<Ipv4Addr>) -> DynResult<(Vec<Ipv4Addr>, HashMap<u32, Vec<String>>)> {
    let com_con = COMLibrary::new()?;
    let wmi_con = WMIConnection::new(com_con.into())?;
    let adapters: Vec<AdapterConfig> = wmi_con.raw_query("SELECT Index, IPEnabled, DNSServerSearchOrder FROM Win32_NetworkAdapterConfiguration")?;
    let active_adapters: Vec<AdapterConfig> = adapters.into_iter().filter(|a| a.ip_enabled && interface_indexes.contains(&a.index)).collect();
    
    let mut dns_data = HashMap::new();
    let mut dns_servers = HashSet::new();

    if let Some(address) = dns_address {
        dns_servers.insert(address);
        for adapter in active_adapters {
            dns_data.insert(adapter.index, adapter.dns_server_search_order.clone());
            let in_params_getter = wmi_con.get_object("Win32_NetworkAdapterConfiguration")?.get_method("SetDNSServerSearchOrder")?;
            let in_params = in_params_getter.ok_or_else(|| SimpleError::new("IWebMClassWrapper is None!"))?.spawn_instance()?;
            in_params.put_property("Index", adapter.index)?;
            in_params.put_property("DNSServerSearchOrder", vec![address.to_string()])?;
            wmi_con.exec_method("Win32_NetworkAdapterConfiguration", "SetDNSServerSearchOrder", Some(&in_params))?;
        }
    } else {
        for adapter in active_adapters {
            dns_data.insert(adapter.index, adapter.dns_server_search_order.clone());
            let order_addr: Result<Vec<Ipv4Addr>, AddrParseError> = adapter.dns_server_search_order.iter().map(|a| a.parse()).collect();
            dns_servers.extend(order_addr?);
        }
    }
    Ok((Vec::from_iter(dns_servers), dns_data))
}

fn reset_dns_addresses(dns_data: &HashMap<u32, Vec<String>>) -> DynResult<()> {
    let com_con = COMLibrary::new()?;
    let wmi_con = WMIConnection::new(com_con.into())?;

    for (iface, search_order) in dns_data {
        let in_params_getter = wmi_con.get_object("Win32_NetworkAdapterConfiguration")?.get_method("SetDNSServerSearchOrder")?;
        let in_params = in_params_getter.ok_or_else(|| SimpleError::new("IWebMClassWrapper is None!"))?.spawn_instance()?;
        in_params.put_property("Index", iface.clone())?;
        in_params.put_property("DNSServerSearchOrder", search_order.clone())?;
        wmi_con.exec_method("Win32_NetworkAdapterConfiguration", "SetDNSServerSearchOrder", Some(&in_params))?;
    }
    Ok(())
}


trait PacketExchangeProcess {
    async fn packet_receive_loop(&self, receive_tunnel_queue: RemoteMutTunnelTransport) -> DynResult<()>;
    async fn packet_send_loop(&self, send_tunnel_queue: RemoteConstTunnelTransport, default_interface: u32) -> DynResult<()>;
}

impl PacketExchangeProcess for Arc<WinDivert<NetworkLayer>> {
    async fn packet_receive_loop(&self, mut receive_tunnel_queue: RemoteMutTunnelTransport) -> DynResult<()> {
        loop {
            let value = receive_tunnel_queue.receive().await?;
            match self.recv(Some(value.recreate())) {
                Ok(res) => {
                    debug!("Capturing a packet, length: {}", res.data.len());
                    receive_tunnel_queue.send(res.data.len()).await?
                },
                Err(err) => {
                    warn!("Error receiving packet: {err}!");
                    continue;
                }
            };
        }
    }

    async fn packet_send_loop(&self, mut send_tunnel_queue: RemoteConstTunnelTransport, default_interface: u32) -> DynResult<()> {
        loop {
            let value = send_tunnel_queue.receive().await?;
            let mut address = unsafe { WinDivertAddress::<NetworkLayer>::new() };
            address.set_interface_index(default_interface);
            address.set_subinterface_index(0);
            address.set_outbound(false);
            let packet = WinDivertPacket {
                address: address,
                data: Cow::Borrowed(value.recreate())
            };
            match self.send(&packet) {
                Ok(res) => {
                    debug!("Inserting a packet, length: {}", res);
                    send_tunnel_queue.send(res as usize).await?
                },
                Err(err) => {
                    warn!("Error sending packet: {err}!");
                    continue;
                }
            };
        }
    }
}

fn enable_routing(seaside_address: Ipv4Addr, default_index: u32, default_network: Ipv4Net, receive_tunnel_queue: RemoteMutTunnelTransport, send_tunnel_queue: RemoteConstTunnelTransport, dns_addresses: Vec<Ipv4Addr>, capture_iface: HashSet<String>, capture_ranges: HashSet<Ipv4Net>, exempt_ranges: HashSet<Ipv4Net>) -> DynResult<(Arc<WinDivert<NetworkLayer>>, JoinHandle<DynResult<()>>, JoinHandle<DynResult<()>>)> {
    let mut exempt_filter = exempt_ranges.iter().map(|i| format!("(ip.DstAddr <= {} or ip.DstAddr >= {})", i.network(), i.broadcast())).collect::<Vec<String>>().join(" and ");
    if exempt_filter.is_empty() {
        exempt_filter = String::from("true");
    }

    let mut capture_range_filter = capture_ranges.iter().map(|i| format!("(ip.DstAddr <= {} or ip.DstAddr >= {})", i.network(), i.broadcast())).collect::<Vec<String>>().join(" or ");
    if capture_range_filter.is_empty() {
        capture_range_filter = String::from("false");
    }

    let capture_iface_result: DynResult<Vec<String>> = capture_iface.iter().map(|i| {
        let net_idx = i.parse().map_err(|e| Box::new(e))?;
        let (network, _) = unsafe { get_interface_details(net_idx) }?;
        Ok(format!("((ifIdx == {i}) and (ip.DstAddr <= {} or ip.DstAddr >= {}))", network.network(), network.broadcast()))
    }).collect();
    let mut capture_iface_filter = capture_iface_result?.join(" or ");
    if capture_iface_filter.is_empty() {
        capture_iface_filter = String::from("false");
    }

    let dns_filter = dns_addresses.iter().map(|i| format!("ip.DstAddr != {i}")).collect::<Vec<String>>().join(" and ");
    let caerulean_filter = format!("(ifIdx != {default_index}) or (ip.SrcAddr != {}) or (ip.DstAddr != {})", default_network.addr(), seaside_address);

    let filter = format!("ip and outbound and ({exempt_filter}) and ({capture_range_filter} or {capture_iface_filter}) and ({dns_filter}) and ({caerulean_filter})");
    debug!("WinDivert filter will be used: '{filter}'");
    let divert = WinDivert::network(filter, 0, WinDivertFlags::new())?;

    let divert_arc = Arc::new(divert);
    let divert_clone_receive = divert_arc.clone();
    let divert_clone_send = divert_arc.clone();
    let receive_handle = run_coroutine_in_thread!(divert_clone_receive.packet_receive_loop(receive_tunnel_queue));
    let send_handle = run_coroutine_in_thread!(divert_clone_send.packet_send_loop(send_tunnel_queue, default_index));
    Ok((divert_arc, receive_handle, send_handle))
}


pub struct TunnelInternal {
    pub default_address: Ipv4Addr,
    receive_transport: RwLock<LocalMutTunnelTransport>,
    send_transport: RwLock<LocalConstTunnelTransport>,
    divert: Arc<WinDivert<NetworkLayer>>,
    receive_handle: Option<JoinHandle<DynResult<()>>>,
    send_handle: Option<JoinHandle<DynResult<()>>>,
    dns_data: HashMap<u32, Vec<String>>
}

impl TunnelInternal {
    pub fn new(seaside_address: Ipv4Addr, seaside_port: u16, _: &str, _: Ipv4Net, _: u8, dns: Option<Ipv4Addr>, mut capture_iface: HashSet<String>, capture_ranges: HashSet<Ipv4Net>, exempt_ranges: HashSet<Ipv4Net>, local_address: Option<Ipv4Addr>) -> DynResult<Self> {

        let _: () = {  // TODO: REMOVE!!!
            log::debug!("TEST BLOCK 2 STARTED");
            let peer_address = std::net::SocketAddr::new(std::net::IpAddr::V4(seaside_address), seaside_port);
            let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?.into();
            let connection_socket = tokio::net::TcpSocket::from_std_stream(socket);

            if let Some(adr) = local_address {
                let local_address = std::net::SocketAddr::new(std::net::IpAddr::V4(adr), 0);
                log::debug!("Binding connection client to {}...", local_address);
                connection_socket.bind(local_address)?;
            }

            log::debug!("Connecting to listener at {}", peer_address);
            let connection_stream = run_coroutine_sync!(async { connection_socket.connect(peer_address).await })?;
            log::debug!("Current user address: {}", connection_stream.local_addr()?);
            log::debug!("TEST BLOCK 2 ENDED");
        };

        debug!("Checking system default network properties...");
        let default_interface = if let Some(address) = local_address {
            unsafe { get_default_interface_by_local_address(address) }?
        } else {
            unsafe { get_default_interface_by_remote_address(seaside_address) }?
        };
        let (default_network, default_mtu) = unsafe { get_interface_details(default_interface) }?;
        debug!("Default network properties received: network {default_network}, MTU {default_mtu}");
        let default_address = default_network.addr();

        let _: () = {  // TODO: REMOVE!!!
            log::debug!("TEST BLOCK 3 STARTED");
            let peer_address = std::net::SocketAddr::new(std::net::IpAddr::V4(seaside_address), seaside_port);
            let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?.into();
            let connection_socket = tokio::net::TcpSocket::from_std_stream(socket);

            if let Some(adr) = local_address {
                let local_address = std::net::SocketAddr::new(std::net::IpAddr::V4(adr), 0);
                log::debug!("Binding connection client to {}...", local_address);
                connection_socket.bind(local_address)?;
            }

            log::debug!("Connecting to listener at {}", peer_address);
            let connection_stream = run_coroutine_sync!(async { connection_socket.connect(peer_address).await })?;
            log::debug!("Current user address: {}", connection_stream.local_addr()?);
            log::debug!("TEST BLOCK 3 ENDED");
        };

        if capture_iface.is_empty() && capture_ranges.is_empty() {
            debug!("The default interface added to capture: {default_interface}");
            capture_iface.insert(default_interface.to_string());
        }

        debug!("Creating tunnel queue...");
        let (receive_container_sender, receive_container_receiver) = channel(None);
        let (receive_data_sender, receive_data_receiver) = channel(None);
        let (send_container_sender, send_container_receiver) = channel(None);
        let (send_data_sender, send_data_receiver) = channel(None);

        debug!("Setting DNS address to {dns:?}...");
        let interfaces: Result<Vec<u32>, ParseIntError> = capture_iface.iter().map(|s| s.parse()).collect();
        let (dns_addresses, dns_data) = set_dns_addresses(HashSet::from_iter(interfaces?), dns)?;
        debug!("The DNS server for interfaces were set to: {dns_addresses:?}");

        let _: () = {  // TODO: REMOVE!!!
            log::debug!("TEST BLOCK 4 STARTED");
            let peer_address = std::net::SocketAddr::new(std::net::IpAddr::V4(seaside_address), seaside_port);
            let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?.into();
            let connection_socket = tokio::net::TcpSocket::from_std_stream(socket);

            if let Some(adr) = local_address {
                let local_address = std::net::SocketAddr::new(std::net::IpAddr::V4(adr), 0);
                log::debug!("Binding connection client to {}...", local_address);
                connection_socket.bind(local_address)?;
            }

            log::debug!("Connecting to listener at {}", peer_address);
            let connection_stream = run_coroutine_sync!(async { connection_socket.connect(peer_address).await })?;
            log::debug!("Current user address: {}", connection_stream.local_addr()?);
            log::debug!("TEST BLOCK 4 ENDED");
        };

        debug!("Setting up routing...");
        let remote_receive_transport = RemoteMutTunnelTransport::new(receive_container_sender, receive_data_receiver);
        let remote_send_transport = RemoteConstTunnelTransport::new(send_container_sender, send_data_receiver);
        let (divert, receive_handle, send_handle) = enable_routing(seaside_address, default_interface, default_network, remote_receive_transport, remote_send_transport, dns_addresses, capture_iface, capture_ranges, exempt_ranges)?;

        let _: () = {  // TODO: REMOVE!!!
            log::debug!("TEST BLOCK 5 STARTED");
            let peer_address = std::net::SocketAddr::new(std::net::IpAddr::V4(seaside_address), seaside_port);
            let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?.into();
            let connection_socket = tokio::net::TcpSocket::from_std_stream(socket);

            if let Some(adr) = local_address {
                let local_address = std::net::SocketAddr::new(std::net::IpAddr::V4(adr), 0);
                log::debug!("Binding connection client to {}...", local_address);
                connection_socket.bind(local_address)?;
            }

            log::debug!("Connecting to listener at {}", peer_address);
            let connection_stream = run_coroutine_sync!(async { connection_socket.connect(peer_address).await })?;
            log::debug!("Current user address: {}", connection_stream.local_addr()?);
            log::debug!("TEST BLOCK 5 ENDED");
        };

        debug!("Creating tunnel handle...");
        let local_receive_transport = RwLock::new(LocalMutTunnelTransport::new(receive_data_sender, receive_container_receiver));
        let local_send_transport = RwLock::new(LocalConstTunnelTransport::new(send_data_sender, send_container_receiver));
        Ok(Self {default_address, receive_transport: local_receive_transport, send_transport: local_send_transport, divert, receive_handle: Some(receive_handle), send_handle: Some(send_handle), dns_data})
    }
}

impl Drop for TunnelInternal {
    #[allow(unused_must_use)]
    fn drop(&mut self) {
        run_coroutine_sync!(async {
            // TODO: change once https://github.com/Rubensei/windivert-rust/issues/14 is resolved.
            debug!("Retrieving routing handle...");
            let divert = unsafe { &mut *(Arc::as_ptr(&self.divert) as *mut WinDivert<NetworkLayer>) };

            debug!("Resetting routing...");
            divert.shutdown(WinDivertShutdownMode::Both).inspect_err(|e| error!("Error shutting down WinDivert: {}", e));
            divert.close(CloseAction::Nothing).inspect_err(|e| error!("Error closing WinDivert: {}", e));

            debug!("Closing handle routing (receive)...");
            let mut receive_writer = self.receive_transport.write().await;
            receive_writer.close().await.inspect_err(|r| info!("Error closing receiving tunnel queue: {r}"));

            debug!("Waiting for handle thread (receive)...");
            let receive_decay = replace(&mut self.receive_handle, None);
            if let Some(thread) = receive_decay {
                let result = thread.await.expect("WinDivert thread termination error!");
                result.inspect_err(|r| info!("WinDivert thread terminated with: {r}"));
            }

            debug!("Closing handle routing (send)...");
            let mut send_writer = self.send_transport.write().await;
            send_writer.close().await.inspect_err(|r| info!("Error closing sending tunnel queue: {r}"));

            debug!("Waiting for handle thread (send)...");
            let send_decay = replace(&mut self.send_handle, None);
            if let Some(thread) = send_decay {
                let result = thread.await.expect("WinDivert thread termination error!");
                result.inspect_err(|r| info!("WinDivert thread terminated with: {r}"));
            }

            debug!("Reverting DNS servers...");
            reset_dns_addresses(&self.dns_data).inspect_err(|e| error!("Error resetting DNS addresses: {}", e));
        });
    }
}


impl Tunnelling for TunnelInternal {
    async fn recv(&self, buf: &mut [u8]) -> DynResult<usize> {
        let send_pointer = MutSendPtr::new(buf);
        let mut writer = self.receive_transport.write().await;
        writer.send(send_pointer).await?;
        writer.receive().await
    }

    async fn send(&self, buf: &[u8]) -> DynResult<usize> {
        let send_pointer = ConstSendPtr::new(buf);
        let mut writer = self.send_transport.write().await;
        writer.send(send_pointer).await?;
        writer.receive().await
    }
}
