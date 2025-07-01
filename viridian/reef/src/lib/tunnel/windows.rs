use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::mem::{align_of, replace};
use std::net::{AddrParseError, Ipv4Addr};
use std::num::ParseIntError;
use std::sync::Arc;

use cached::proc_macro::cached;
use etherparse::icmpv4::DestUnreachableHeader;
use etherparse::{Icmpv4Header, Icmpv4Type, IpNumber, Ipv4Header, Ipv4HeaderSlice};
use ipnet::Ipv4Net;
use log::{debug, error, info};
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
use windows::Win32::NetworkManagement::IpHelper::{GetAdaptersAddresses, GetBestRoute, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_UNICAST_ADDRESS_LH, MIB_IPFORWARDROW};
use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};
use wmi::{COMLibrary, WMIConnection};

use crate::bytes::get_buffer;
use crate::tunnel::ptr_utils::{ConstSendPtr, LocalConstTunnelTransport, RemoteConstTunnelTransport};
use crate::{run_coroutine_in_thread, run_coroutine_sync, DynResult};
use super::Tunnelling;
use super::ptr_utils::{LocalMutTunnelTransport, MutSendPtr, RemoteMutTunnelTransport};


const ZERO_IP_ADDRESS: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
const DEFAULT_SUBINTERFACE_INDEX: u32 = 0;
const FRAGMENT_BYTES: usize = 8;
const FRAGMENT_TTL: u8 = 64;


#[cached(size=1024, result=true)]
fn get_default_interface_by_remote_address(destination_ip: Ipv4Addr) -> DynResult<u32> {
    let dest_ip = u32::from(destination_ip).to_be();
    let src_ip = u32::from(ZERO_IP_ADDRESS).to_be();

    let mut route: MIB_IPFORWARDROW = MIB_IPFORWARDROW::default();
    let result = unsafe { GetBestRoute(dest_ip, src_ip, &mut route) };

    if WIN32_ERROR(result) == ERROR_SUCCESS {
        Ok(route.dwForwardIfIndex)
    } else {
        bail!("Default route for ip {destination_ip} failed with error {}!", result)
    }
}

async unsafe fn get_default_interface<T, P: Fn(*mut IP_ADAPTER_UNICAST_ADDRESS_LH, &IP_ADAPTER_ADDRESSES_LH) -> DynResult<Option<T>>>(processor: P) -> DynResult<Option<T>> {
    let mut buffer_size: u32 = 0;

    let result = GetAdaptersAddresses(AF_INET.0 as u32, GAA_FLAG_INCLUDE_PREFIX, None, None, &mut buffer_size);
    if WIN32_ERROR(result) != ERROR_BUFFER_OVERFLOW {
        bail!("Empty call to 'GetAdaptersAddresses' resulted with error {result}!");
    }

    let buffer = get_buffer(Some(buffer_size as usize + align_of::<u64>() - 1)).await;
    let mut buffer_slice = buffer.slice_mut();
    let (_, buffer_aligned, _) = buffer_slice.align_to_mut::<u64>();
    let adapter_addresses = buffer_aligned.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

    let result = GetAdaptersAddresses(AF_INET.0 as u32, GAA_FLAG_INCLUDE_PREFIX, None, Some(adapter_addresses), &mut buffer_size);
    if WIN32_ERROR(result) != ERROR_SUCCESS {
        bail!("Call to 'GetAdaptersAddresses' resulted with error {result}!");
    }

    let mut current_adapter = adapter_addresses;
    while !current_adapter.is_null() {
        let adapter = *current_adapter ;
        let mut unicast_ptr = adapter.FirstUnicastAddress;

        while !unicast_ptr.is_null() {
            match processor(unicast_ptr, &adapter)? {
                Some(res) => return Ok(Some(res)),
                None => unicast_ptr = (*unicast_ptr).Next
            };
        }

        current_adapter = adapter.Next;
    }

    Ok(None)
}

async unsafe fn get_default_interface_by_local_address(local_ip: Ipv4Addr) -> DynResult<u32> {
    unsafe fn process_interface(unicast: *mut IP_ADAPTER_UNICAST_ADDRESS_LH, adapter: &IP_ADAPTER_ADDRESSES_LH, local_ip: Ipv4Addr) -> DynResult<Option<u32>> {
        let sockaddr = *(*unicast).Address.lpSockaddr;
        if sockaddr.sa_family == AF_INET {
            let sockaddr_in = *((*unicast).Address.lpSockaddr as *const SOCKADDR_IN);
            let addr = Ipv4Addr::from(u32::from_be(sockaddr_in.sin_addr.S_un.S_addr));
            if addr == local_ip {
                return Ok(Some(adapter.Anonymous1.Anonymous.IfIndex));
            }
        }
        Ok(None)
    }

    match get_default_interface(|u, a| process_interface(u, a, local_ip)).await {
        Ok(Some(res)) => Ok(res),
        Ok(None) => bail!("No interfaces with IP address {local_ip}!"),
        Err(err) => bail!("Error processing interface addresses: {err}!")
    }
}

async unsafe fn get_interface_details(interface_index: u32) -> DynResult<(Ipv4Net, u32)> {
    unsafe fn process_interface(unicast: *mut IP_ADAPTER_UNICAST_ADDRESS_LH, adapter: &IP_ADAPTER_ADDRESSES_LH, interface_index: u32) -> DynResult<Option<(Ipv4Net, u32)>> {
        let sockaddr = *(*unicast).Address.lpSockaddr;
        if sockaddr.sa_family == AF_INET && adapter.Anonymous1.Anonymous.IfIndex == interface_index {
            let sockaddr_in = *((*unicast).Address.lpSockaddr as *const SOCKADDR_IN);
            let ip_addr = Ipv4Addr::from(u32::from_be(sockaddr_in.sin_addr.S_un.S_addr));
            let prefix_len = (*unicast).OnLinkPrefixLength;
            return Ok(Some((Ipv4Net::new(ip_addr, prefix_len)?, adapter.Mtu)));
        }
        Ok(None)
    }

    match get_default_interface(|u, a| process_interface(u, a, interface_index)).await {
        Ok(Some(res)) => Ok(res),
        Ok(None) => bail!("No IP addresses found for interface with index {interface_index}!"),
        Err(err) => bail!("Error processing interface addresses: {err}!")
    }
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
    async fn build_icmp_frag_needed_packet<'a>(&self, original_ip_packet: &WinDivertPacket<'a, NetworkLayer>, mtu: u16) -> DynResult<WinDivertPacket<'a, NetworkLayer>>;
    async fn packet_receive_loop(&self, queue: RemoteConstTunnelTransport) -> DynResult<()>;
    async fn packet_send_loop(&self, mtu: usize, queue: RemoteMutTunnelTransport) -> DynResult<()>;
}

impl PacketExchangeProcess for Arc<WinDivert<NetworkLayer>> {
    async fn build_icmp_frag_needed_packet<'a>(&self, original_packet: &WinDivertPacket<'a, NetworkLayer>, mtu: u16) -> DynResult<WinDivertPacket<'a, NetworkLayer>> {
        let original_ip_header = Ipv4HeaderSlice::from_slice(&original_packet.data)?;
        let payload_length = original_ip_header.payload_len()? as usize;

        if payload_length < FRAGMENT_BYTES {
            bail!("Insufficient payload length: {payload_length} bytes!");
        }

        let mut icmp_header = Icmpv4Header::new(Icmpv4Type::DestinationUnreachable(DestUnreachableHeader::FragmentationNeeded { next_hop_mtu: mtu }));
        let icmp_payload = &original_packet.data[..original_ip_header.slice().len() + FRAGMENT_BYTES];
        icmp_header.update_checksum(icmp_payload);

        let mut ip_header = Ipv4Header::new((icmp_header.header_len() + icmp_payload.len()) as u16, FRAGMENT_TTL, IpNumber::ICMP, original_ip_header.destination(), original_ip_header.source())?;
        ip_header.header_checksum = ip_header.calc_header_checksum();
        
        let buffer = get_buffer(None).await;
        buffer.append(&ip_header.to_bytes());
        buffer.append(&icmp_header.to_bytes());
        buffer.append(icmp_payload);

        let mut address = unsafe { WinDivertAddress::<NetworkLayer>::new() };
        address.set_interface_index(original_packet.address.interface_index());
        address.set_subinterface_index(original_packet.address.subinterface_index());
        address.set_outbound(true);
        Ok(WinDivertPacket {
            address,
            data: Cow::Owned(buffer.into())
        })
    }

    async fn packet_receive_loop(&self, mut queue: RemoteConstTunnelTransport) -> DynResult<()> {
        loop {
            let value = queue.receive().await?;
            let raw_packet = value.recreate();
            debug!("Captured a remote packet, length: {}", value.len());
            let interface_index = match Ipv4HeaderSlice::from_slice(raw_packet) {
                Ok(res) => {
                    match get_default_interface_by_remote_address(res.source_addr()) {
                        Ok(res) => res,
                        Err(err) => {
                            debug!("Error calculating interface index for packet: {err}");
                            continue;
                        }
                    }
                },
                Err(err) => {
                    debug!("Error parsing packet header: {err}");
                    continue;
                }
            };
            let mut address = unsafe { WinDivertAddress::<NetworkLayer>::new() };
            address.set_interface_index(interface_index);
            address.set_subinterface_index(DEFAULT_SUBINTERFACE_INDEX);
            address.set_outbound(false);
            let packet = WinDivertPacket {address, data: Cow::Borrowed(raw_packet)};
            match self.send(&packet) {
                Ok(res) => {
                    debug!("Inserting remote packet into a tunnel (interface {interface_index}), length: {res}");
                    queue.send(res as usize).await?;
                },
                Err(err) => bail!("Closing receive loop: {err}!")
            };
        }
    }

    async fn packet_send_loop(&self, mtu: usize, mut queue: RemoteMutTunnelTransport) -> DynResult<()> {
        'outer: loop {
            let value = queue.receive().await?;
            'inner: loop {
                let packet = match self.recv(Some(value.recreate())) {
                    Ok(res) => {
                        debug!("Captured a local packet, length: {}", res.data.len());
                        res
                    },
                    Err(err) => bail!("Closing send loop: {err}!")
                };
                let packet_length = packet.data.len();
                if packet_length > mtu {
                    debug!("Packet too long: {packet_length} bytes!");
                    match self.build_icmp_frag_needed_packet(&packet, mtu as u16).await {
                        Ok(res) => {
                            debug!("Sending fragmentation request, length: {}", res.data.len());
                            self.send(&res)?;
                        },
                        Err(err) => debug!("Error constructing 'fragmentation needed' packet: {err}"),
                    };
                    continue 'inner;
                } else {
                    debug!("Inserting local packet into a tunnel, length: {packet_length}");
                    queue.send(packet_length).await?;
                    continue 'outer;
                }
            }
        }
    }
}

async fn enable_routing(seaside_address: Ipv4Addr, default_index: u32, default_network: Ipv4Net, divert_priority: i16, default_mtu: u32, receive_queue: RemoteConstTunnelTransport, send_queue: RemoteMutTunnelTransport, dns_addresses: Vec<Ipv4Addr>, capture_iface: HashSet<String>, capture_ranges: HashSet<Ipv4Net>, exempt_ranges: HashSet<Ipv4Net>, capture_ports: Option<(u16, u16)>, exempt_ports: Option<(u16, u16)>) -> DynResult<(Arc<WinDivert<NetworkLayer>>, JoinHandle<DynResult<()>>, JoinHandle<DynResult<()>>)> {
    let exempt_ports_filter = if let Some((lowest, highest)) = exempt_ports {
        format!("tcp? (tcp.SrcPort < {} or tcp.SrcPort > {}): (udp.SrcPort < {} or udp.SrcPort > {})", lowest, highest, lowest, highest)
    } else {
        String::from("true")
    };

    let mut exempt_range_filter = exempt_ranges.iter().map(|i| format!("(ip.DstAddr < {} or ip.DstAddr > {})", i.network(), i.broadcast())).collect::<Vec<String>>().join(" and ");
    if exempt_range_filter.is_empty() {
        exempt_range_filter = String::from("true");
    }

    let capture_ports_filter = if let Some((lowest, highest)) = capture_ports {
        format!("(tcp.SrcPort >= {} and tcp.SrcPort <= {}) or (udp.SrcPort >= {} and udp.SrcPort <= {})", lowest, highest, lowest, highest)
    } else {
        String::from("false")
    };

    let mut capture_range_filter = capture_ranges.iter().map(|i| format!("(ip.DstAddr >= {} and ip.DstAddr <= {})", i.network(), i.broadcast())).collect::<Vec<String>>().join(" or ");
    if capture_range_filter.is_empty() {
        capture_range_filter = String::from("false");
    }

    let mut capture_networks_result = Vec::new();
    for iface in capture_iface {
        let net_idx = iface.parse().map_err(|e| Box::new(e))?;
        let (network, _) = unsafe { get_interface_details(net_idx).await }?;
        let filter = format!("((ifIdx == {iface}) and (ip.DstAddr < {} or ip.DstAddr > {}))", network.network(), network.broadcast());
        capture_networks_result.push(filter);
    };
    let mut capture_iface_filter = capture_networks_result.join(" or ");
    if capture_iface_filter.is_empty() {
        capture_iface_filter = String::from("false");
    }

    let dns_filter = dns_addresses.iter().map(|i| format!("ip.DstAddr != {i}")).collect::<Vec<String>>().join(" and ");
    let caerulean_filter = format!("(ifIdx != {default_index}) or (ip.SrcAddr != {}) or (ip.DstAddr != {})", default_network.addr(), seaside_address);

    let filter = format!("ip and outbound and (({exempt_ports_filter}) and ({exempt_range_filter})) and (({capture_ports_filter}) or {capture_range_filter} or {capture_iface_filter}) and ({dns_filter}) and ({caerulean_filter})");
    debug!("WinDivert filter will be used: '{filter}'");
    let divert = WinDivert::network(filter, divert_priority, WinDivertFlags::new())?;

    let divert_arc = Arc::new(divert);
    let receive_divert_clone = divert_arc.clone();
    let send_divert_clone = divert_arc.clone();
    let receive_handle = run_coroutine_in_thread!(receive_divert_clone.packet_receive_loop(receive_queue));
    let send_handle = run_coroutine_in_thread!(send_divert_clone.packet_send_loop(default_mtu as usize, send_queue));
    Ok((divert_arc, receive_handle, send_handle))
}


pub struct TunnelInternal {
    pub default_address: Ipv4Addr,
    divert: Arc<WinDivert<NetworkLayer>>,
    send_queue: RwLock<LocalMutTunnelTransport>,
    receive_queue: RwLock<LocalConstTunnelTransport>,
    send_handle: Option<JoinHandle<DynResult<()>>>,
    receive_handle: Option<JoinHandle<DynResult<()>>>,
    dns_data: HashMap<u32, Vec<String>>
}

impl TunnelInternal {
    pub async fn new(seaside_address: Ipv4Addr, _: &str, _: Ipv4Net, svr_index: u8, dns: Option<Ipv4Addr>, mut capture_iface: HashSet<String>, capture_ranges: HashSet<Ipv4Net>, exempt_ranges: HashSet<Ipv4Net>, capture_ports: Option<(u16, u16)>, exempt_ports: Option<(u16, u16)>, local_address: Option<Ipv4Addr>) -> DynResult<Self> {
        debug!("Checking system default network properties...");
        let default_interface = if let Some(address) = local_address {
            unsafe { get_default_interface_by_local_address(address).await }?
        } else {
            get_default_interface_by_remote_address(seaside_address)?
        };
        let (default_network, default_mtu) = unsafe { get_interface_details(default_interface).await }?;
        debug!("Default network properties received: network {default_network}, MTU {default_mtu}");
        let default_address = default_network.addr();

        if capture_iface.is_empty() && capture_ranges.is_empty() && capture_ports.is_none() {
            debug!("The default interface added to capture: {default_interface}");
            capture_iface.insert(default_interface.to_string());
        }

        debug!("Setting DNS address to {dns:?}...");
        let interfaces: Result<Vec<u32>, ParseIntError> = capture_iface.iter().map(|s| s.parse()).collect();
        let (dns_addresses, dns_data) = set_dns_addresses(HashSet::from_iter(interfaces?), dns)?;
        debug!("The DNS server for interfaces were set to: {dns_addresses:?}");

        debug!("Setting up routing...");
        let (remote_send_sender, local_send_receiver) = channel(None);
        let (local_send_sender, remote_send_receiver) = channel(None);
        let remote_send_queue = RemoteMutTunnelTransport::new(remote_send_sender, remote_send_receiver);
        let local_send_queue = RwLock::new(LocalMutTunnelTransport::new(local_send_sender, local_send_receiver));
        let (remote_receive_sender, local_receive_receiver) = channel(None);
        let (local_receive_sender, remote_receive_receiver) = channel(None);
        let remote_receive_queue = RemoteConstTunnelTransport::new(remote_receive_sender, remote_receive_receiver);
        let local_receive_queue = RwLock::new(LocalConstTunnelTransport::new(local_receive_sender, local_receive_receiver));
        let (divert, receive_handle, send_handle) = enable_routing(seaside_address, default_interface, default_network, svr_index as i16, default_mtu, remote_receive_queue, remote_send_queue, dns_addresses, capture_iface, capture_ranges, exempt_ranges, capture_ports, exempt_ports).await?;
        
        debug!("Creating tunnel object...");
        Ok(Self {default_address, divert, send_queue: local_send_queue, receive_queue: local_receive_queue, send_handle: Some(send_handle), receive_handle: Some(receive_handle), dns_data})
    }
}

impl Tunnelling for TunnelInternal {
    async fn recv(&self, buf: &mut [u8]) -> DynResult<usize> {
        let pointer = MutSendPtr::new(buf);
        let mut writer = self.send_queue.write().await;
        writer.send(pointer).await?;
        writer.receive().await
    }

    async fn send(&self, buf: &[u8]) -> DynResult<usize> {
        let pointer = ConstSendPtr::new(buf);
        let mut writer = self.receive_queue.write().await;
        writer.send(pointer).await?;
        writer.receive().await
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
            divert.shutdown(WinDivertShutdownMode::Both).inspect_err(|e| error!("Error shutting down WinDivert: {e}"));
            divert.close(CloseAction::Nothing).inspect_err(|e| error!("Error closing WinDivert: {e}"));

            debug!("Closing routing queue (receive)...");
            let mut receive_queue_writer = self.receive_queue.write().await;
            receive_queue_writer.close().await.inspect_err(|e| info!("Error closing receive tunnel queue: {e}"));

            debug!("Closing routing queue (send)...");
            let mut send_queue_writer = self.send_queue.write().await;
            send_queue_writer.close().await.inspect_err(|e| info!("Error closing send tunnel queue: {e}"));

            debug!("Waiting for handle thread (receive)...");
            let receive_handle = replace(&mut self.receive_handle, None);
            if let Some(thread) = receive_handle {
                let result = thread.await.expect("WinDivert receive thread termination error!");
                result.inspect_err(|e| info!("WinDivert receive thread terminated with: {e}"));
            }

            debug!("Waiting for handle thread (send)...");
            let send_handle = replace(&mut self.send_handle, None);
            if let Some(thread) = send_handle {
                let result = thread.await.expect("WinDivert send thread termination error!");
                result.inspect_err(|e| info!("WinDivert send thread terminated with: {e}"));
            }

            debug!("Reverting DNS servers...");
            reset_dns_addresses(&self.dns_data).inspect_err(|e| error!("Error resetting DNS addresses: {e}"));
        });
    }
}
