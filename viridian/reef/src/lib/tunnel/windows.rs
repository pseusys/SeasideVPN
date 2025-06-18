use std::collections::{HashMap, HashSet};
use std::mem::replace;
use std::net::{AddrParseError, Ipv4Addr};
use std::num::ParseIntError;
use std::sync::Arc;

use ipnet::Ipv4Net;
use log::{debug, error, info, warn};
use serde::Deserialize;
use simple_error::{bail, SimpleError};
use tun::{create_as_async, AsyncDevice, Configuration};
use tokio::task::JoinHandle;
use windivert::layer::NetworkLayer;
use windivert::packet::WinDivertPacket;
use windivert::{CloseAction, WinDivert};
use windivert::prelude::{WinDivertFlags, WinDivertShutdownMode};
use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{GetAdaptersAddresses, GetBestRoute, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH, MIB_IPFORWARDROW};
use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};
use wmi::{COMLibrary, WMIConnection};

use super::TunnelInternal;
use crate::bytes::{get_buffer, ByteBuffer};
use crate::{run_coroutine_in_thread, run_coroutine_sync, DynResult};


const ZERO_IP_ADDRESS: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);


unsafe fn get_default_interface_by_remote_address(destination_ip: Ipv4Addr) -> DynResult<(Ipv4Addr, u32)> {
    let dest_ip = destination_ip.into();
    let src_ip = ZERO_IP_ADDRESS.into();

    let mut route: MIB_IPFORWARDROW = MIB_IPFORWARDROW::default();
    let result = GetBestRoute(dest_ip, src_ip, &mut route);

    if WIN32_ERROR(result) == ERROR_SUCCESS {
        let default_gateway = Ipv4Addr::from(route.dwForwardNextHop);
        let defult_interface = route.dwForwardIfIndex;
        Ok((default_gateway, defult_interface))
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

unsafe fn get_interface_index(interface_name: &str) -> DynResult<u32> {
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

        if adapter.AdapterName.to_string()? == interface_name {
            return Ok(adapter.Anonymous1.Anonymous.IfIndex);
        }

        current_adapter = adapter.Next;
    }

    bail!("No interfaces found for interface with name {interface_name}!")
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


trait RecvProcess {
    async fn receive<'a>(&self, buffer: ByteBuffer<'a>) -> DynResult<WinDivertPacket<'a, NetworkLayer>>;
    async fn packet_process_loop(&self, tunnel_cidr: u32) -> DynResult<()>;
}

impl RecvProcess for Arc<WinDivert<NetworkLayer>> {
    async fn receive<'a>(&self, buffer: ByteBuffer<'a>) -> DynResult<WinDivertPacket<'a, NetworkLayer>> {
        let result = match self.recv(Some(&mut buffer.slice_mut())) {
            Ok(packet) => Ok(packet.into_owned()),
            Err(err) => Err(err)
        };
        match result {
            Ok(packet) => Ok(packet),
            Err(err) => Err(Box::new(err))
        }
    }

    async fn packet_process_loop(&self, tunnel_index: u32) -> DynResult<()> {
        loop {
            let buffer = get_buffer(None).await;
            let mut packet = match self.receive(buffer).await {
                Ok(packet) => packet,
                Err(err) => {
                    warn!("Error receiving packet: {err}!");
                    continue;
                },
            };
            packet.address.set_interface_index(tunnel_index);
            if let Err(err) = self.send(&packet) {
                warn!("Error sending packet: {err}!");
            }
        }
    }
}

fn enable_routing(seaside_address: Ipv4Addr, default_index: u32, default_network: Ipv4Net, tunnel_index: u32, dns_addresses: Vec<Ipv4Addr>, capture_iface: HashSet<String>, capture_ranges: HashSet<Ipv4Net>, exempt_ranges: HashSet<Ipv4Net>) -> DynResult<(Arc<WinDivert<NetworkLayer>>, JoinHandle<DynResult<()>>)> {
    let mut exempt_filter = exempt_ranges.iter().map(|i| format!("not (remoteAddr >= {} and remoteAddr <= {})", i.network(), i.broadcast())).collect::<Vec<String>>().join(" and ");
    if exempt_filter.is_empty() {
        exempt_filter = String::from("true");
    }

    let mut capture_range_filter = capture_ranges.iter().map(|i| format!("(remoteAddr >= {} and remoteAddr <= {})", i.network(), i.broadcast())).collect::<Vec<String>>().join(" or ");
    if capture_range_filter.is_empty() {
        capture_range_filter = String::from("false");
    }

    let capture_iface_result: DynResult<Vec<String>> = capture_iface.iter().map(|i| {
        let net_idx = i.parse().map_err(|e| Box::new(e))?;
        let (network, _) = unsafe { get_interface_details(net_idx) }?;
        Ok(format!("((ifIdx == {i}) and not (remoteAddr >= {} and remoteAddr <= {}))", network.network(), network.broadcast()))
    }).collect();
    let mut capture_iface_filter = capture_iface_result?.join(" or ");
    if capture_iface_filter.is_empty() {
        capture_iface_filter = String::from("false");
    }

    let dns_filter = dns_addresses.iter().map(|i| format!("remoteAddr != {i}")).collect::<Vec<String>>().join(" and ");
    let caerulean_filter = format!("not ((ifIdx == {default_index}) and (localAddress == {}) and (remoteAddress == {})", default_network.addr(), seaside_address);

    let filter = format!("ip and outbound and ({exempt_filter}) and ({capture_range_filter} or {capture_iface_filter}) and ({dns_filter}) and ({caerulean_filter})");
    let divert = WinDivert::network(filter, 0, WinDivertFlags::new())?;

    let divert_arc = Arc::new(divert);
    let divert_clone = divert_arc.clone();
    let handle = run_coroutine_in_thread!(divert_clone.packet_process_loop(tunnel_index));
    Ok((divert_arc, handle))
}


fn create_tunnel(name: &str, address: Ipv4Addr, netmask: Ipv4Addr, mtu: u16) -> DynResult<AsyncDevice> {
    let mut config = Configuration::default();
    config.address(address).netmask(netmask).tun_name(name).mtu(mtu).up();
    match create_as_async(&config) {
        Ok(device) => Ok(device),
        Err(err) => bail!("Error creating tunnel: {}", err)
    }
}


pub struct PlatformInternalConfig {
    divert: Arc<WinDivert<NetworkLayer>>,
    handle: Option<JoinHandle<DynResult<()>>>,
    dns_data: HashMap<u32, Vec<String>>
}

impl TunnelInternal {
    pub fn new(seaside_address: Ipv4Addr, tunnel_name: &str, tunnel_network: Ipv4Net, _: u8, dns: Option<Ipv4Addr>, mut capture_iface: HashSet<String>, capture_ranges: HashSet<Ipv4Net>, exempt_ranges: HashSet<Ipv4Net>, local_address: Option<Ipv4Addr>) -> DynResult<TunnelInternal> {
        debug!("Checking system default network properties...");
        let (default_gateway, default_interface) = if let Some(address) = local_address {
            (address, unsafe { get_default_interface_by_local_address(address) }?)
        } else {
            unsafe { get_default_interface_by_remote_address(seaside_address) }?
        };
        let (default_network, default_mtu) = unsafe { get_interface_details(default_interface) }?;
        debug!("Default network properties received: network {default_network}, MTU {default_mtu}, gateway {default_gateway}");

        if capture_iface.is_empty() && capture_ranges.is_empty() {
            debug!("The default interface added to capture: {default_interface}");
            capture_iface.insert(default_interface.to_string());
        }

        debug!("Creating tunnel device: address {}, netmask {}...", tunnel_network.addr(), tunnel_network.netmask());
        let tunnel_device = create_tunnel(tunnel_name, tunnel_network.addr(), tunnel_network.netmask(), default_mtu as u16)?;
        let tunnel_index = unsafe { get_interface_index(tunnel_name) }?;

        debug!("Setting DNS address to {dns:?}...");
        let interfaces: Result<Vec<u32>, ParseIntError> = capture_iface.iter().map(|s| s.parse()).collect();
        let (dns_addresses, dns_data) = set_dns_addresses(HashSet::from_iter(interfaces?), dns)?;
        debug!("The DNS server for interfaces were set to: {dns_addresses:?}");

        debug!("Setting up routing...");
        let (divert, handle) = enable_routing(seaside_address, default_interface, default_network, tunnel_index, dns_addresses, capture_iface, capture_ranges, exempt_ranges)?;

        let internal = PlatformInternalConfig {divert, handle: Some(handle), dns_data};
        Ok(TunnelInternal {tun_device: tunnel_device, _internal: internal})
    }
}

impl Drop for PlatformInternalConfig {
    #[allow(unused_must_use)]
    fn drop(&mut self) {
        run_coroutine_sync!(async {
            // TODO: change once https://github.com/Rubensei/windivert-rust/issues/14 is resolved.
            debug!("Retrieving routing handle...");
            let divert = unsafe { &mut *(Arc::as_ptr(&self.divert) as *mut WinDivert<NetworkLayer>) };

            debug!("Resetting routing...");
            divert.shutdown(WinDivertShutdownMode::Both).inspect_err(|e| error!("Error shutting down WinDivert: {}", e));
            divert.close(CloseAction::Nothing).inspect_err(|e| error!("Error closing WinDivert: {}", e));

            debug!("Closing handle routing...");
            let decay = replace(&mut self.handle, None);
            if let Some(thread) = decay {
                let result = thread.await.expect("WinDivert thread termination error!");
                result.inspect_err(|r| info!("WinDivert thread terminated with: {r}"));
            }

            debug!("Reverting DNS servers...");
            reset_dns_addresses(&self.dns_data).inspect_err(|e| error!("Error resetting DNS addresses: {}", e));
        });
    }
}
