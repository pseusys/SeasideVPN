use std::collections::{HashMap, HashSet};
use std::mem::{align_of, replace};
use std::net::{AddrParseError, Ipv4Addr};
use std::num::ParseIntError;
use std::sync::Arc;

use ipnet::Ipv4Net;
use log::{debug, error, info, warn};
use serde::Deserialize;
use simple_error::{bail, SimpleError};
use tokio::task::JoinHandle;
use tun::{create_as_async, AsyncDevice, Configuration};
use windivert::layer::NetworkLayer;
use windivert::{CloseAction, WinDivert};
use windivert::prelude::{WinDivertFlags, WinDivertShutdownMode};
use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{GetAdaptersAddresses, GetBestRoute, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_UNICAST_ADDRESS_LH, MIB_IPFORWARDROW};
use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};
use wmi::{COMLibrary, WMIConnection};

use crate::bytes::get_buffer;

use crate::{run_coroutine_in_thread, run_coroutine_sync, DynResult};


const ZERO_IP_ADDRESS: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
const DEFAULT_SUBINTERFACE: u32 = 0;


unsafe fn get_default_interface_by_remote_address(destination_ip: Ipv4Addr) -> DynResult<u32> {
    let dest_ip = u32::from(destination_ip).to_be();
    let src_ip = u32::from(ZERO_IP_ADDRESS).to_be();

    let mut route: MIB_IPFORWARDROW = MIB_IPFORWARDROW::default();
    let result = GetBestRoute(dest_ip, src_ip, &mut route);

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
    let buffer_slice = buffer.slice_mut();
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


fn create_tunnel(name: &str, address: Ipv4Addr, netmask: Ipv4Addr, mtu: u16) -> DynResult<AsyncDevice> {
    let mut config = Configuration::default();
    config.address(address).netmask(netmask).tun_name(name).mtu(mtu).up();
    let tunnel = match create_as_async(&config) {
        Ok(device) => Ok(device),
        Err(err) => bail!("Error creating tunnel: {}", err)
    };
    tunnel
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
    async fn packet_receive_loop(&self, tunnel_interface: u32) -> DynResult<()>;
}

impl PacketExchangeProcess for Arc<WinDivert<NetworkLayer>> {
    async fn packet_receive_loop(&self, tunnel_interface: u32) -> DynResult<()> {
        loop {
            let buffer = get_buffer(None).await;
            let mut packet_slice =  buffer.slice_mut();
            let mut packet = match self.recv(Some(&mut packet_slice)) {
                Ok(res) => {
                    debug!("Captured a local packet, length: {}", res.data.len());
                    res
                },
                Err(err) => {
                    warn!("Error capturing packet: {err}!");
                    continue;
                }
            };
            packet.address.set_interface_index(tunnel_interface);
            packet.address.set_subinterface_index(DEFAULT_SUBINTERFACE);
            packet.address.set_outbound(true);
            match self.send(&packet) {
                Ok(res) => {
                    debug!("Inserted a packet into a tunnel, length: {}", res);
                },
                Err(err) => {
                    warn!("Error inserting packet into a tunnel: {err}!");
                    continue;
                }
            };
        }
    }
}

async fn enable_routing(seaside_address: Ipv4Addr, default_index: u32, default_network: Ipv4Net, divert_priority: i16, tunnel_interface: u32, dns_addresses: Vec<Ipv4Addr>, capture_iface: HashSet<String>, capture_ranges: HashSet<Ipv4Net>, exempt_ranges: HashSet<Ipv4Net>, capture_ports: Option<(u16, u16)>, exempt_ports: Option<(u16, u16)>) -> DynResult<(Arc<WinDivert<NetworkLayer>>, JoinHandle<DynResult<()>>)> {
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
    let divert_clone = divert_arc.clone();
    let receive_handle = run_coroutine_in_thread!(divert_clone.packet_receive_loop(tunnel_interface));
    Ok((divert_arc, receive_handle))
}


pub struct TunnelInternal {
    pub default_address: Ipv4Addr,
    pub tunnel_device: Arc<AsyncDevice>,
    divert: Arc<WinDivert<NetworkLayer>>,
    handle: Option<JoinHandle<DynResult<()>>>,
    dns_data: HashMap<u32, Vec<String>>
}

impl TunnelInternal {
    pub async fn new(seaside_address: Ipv4Addr, tunnel_name: &str, tunnel_network: Ipv4Net, svr_index: u8, dns: Option<Ipv4Addr>, mut capture_iface: HashSet<String>, capture_ranges: HashSet<Ipv4Net>, exempt_ranges: HashSet<Ipv4Net>, capture_ports: Option<(u16, u16)>, exempt_ports: Option<(u16, u16)>, local_address: Option<Ipv4Addr>) -> DynResult<Self> {
        debug!("Checking system default network properties...");
        let default_interface = if let Some(address) = local_address {
            unsafe { get_default_interface_by_local_address(address).await }?
        } else {
            unsafe { get_default_interface_by_remote_address(seaside_address) }?
        };
        let (default_network, default_mtu) = unsafe { get_interface_details(default_interface).await }?;
        debug!("Default network properties received: network {default_network}, MTU {default_mtu}");
        let default_address = default_network.addr();

        if capture_iface.is_empty() && capture_ranges.is_empty() && capture_ports.is_none() {
            debug!("The default interface added to capture: {default_interface}");
            capture_iface.insert(default_interface.to_string());
        }

        debug!("Creating tunnel device: address {}, netmask {}...", tunnel_network.addr(), tunnel_network.netmask());
        let tunnel_device = Arc::new(create_tunnel(tunnel_name, tunnel_network.addr(), tunnel_network.netmask(), default_mtu as u16)?);
        let tunnel_index = unsafe { get_default_interface_by_local_address(tunnel_network.addr()).await }?;

        debug!("Setting DNS address to {dns:?}...");
        let interfaces: Result<Vec<u32>, ParseIntError> = capture_iface.iter().map(|s| s.parse()).collect();
        let (dns_addresses, dns_data) = set_dns_addresses(HashSet::from_iter(interfaces?), dns)?;
        debug!("The DNS server for interfaces were set to: {dns_addresses:?}");

        debug!("Setting up routing...");
        let (divert, handle) = enable_routing(seaside_address, default_interface, default_network, svr_index as i16, tunnel_index, dns_addresses, capture_iface, capture_ranges, exempt_ranges, capture_ports, exempt_ports).await?;
        Ok(Self {default_address, divert, tunnel_device, handle: Some(handle), dns_data})
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

            debug!("Waiting for handle thread...");
            let receive_decay = replace(&mut self.handle, None);
            if let Some(thread) = receive_decay {
                let result = thread.await.expect("WinDivert thread termination error!");
                result.inspect_err(|r| info!("WinDivert thread terminated with: {r}"));
            }

            debug!("Reverting DNS servers...");
            reset_dns_addresses(&self.dns_data).inspect_err(|e| error!("Error resetting DNS addresses: {}", e));
        });
    }
}
