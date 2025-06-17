use std::ffi::c_void;
use std::mem::replace;
use std::net::Ipv4Addr;
use std::ptr::null_mut;
use std::sync::Arc;

use etherparse::IpHeaders;
use ipnet::Ipv4Net;
use log::{debug, error, info, warn};
use simple_error::bail;
use tun::{create_as_async, AsyncDevice, Configuration};
use tokio::task::JoinHandle;
use windivert::layer::NetworkLayer;
use windivert::packet::WinDivertPacket;
use windivert::{CloseAction, WinDivert};
use windivert::prelude::{WinDivertFlags, WinDivertShutdownMode};
use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{GetAdaptersAddresses, GetBestRoute, GAA_FLAG_INCLUDE_PREFIX, MIB_IPFORWARDROW, IP_ADAPTER_ADDRESSES_LH};
use windows::Win32::Networking::WinSock::{AF_INET, IN_ADDR, inet_addr};

use super::{bytes_to_ip_address, TunnelInternal};
use crate::bytes::{get_buffer, ByteBuffer};
use crate::{run_coroutine_in_thread, run_coroutine_sync, DynResult};


const ZERO_IP_ADDRESS: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);


fn get_default_interface(destination_ip: &Ipv4Addr) -> DynResult<(Ipv4Addr, u32)> {
    let dest_ip = (*destination_ip).into();
    let src_ip = ZERO_IP_ADDRESS.into();

    let mut route: MIB_IPFORWARDROW = MIB_IPFORWARDROW::default();
    let result = unsafe { GetBestRoute(dest_ip, src_ip, &mut route) };

    if WIN32_ERROR(result) == ERROR_SUCCESS {
        let default_gateway = Ipv4Addr::from(route.dwForwardNextHop);
        let defult_interface = route.dwForwardIfIndex;
        Ok((default_gateway, defult_interface))
    } else {
        bail!("Default route for ip {destination_ip} failed with error {}!", result)
    }
}

fn get_interface_details(interface_index: u32) -> DynResult<(Ipv4Addr, u8, u32)> {
    let mut buffer_size: u32 = 0;

    let result = unsafe { GetAdaptersAddresses(AF_INET.0 as u32, GAA_FLAG_INCLUDE_PREFIX, None, None, &mut buffer_size) };
    if WIN32_ERROR(result) != ERROR_BUFFER_OVERFLOW {
        bail!("Empty call to 'GetAdaptersAddresses' resulted with error {result}!");
    }

    let mut buffer: Vec<u8> = vec![0; buffer_size as usize];
    let adapter_addresses = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

    let result = unsafe { GetAdaptersAddresses(AF_INET.0 as u32, GAA_FLAG_INCLUDE_PREFIX, None, Some(adapter_addresses), &mut buffer_size) };
    if WIN32_ERROR(result) != ERROR_SUCCESS {
        bail!("Call to 'GetAdaptersAddresses' resulted with error {result}!");
    }

    let mut current_adapter = adapter_addresses;
    while !current_adapter.is_null() {
        let adapter = unsafe { *current_adapter };

        if unsafe { adapter.Anonymous1.Anonymous.IfIndex } == interface_index {
            let unicast_addr = unsafe { *adapter.FirstUnicastAddress };
            let socket_bytes = unsafe { (*unicast_addr.Address.lpSockaddr).sa_data };
            let ip_bytes = unsafe { &*(&socket_bytes[2..6] as *const _ as *const [u8]) };
            let ip_addr = Ipv4Addr::from(*<&[u8; 4]>::try_from(ip_bytes)?);
            let prefix_len = unicast_addr.OnLinkPrefixLength;
            return Ok((ip_addr, prefix_len, adapter.Mtu));
        }

        current_adapter = adapter.Next;
    }

    bail!("No IP addresses found for interface with index {interface_index}!")
}

fn get_interface_index(interface_name: &str) -> DynResult<u32> {
    let mut buffer_size: u32 = 0;

    let result = unsafe { GetAdaptersAddresses(AF_INET.0 as u32, GAA_FLAG_INCLUDE_PREFIX, None, None, &mut buffer_size) };
    if WIN32_ERROR(result) != ERROR_BUFFER_OVERFLOW {
        bail!("Empty call to 'GetAdaptersAddresses' resulted with error {result}!");
    }

    let mut buffer: Vec<u8> = vec![0; buffer_size as usize];
    let adapter_addresses = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

    let result = unsafe { GetAdaptersAddresses(AF_INET.0 as u32, GAA_FLAG_INCLUDE_PREFIX, None, Some(adapter_addresses), &mut buffer_size) };
    if WIN32_ERROR(result) != ERROR_SUCCESS {
        bail!("Call to 'GetAdaptersAddresses' resulted with error {result}!");
    }

    let mut current_adapter = adapter_addresses;
    while !current_adapter.is_null() {
        let adapter = unsafe { *current_adapter };

        if unsafe { adapter.AdapterName.to_string()? } == interface_name {
            return Ok(unsafe { adapter.Anonymous1.Anonymous.IfIndex });
        }

        current_adapter = adapter.Next;
    }

    bail!("No interfaces found for interface with name {interface_name}!")
}


fn set_dns_address(interface_index: u32, dns_address: Ipv4Addr) -> Result<()> {
    let dns_addr = inet_addr(PCSTR(dns_ip.as_ptr()));
    if dns_addr == u32::MAX {
        bail!("Invalid DNS IP address");
    }

    let dns_server = NLDNS_SERVER_ADDRESS {
        Version: NL_DNS_SERVER_ADDRESS_VERSION_1,
        Length: std::mem::size_of::<NLDNS_SERVER_ADDRESS>() as u16,
        Anonymous: NLDNS_SERVER_ADDRESS_0 {
            DnsServer: IN_ADDR { S_un: windows::Win32::Networking::WinSock::IN_ADDR_0 { S_addr: dns_addr } },
        },
    };

    let dns_settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: DNS_SETTING_NAMESERVER | DNS_SETTING_DEFAULT_NAME,
        Anonymous: DNS_INTERFACE_SETTINGS_0 {
            SettingV1: DNS_INTERFACE_SETTINGS_0_0 {
                NameServer: PWSTR::null(),
                SearchList: PWSTR::null(),
                RegistrationEnabled: FALSE.into(),
                RegisterAdapterName: FALSE.into(),
                EnableLLMNR: FALSE.into(),
                QueryAdapterName: FALSE.into(),
                ProfileNameServer: PWSTR::null(),
                Domain: PWSTR::null(),
                NameServerList: &dns_server as *const _ as *mut c_void,
                NameServerCount: 1,
            },
        },
    };

    let result = SetInterfaceDnsSettings(interface_index, &dns_settings);
    if result != NO_ERROR {
        bail!("SetInterfaceDnsSettings failed: {}", result);
    }
    Ok(())
}


trait RecvProcess {
    async fn receive<'a>(&self, buffer: ByteBuffer<'a>) -> DynResult<WinDivertPacket<'a, NetworkLayer>>;
    async fn packet_process_loop(&self, default_network: &Ipv4Net, tunnel_cidr: u32) -> DynResult<()>;
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

    async fn packet_process_loop(&self, default_network: &Ipv4Net, tunnel_index: u32) -> DynResult<()> {
        loop {
            let buffer = get_buffer(None).await;
            let mut packet = match self.receive(buffer).await {
                Ok(packet) => packet,
                Err(err) => {
                    warn!("Error receiving packet: {err}!");
                    continue;
                },
            };
            if let Ok((IpHeaders::Ipv4(ipv4, _), _)) = IpHeaders::from_ipv4_slice(&packet.data) {
                let source_address = match bytes_to_ip_address(&ipv4.source) {
                    Ok(res) => res,
                    Err(err) => {
                        warn!("Error parsing source IP address bytes: {err}!");
                        continue;
                    }
                };
                if !default_network.contains(&source_address) {
                    packet.address.set_interface_index(tunnel_index);
                }
            } else {
                warn!("Error parsing packet!");
                continue;
            }
            if let Err(err) = self.send(&packet) {
                warn!("Error sending packet: {err}!");
            }
        }
    }
}

fn enable_routing(default_index: u32, default_address: Ipv4Addr, default_cidr: u8, tunnel_index: u32) -> DynResult<(Arc<WinDivert<NetworkLayer>>, JoinHandle<DynResult<()>>)> {
    let filter = format!("ip and outbound and ifIdx == {default_index}");
    let divert = WinDivert::network(filter, 0, WinDivertFlags::new())?;

    let default_network = Ipv4Net::new(default_address, default_cidr)?;
    let divert_arc = Arc::new(divert);
    let divert_clone = divert_arc.clone();
    let handle = run_coroutine_in_thread!(divert_clone.packet_process_loop(&default_network, tunnel_index));
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
    handle: Option<JoinHandle<DynResult<()>>>
}

impl TunnelInternal {
    pub fn new(seaside_address: Ipv4Addr, tunnel_name: &str, tunnel_network: Ipv4Net, _: u8) -> DynResult<TunnelInternal> {
        debug!("Checking system default network properties...");
        let (default_gateway, default_interface) = get_default_interface(&seaside_address)?;
        let (default_address, default_cidr, default_mtu) = get_interface_details(default_interface)?;
        debug!("Default network properties received: address {default_address}, CIDR {default_cidr}, MTU {default_mtu}, gateway {default_gateway}");

        debug!("Creating tunnel device: address {}, netmask {}...", tunnel_network.addr(), tunnel_network.netmask());
        let tunnel_device = create_tunnel(tunnel_name, tunnel_network.addr(), tunnel_network.netmask(), default_mtu as u16)?;
        let tunnel_index = get_interface_index(tunnel_name)?;

        debug!("Setting DNS address to {dns}...");
        set_dns_address(dns)?;

        debug!("Setting up routing...");
        let (divert, handle) = enable_routing(default_interface, default_address, default_cidr, tunnel_index)?;

        let internal = PlatformInternalConfig {divert, handle: Some(handle)};
        Ok(TunnelInternal {def_ip: default_address, def_cidr: default_cidr, tun_device: tunnel_device, _internal: internal})
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
        });
    }
}
