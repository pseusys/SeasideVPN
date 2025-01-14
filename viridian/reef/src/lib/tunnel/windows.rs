use std::borrow::{BorrowMut, Cow};
use std::error::Error;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use etherparse::{IpHeaders, Ipv4Dscp};
use ipnet::Ipv4Net;
use log::{debug, info};
use simple_error::bail;
use tokio::select;
use tokio::sync::watch::{channel, Receiver, Sender};
use tokio::task::{spawn, spawn_blocking};
use windivert::layer::NetworkLayer;
use windivert::packet::WinDivertPacket;
use windivert::WinDivert;
use windivert::prelude::WinDivertFlags;
use windivert_sys::ChecksumFlags;
use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{GetAdaptersAddresses, GetBestRoute, GAA_FLAG_INCLUDE_PREFIX, MIB_IPFORWARDROW, IP_ADAPTER_ADDRESSES_LH};
use tun::{create_as_async, AsyncDevice, Configuration};
use windows::Win32::Networking::WinSock::AF_INET;

use super::{bytes_to_ip_address, verify_ip_address, Creatable, Tunnel};
use crate::DynResult;


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


trait RecvProcess {
    async fn arecv<'a>(self: &Arc<Self>, data: &Arc<Mutex<Vec<u8>>>) -> DynResult<WinDivertPacket<'a, NetworkLayer>>;
    fn process_packet<'a>(self: &Arc<Self>, packet: &mut WinDivertPacket<'a, NetworkLayer>, default_network: &Ipv4Net, tunnel_index: u32, svr_idx: u8) -> DynResult<()>;
}

impl RecvProcess for WinDivert<NetworkLayer> {
    async fn arecv<'a>(self: &Arc<Self>, data: &Arc<Mutex<Vec<u8>>>) -> DynResult<WinDivertPacket<'a, NetworkLayer>> {
        let divert = Arc::clone(self);
        let buffer = Arc::clone(data);
        let result = spawn_blocking(move || {
            match divert.recv(Some(&mut buffer.lock().unwrap())) {
                Ok(packet) => Ok(packet.into_owned()),
                Err(err) => Err(err)
            }
        }).await;
        match result {
            Ok(Ok(packet)) => Ok(packet),
            Ok(Err(err)) => Err(Box::new(err)),
            Err(err) => Err(Box::new(err))
        }
    }

    fn process_packet<'a>(self: &Arc<Self>, packet: &mut WinDivertPacket<'a, NetworkLayer>, default_network: &Ipv4Net, tunnel_index: u32, svr_idx: u8) -> DynResult<()> {
        packet.address.set_interface_index(tunnel_index);
        if let Ok((IpHeaders::Ipv4(mut ipv4, _), _)) = IpHeaders::from_ipv4_slice(&packet.data) {
            let source_address = bytes_to_ip_address(&ipv4.source)?;
            if !default_network.contains(&source_address) {
                ipv4.dscp = Ipv4Dscp::try_new(svr_idx)?;
                let header_bytes = ipv4.to_bytes();
                if let Cow::Owned(ref mut data) = packet.data.borrow_mut() {
                    data[..ipv4.header_len()].copy_from_slice(&header_bytes[..]);
                }
            }
        }
        packet.recalculate_checksums(ChecksumFlags::new())?;
        self.send(&packet)?;
        Ok(())
    }
}

async fn enable_routing(default_index: u32, default_address: Ipv4Addr, default_cidr: u8, tunnel_index: u32, svr_idx: u8, mut stop_signal: Receiver<()>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let filter = format!("ip and outbound and ifIdx == {default_index}");
    let divert = WinDivert::network(filter, 0, WinDivertFlags::new())?;
    let default_network = Ipv4Net::new(default_address, default_cidr.leading_ones().try_into()?)?;

    let data = Arc::new(Mutex::new(vec![0u8; u16::MAX.into()]));
    let divert_arc = Arc::new(divert);
    loop {
        select! {
            recvd = divert_arc.arecv(&data) => match recvd {
                Ok(mut packet) => if let Err(err) = divert_arc.process_packet(&mut packet, &default_network, tunnel_index, svr_idx) {
                    debug!("WinDivert packet processing error: {err}");
                },
                Err(err) => debug!("WinDivert packet receiving error: {err}")
            },
            _ = stop_signal.changed() => {
                info!("Terminating WinDivert task...");
                break;
            }
        }
    }
    Ok(())
}


async fn create_tunnel(name: &str, address: Ipv4Addr, netmask: Ipv4Addr, mtu: u16) -> DynResult<AsyncDevice> {
    let mut config = Configuration::default();
    config.address(address).netmask(netmask).tun_name(name).mtu(mtu).up();
    match create_as_async(&config) {
        Ok(device) => Ok(device),
        Err(err) => bail!("Error creating tunnel: {}", err)
    }
}


pub struct PlatformInternalConfig {
    routing_stopper: Sender<()>
}

impl Creatable for Tunnel {
    async fn new(seaside_address: Ipv4Addr, tunnel_name: &str, tunnel_address: Ipv4Addr, tunnel_netmask: Ipv4Addr, svr_index: u8) -> DynResult<Tunnel> {
        verify_ip_address(&seaside_address)?;

        debug!("Checking system default network properties...");
        let (default_gateway, default_interface) = get_default_interface(&seaside_address)?;
        let (default_address, default_cidr, default_mtu) = get_interface_details(default_interface)?;
        debug!("Default network properties received: address {default_address}, CIDR {default_cidr}, MTU {default_mtu}, gateway {default_gateway}");

        debug!("Creating tunnel device...");
        let tunnel_device = create_tunnel(tunnel_name, tunnel_address, tunnel_netmask, default_mtu as u16).await?;
        let tunnel_index = get_interface_index(tunnel_name)?;

        debug!("Setting up routing...");
        let (stop_tx, stop_rx) = channel(());
        // TODO: implement handle dropping once the feature becomes non-experimental: https://doc.rust-lang.org/std/future/trait.AsyncDrop.html
        spawn(enable_routing(default_interface, default_address, default_cidr, tunnel_index, svr_index, stop_rx));

        let internal = PlatformInternalConfig {routing_stopper: stop_tx};
        Ok(Tunnel {def_ip: default_address, def_cidr: default_cidr, tun_device: tunnel_device, internal})
    }
}

impl Drop for Tunnel {
    #[allow(unused_must_use)]
    fn drop(&mut self) {
        debug!("Resetting routing...");
        self.internal.routing_stopper.send(());
    }
}

