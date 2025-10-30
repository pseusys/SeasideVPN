#[cfg(test)]
#[path = "../../tests/tunnel/linux.rs"]
mod linux_test;

use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};

use futures::TryStreamExt;
use ipnet::Ipv4Net;
use lazy_static::lazy_static;
use rtnetlink::packet_route::address::AddressAttribute;
use rtnetlink::packet_route::link::LinkAttribute;
use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute};
use rtnetlink::{new_connection, Handle, RouteMessageBuilder};
use simple_error::{bail, require_with};
use tun::{create_as_async, AsyncDevice, Configuration};

use crate::{run_coroutine_async, DynResult};

lazy_static! {
    static ref NETLINK_HANDLE: Handle = {
        let (connection, handle, _) = new_connection().expect("Failed to open RTNETLINK socket!");
        run_coroutine_async!(connection);
        handle
    };
}

#[inline]
#[cfg(not(any(feature = "test", test)))]
pub fn get_handle() -> Handle {
    NETLINK_HANDLE.clone()
}

#[inline]
#[cfg(any(feature = "test", test))]
pub fn get_handle() -> Handle {
    let (connection, handle, _) = new_connection().expect("Failed to open RTNETLINK socket!");
    run_coroutine_async!(connection);
    handle
}

pub async fn get_default_address_and_device(target: Ipv4Addr) -> DynResult<(Ipv4Addr, u32)> {
    let handle = get_handle();
    let mut stream = handle.route().get(RouteMessageBuilder::<Ipv4Addr>::new().build()).execute();
    while let Some(res) = stream.try_next().await? {
        let dest = res.attributes.iter().find_map(|a| match a {
            RouteAttribute::Destination(RouteAddress::Inet(addr)) => Some(addr),
            _ => None,
        });
        let ip = res.attributes.iter().find_map(|a| match a {
            RouteAttribute::PrefSource(RouteAddress::Inet(address)) => Some(address),
            _ => None,
        });
        if dest.is_some() && ip.is_some() {
            let network = Ipv4Net::new(dest.unwrap().clone(), res.header.destination_prefix_length)?;
            if network.contains(ip.unwrap()) {
                let dev = res.attributes.iter().find_map(|a| match a {
                    RouteAttribute::Oif(iface) => Some(iface),
                    _ => None,
                });
                return Ok((*require_with!(ip, "Default IP address was not found!"), *require_with!(dev, "Default network interface was not found!")));
            }
        }
    }
    bail!("Couldn't find any route to {target}!")
}

pub async fn get_device_by_local_address(target: Ipv4Addr) -> DynResult<u32> {
    let handle = get_handle();
    let mut stream = handle.address().get().set_address_filter(IpAddr::V4(target)).execute();
    while let Some(res) = stream.try_next().await? {
        return Ok(res.header.index);
    }
    bail!("Couldn't find any devices for address {target}!")
}

pub async fn get_device_name_and_cidr(device: u32) -> DynResult<(String, u8)> {
    let handle = get_handle();
    let mut stream = handle.address().get().set_link_index_filter(device).execute();
    while let Some(res) = stream.try_next().await? {
        let label = res.attributes.iter().find_map(|a| match a {
            AddressAttribute::Label(label) => Some(label),
            _ => None,
        });
        return Ok((require_with!(label, "Device name was not found!").clone(), res.header.prefix_len));
    }
    bail!("Couldn't find any devices for index {device}!")
}

pub async fn get_device_address_and_cidr(label: &str) -> DynResult<(Ipv4Addr, u8)> {
    let handle = get_handle();
    let mut stream = handle.address().get().execute();
    while let Some(res) = stream.try_next().await? {
        let name = res.attributes.iter().find_map(|a| match a {
            AddressAttribute::Label(label) => Some(label),
            _ => None,
        });
        if name.is_some_and(|n| n == label) {
            let addr = res.attributes.iter().find_map(|a| match a {
                AddressAttribute::Address(IpAddr::V4(addr)) => Some(addr),
                _ => None,
            });
            return Ok((*require_with!(addr, "Network interface IP address was not resolved!"), res.header.prefix_len));
        }
    }
    bail!("Couldn't find any devices for name {label}!")
}

pub async fn get_device_mtu(device: u32) -> DynResult<u32> {
    let handle = get_handle();
    let mut stream = handle.link().get().match_index(device).execute();
    while let Some(res) = stream.try_next().await? {
        let mtu = res.attributes.iter().find_map(|a| match a {
            LinkAttribute::Mtu(mtu) => Some(mtu),
            _ => None,
        });
        return Ok(*require_with!(mtu, "Default network interface MTU was not resolved!"));
    }
    bail!("Couldn't find any links for device {device}!")
}

pub async fn get_address_device(network: Ipv4Net) -> DynResult<u32> {
    let handle = get_handle();
    let broadcast = network.broadcast();
    let mut stream = handle.route().get(RouteMessageBuilder::<Ipv4Addr>::new().build()).execute();
    while let Some(res) = stream.try_next().await? {
        let dest = res.attributes.iter().find_map(|a| match a {
            RouteAttribute::Destination(RouteAddress::Inet(addr)) => Some(addr),
            _ => None,
        });
        if dest.is_some_and(|n| n.clone() == broadcast) {
            let dev = res.attributes.iter().find_map(|a| match a {
                RouteAttribute::Oif(iface) => Some(iface),
                _ => None,
            });
            return Ok(*require_with!(dev, "Tunnel device number was not resolved!"));
        }
    }
    bail!("Couldn't find any route to {network}!")
}

pub async fn get_default_interface_by_local_address(local_address: Ipv4Addr) -> DynResult<(u8, String, u32)> {
    let default_dev = get_device_by_local_address(local_address).await?;
    let (default_name, default_cidr) = get_device_name_and_cidr(default_dev).await?;
    let default_mtu = get_device_mtu(default_dev).await?;
    Ok((default_cidr, default_name, default_mtu))
}

pub async fn get_default_interface_by_remote_address(seaside_address: Ipv4Addr) -> DynResult<(Ipv4Addr, u8, String, u32)> {
    let (default_ip, default_dev) = get_default_address_and_device(seaside_address).await?;
    let (default_name, default_cidr) = get_device_name_and_cidr(default_dev).await?;
    let default_mtu = get_device_mtu(default_dev).await?;
    Ok((default_ip, default_cidr, default_name, default_mtu))
}

pub fn create_tunnel(name: &str, address: Ipv4Addr, netmask: Ipv4Addr, mtu: u16) -> DynResult<AsyncDevice> {
    let mut config = Configuration::default();
    config.address(address).netmask(netmask).tun_name(name).mtu(mtu).up();
    config.platform_config(|conf| {
        conf.ensure_root_privileges(true);
    });
    let tunnel = match create_as_async(&config) {
        Ok(device) => Ok(device),
        Err(err) => bail!("Error creating tunnel: {err}"),
    };
    File::create(format!("/proc/sys/net/ipv6/conf/{name}/disable_ipv6"))?.write(&[0x31])?;
    tunnel
}
