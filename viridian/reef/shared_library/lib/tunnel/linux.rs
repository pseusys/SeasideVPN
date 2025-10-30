use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use log::debug;
use reeflib::tunnel::{create_tunnel, get_default_interface_by_remote_address};
use tun::AsyncDevice;

use crate::tunnel::Tunnelling;
use crate::DynResult;

pub struct TunnelInternal {
    pub default_address: Ipv4Addr,
    pub tunnel_device: AsyncDevice,
}

impl TunnelInternal {
    pub async fn new(seaside_address: Ipv4Addr, tunnel_name: &str, tunnel_network: Ipv4Net) -> DynResult<Self> {
        debug!("Checking system default network properties...");
        let (default_address, default_cidr, default_name, default_mtu) = get_default_interface_by_remote_address(seaside_address).await?;
        debug!("Default network properties received: address {default_address}, CIDR {default_cidr}, name {default_name}, MTU {default_mtu}");

        debug!("Creating tunnel device: address {}, netmask {}...", tunnel_network.addr(), tunnel_network.netmask());
        let tunnel_device = create_tunnel(tunnel_name, tunnel_network.addr(), tunnel_network.netmask(), default_mtu as u16)?;

        debug!("Creating tunnel handle...");
        Ok(Self { default_address, tunnel_device })
    }
}

impl Tunnelling for TunnelInternal {
    async fn recv(&self, buf: &mut [u8]) -> DynResult<usize> {
        Ok(self.tunnel_device.recv(buf).await?)
    }

    async fn send(&self, buf: &[u8]) -> DynResult<usize> {
        Ok(self.tunnel_device.send(buf).await?)
    }
}
