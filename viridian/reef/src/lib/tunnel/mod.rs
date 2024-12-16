use std::future::Future;
use std::net::Ipv4Addr;

use simple_error::bail;
use tun::AsyncDevice;

use crate::DynResult;


#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
mod nl_utils;

#[cfg(target_os = "linux")]
use linux::*;


#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
use windows::*;


pub trait Creatable: Sized {
    fn new(seaside_address: Ipv4Addr, tunnel_name: &str, tunnel_address: Ipv4Addr, tunnel_netmask: Ipv4Addr, svr_index: u8) -> impl Future<Output = DynResult<Self>> + Send;
}

pub struct Tunnel {
    def_ip: Ipv4Addr,
    def_cidr: u8,
    tun_device: AsyncDevice,

    internal: PlatformInternalConfig,
}


impl Tunnel {
    pub fn default_interface(&self) -> (Ipv4Addr, u8) {
        (self.def_ip, self.def_cidr)
    }

    pub async fn read_bytes(&self, bytes: &mut [u8]) -> DynResult<usize> {
        match self.tun_device.recv(bytes).await {
            Ok(res) => Ok(res),
            Err(res) => bail!("Error reading bytes from tunnel: {}", res)
        }
    }

    pub async fn write_bytes(&self, bytes: &[u8]) -> DynResult<usize> {
        match self.tun_device.send(&bytes).await {
            Ok(res) => Ok(res),
            Err(res) => bail!("Error writing bytes to tunnel: {}", res)
        }
    }
}

fn verify_ip_address(address: &Ipv4Addr) -> DynResult<()> {
    if [0, 1, 255].contains(&address.octets()[3]) {
        bail!("Last byte of tunnel address should not be equal to {}!", address.octets()[3])
    }
    Ok(())
}
