use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use simple_error::bail;
use tonic::async_trait;
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


mod utils;
pub use utils::*;


#[async_trait]
pub trait Creatable: Sized {
    async fn new(seaside_address: Ipv4Addr, tunnel_name: &str, tunnel_network: Ipv4Net, svr_index: u8) -> DynResult<Self>;
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
