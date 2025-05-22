use std::{net::Ipv4Addr, sync::Arc};

use ipnet::Ipv4Net;
use simple_error::bail;
use tun::Device;

use crate::{bytes::{get_buffer, ByteBuffer}, DynResult, ReaderWriter};


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


struct TunnelInternal {
    def_ip: Ipv4Addr,
    def_cidr: u8,
    tun_device: Device,

    internal: PlatformInternalConfig
}


pub struct Tunnel {
    tunnel: Arc<TunnelInternal>
}

impl Tunnel {
    pub fn new(seaside_address: Ipv4Addr, tunnel_name: &str, tunnel_network: Ipv4Net, svr_index: u8) -> DynResult<Self> {
        Ok(Self { tunnel: Arc::new(TunnelInternal::new(seaside_address, tunnel_name, tunnel_network, svr_index)?) })
    }

    pub fn default_interface(&self) -> (Ipv4Addr, u8) {
        (self.tunnel.def_ip, self.tunnel.def_cidr)
    }
}

impl Clone for Tunnel {
    fn clone(&self) -> Self {
        Self { tunnel: self.tunnel.clone() }
    }
}

impl ReaderWriter for Tunnel {
    fn read_bytes(&mut self) -> DynResult<ByteBuffer> {
        let buffer = get_buffer(None);
        let read = match self.tunnel.tun_device.recv(&mut buffer.slice_mut()) {
            Ok(res) => res,
            Err(res) => bail!("Error reading bytes from tunnel: {}", res)
        };
        Ok(buffer.rebuffer_end(read))
    }

    fn write_bytes(&mut self, bytes: &mut ByteBuffer) -> DynResult<usize> {
        match self.tunnel.tun_device.send(&bytes.slice()) {
            Ok(res) => Ok(res),
            Err(res) => bail!("Error writing bytes to tunnel: {}", res)
        }
    }
}
