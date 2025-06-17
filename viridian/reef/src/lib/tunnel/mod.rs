use std::collections::HashSet;
use std::{net::Ipv4Addr, sync::Arc};

use ipnet::Ipv4Net;
use simple_error::bail;
use tun::AsyncDevice;

use crate::bytes::{get_buffer, ByteBuffer};
use crate::{DynResult, Reader, Writer};


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
    tun_device: AsyncDevice,

    _internal: PlatformInternalConfig
}


pub struct Tunnel {
    tunnel: Arc<TunnelInternal>
}

impl Tunnel {
    pub fn new(seaside_address: Ipv4Addr, tunnel_name: &str, tunnel_network: Ipv4Net, svr_index: u8, dns: Option<Ipv4Addr>, capture_iface: HashSet<String>, capture_ranges: HashSet<String>, exempt_ranges: HashSet<String>, local_address: Option<Ipv4Addr>) -> DynResult<Self> {
        Ok(Self { tunnel: Arc::new(TunnelInternal::new(seaside_address, tunnel_name, tunnel_network, svr_index, dns, capture_iface, capture_ranges, exempt_ranges, local_address)?) })
    }
}

impl Clone for Tunnel {
    fn clone(&self) -> Self {
        Self { tunnel: self.tunnel.clone() }
    }
}

impl Reader for Tunnel {
    async fn read_bytes(&mut self) -> DynResult<ByteBuffer> {
        let buffer = get_buffer(None).await;
        let read = match self.tunnel.tun_device.recv(&mut buffer.slice_mut()).await {
            Ok(res) => res,
            Err(res) => bail!("Error reading bytes from tunnel: {}", res)
        };
        Ok(buffer.rebuffer_end(read))
    }
}

impl Writer for Tunnel {
    async fn write_bytes(&mut self, bytes: ByteBuffer<'_>) -> DynResult<usize> {
        match self.tunnel.tun_device.send(&bytes.slice()).await {
            Ok(res) => Ok(res),
            Err(res) => bail!("Error writing bytes to tunnel: {}", res)
        }
    }
}
