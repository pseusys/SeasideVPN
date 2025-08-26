use std::collections::HashSet;
use std::{net::Ipv4Addr, sync::Arc};

use ipnet::Ipv4Net;
use simple_error::bail;

use crate::bytes::{get_buffer, ByteBuffer};
use crate::{DynResult, Reader, Writer};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::*;

#[cfg(target_os = "windows")]
mod ptr_utils;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::*;

trait Tunnelling {
    async fn recv(&self, buf: &mut [u8]) -> DynResult<usize>;
    async fn send(&self, buf: &[u8]) -> DynResult<usize>;
}

#[derive(Clone)]
pub struct Tunnel {
    tunnel: Arc<TunnelInternal>,
}

impl Tunnel {
    #[inline]
    pub fn default_ip(&self) -> Ipv4Addr {
        self.tunnel.default_address
    }

    pub async fn new(seaside_address: Ipv4Addr, tunnel_name: &str, tunnel_network: Ipv4Net, svr_index: u8, dns: Option<Ipv4Addr>, capture_iface: HashSet<String>, capture_ranges: HashSet<Ipv4Net>, exempt_ranges: HashSet<Ipv4Net>, capture_ports: Option<(u16, u16)>, exempt_ports: Option<(u16, u16)>, local_address: Option<Ipv4Addr>) -> DynResult<Self> {
        Ok(Self {
            tunnel: Arc::new(TunnelInternal::new(seaside_address, tunnel_name, tunnel_network, svr_index, dns, capture_iface, capture_ranges, exempt_ranges, capture_ports, exempt_ports, local_address).await?),
        })
    }
}

impl Reader for Tunnel {
    async fn read_bytes(&mut self) -> DynResult<ByteBuffer<'_>> {
        let buffer = get_buffer(None).await;
        let read = match self.tunnel.recv(&mut buffer.slice_mut()).await {
            Ok(res) => res,
            Err(res) => bail!("Error reading bytes from tunnel: {}", res),
        };
        Ok(buffer.rebuffer_end(read))
    }
}

impl Writer for Tunnel {
    async fn write_bytes(&mut self, bytes: ByteBuffer<'_>) -> DynResult<usize> {
        match self.tunnel.send(&bytes.slice()).await {
            Ok(res) => Ok(res),
            Err(res) => bail!("Error writing bytes to tunnel: {}", res),
        }
    }
}
