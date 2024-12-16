use std::net::Ipv4Addr;

use super::{verify_ip_address, Creatable, Tunnel};
use crate::DynResult;

pub struct PlatformInternalConfig {}

impl Creatable for Tunnel {
    async fn new(seaside_address: Ipv4Addr, tunnel_name: &str, tunnel_address: Ipv4Addr, tunnel_netmask: Ipv4Addr, svr_index: u8) -> DynResult<Tunnel> {
        verify_ip_address(&seaside_address);
    }
}

impl Drop for Tunnel {
    #[allow(unused_must_use)]
    fn drop(&mut self) {}
}

