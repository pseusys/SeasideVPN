use std::net::Ipv4Addr;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::*;

pub const DEFAULT_TUNNEL_NAME: &str = "seatun";
pub const DEFAULT_DNS_ADDRESS: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
pub const DEFAULT_TUNNEL_ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 82);
pub const DEFAULT_TUNNEL_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
pub const DEFAULT_SVR_INDEX: u8 = 82;
