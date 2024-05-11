#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

use std::error::Error;
use std::future::Future;
use std::net::Ipv4Addr;

#[cfg(target_os = "linux")]
use self::linux::LinuxTunnel;


pub trait Tunnel {
    fn new(name: &str, address: Ipv4Addr) -> impl Future<Output = Result<Self, Box<dyn Error>>> where Self: Sized;
    fn default_interface(&self) -> (Ipv4Addr, u8);
}

#[cfg(target_os = "windows")]
pub async fn new_tunnel(name: &str, address: Ipv4Addr) -> Result<Box<dyn Tunnel>, Box<dyn Error>> {
    todo!()
}

#[cfg(target_os = "macos")]
pub async fn new_tunnel(name: &str, address: Ipv4Addr) -> Result<Box<dyn Tunnel>, Box<dyn Error>> {
    todo!()
}

#[cfg(target_os = "linux")]
pub async fn new_tunnel(name: &str, address: Ipv4Addr) -> Result<Box<dyn Tunnel>, Box<dyn Error>> {
    Ok(Box::from(LinuxTunnel::new(name, address).await?))
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
pub async fn new_tunnel(name: &str, address: Ipv4Addr) -> Result<Box<dyn Tunnel>, Box<dyn Error>> {
    Err(Box::from(format!("Tunnel is not available for the platform {}", OS)))
}
