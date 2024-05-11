pub mod library;

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
use std::os::fd::RawFd;
use std::error::Error;

use library::coordinator::Coordinator;


const VERSION: &str = "0.0.2";


#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
pub async fn init(payload: &str, address: &str, ctrl_port: u16, user_name: &str, min_hc_time: u16, max_hc_time: u16, max_timeout: f32, tunnel_name: &str) -> Result<Coordinator, Box<dyn Error>> {
    Coordinator::new(payload, address, ctrl_port, user_name, min_hc_time, max_hc_time, max_timeout, tunnel_name).await
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
pub fn init_f(payload: &str, address: &str, ctrl_port: u16, user_name: &str, min_hc_time: u16, max_hc_time: u16, max_timeout: f32, tunnel_fd: RawFd) -> Result<Coordinator, Box<dyn Error>> {

}
