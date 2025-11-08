use std::ffi::{c_char, c_void, CStr, CString};
use std::fs::read;
use std::ptr::null_mut;
use std::slice::from_raw_parts;
use std::str::FromStr;

use prost::Message;
use tokio::sync::oneshot::{channel, Sender};
use tokio::task::JoinHandle;
use tun::AbstractDevice;

use reeflib::generated::SeasideWhirlpoolClientCertificate;
use reeflib::protocol::ProtocolType;
use reeflib::utils::parse_address;
use reeflib::{run_coroutine_in_thread, run_coroutine_sync, DynResult};

use crate::viridian::Viridian;

mod tunnel;
mod viridian;

/// cbindgen:ignore
struct RawPtr(*mut c_void);

unsafe impl Send for RawPtr {}

/// cbindgen:ignore
struct Coordinator {
    handle: JoinHandle<c_void>,
    terminator: Sender<()>
}

#[repr(C)]
pub struct VPNConfig {
    remote_address: u32,
    tunnel_name: *const c_char,
    tunnel_gateway: u32,
    tunnel_address: u32,
    tunnel_prefix: u32,
    tunnel_mtu: u32,
    dns_address: u32
}

macro_rules! error_to_string {
    ($result:expr) => {{
        let sanitized = $result.chars().map(|c| if c == '\0' { '?' } else { c }).collect::<String>();
        CString::new(sanitized).unwrap().into_raw()
    }};
}

macro_rules! return_error {
    ($result:expr, $error:ident) => {{
        unsafe { *$error = error_to_string!($result) };
        return false;
    }};
}

#[no_mangle]
pub extern "C" fn vpn_start(certificate: *const c_char, cert_data_length: usize, protocol: *const c_char, config: *mut *mut VPNConfig, coordinator_ptr: *mut *mut c_void, plugin_ptr: *mut c_void, error_callback: extern "C" fn(*mut c_void, *mut c_char) -> c_void,  error: *mut *mut c_char) -> bool {
    let protocol = match unsafe { CStr::from_ptr(protocol) }.to_str() {
        Ok(proto_str) => match ProtocolType::from_str(proto_str) {
            Ok(res) => res,
            Err(err) => return_error!(format!("Error resolving protocol: {err}"), error)
        },
        Err(err) => return_error!(format!("Error resolving protocol string: {err}"), error)
    };

    let cert_data = if cert_data_length > 0 {
        unsafe { from_raw_parts(certificate as *const u8, cert_data_length).to_vec() }
    } else {
        match unsafe { CStr::from_ptr(certificate) }.to_str() {
            Ok(cert_str) => match read(cert_str) {
                Ok(cert_bytes) => cert_bytes,
                Err(err) => return_error!(format!("Error reading certificate file: {err}"), error)
            },
            Err(err) => return_error!(format!("Error resolving certificate string: {err}"), error)
        }
    };

    let certificate = match SeasideWhirlpoolClientCertificate::decode(&*cert_data) {
        Ok(res) => res,
        Err(err) => return_error!(format!("Error decoding certificate: {err}"), error)
    };

    let remote_address = certificate.address.clone();
    let viridian = match run_coroutine_sync!(async { Viridian::new(certificate, protocol).await }) {
        Ok(res) => res,
        Err(err) => return_error!(format!("Error creating viridian: {err}"), error)
    };

    let vpn_config = VPNConfig {
        remote_address: match parse_address(&remote_address) {
            Ok(res) => res.to_bits(),
            Err(err) => return_error!(format!("Error handling remote gateway address: {err}"), error)
        },
        tunnel_name: match viridian.tunnel.tunnel.tunnel_device.tun_name() {
            Ok(tun_name) => match CString::new(tun_name) {
                Ok(res) => res.into_raw(),
                Err(err) => return_error!(format!("Error converting tunnel device name to string: {err}"), error)
            },
            Err(err) => return_error!(format!("Error extracting tunnel device name: {err}"), error)
        },
        tunnel_gateway: viridian.tunnel_network.network().to_bits() + 1,
        tunnel_address: viridian.tunnel_network.addr().to_bits(),
        tunnel_prefix: viridian.tunnel_network.netmask().to_bits().count_ones(),
        tunnel_mtu: match viridian.tunnel.tunnel.tunnel_device.mtu() {
            Ok(res) => res.into(),
            Err(err) => return_error!(format!("Error extracting tunnel device MTU: {err}"), error)
        },
        dns_address: match viridian.dns {
            Some(res) => res.to_bits(),
            None => 0
        }
    };

    let viridian_ptr = Box::into_raw(Box::new(viridian));
    let (sender, mut receiver) = channel();

    let plugin_raw = RawPtr(plugin_ptr);
    let viridian_raw = RawPtr(viridian_ptr as *mut c_void);

    let handle = run_coroutine_in_thread!(async {
        let plugin_raw_copy = plugin_raw;
        let viridian_raw_copy = viridian_raw;
        let mut viridian = unsafe { Box::from_raw(viridian_raw_copy.0 as *mut Viridian) };
        match viridian.start(&mut receiver).await {
            Ok(_) => error_callback(plugin_raw_copy.0, null_mut()),
            Err(err) => error_callback(plugin_raw_copy.0, error_to_string!(format!("Error in VPN loop: {err}"))),
        }
    });

    unsafe { *config = Box::into_raw(Box::new(vpn_config)) };
    unsafe { *coordinator_ptr = Box::into_raw(Box::new(Coordinator { handle, terminator: sender })) as *mut c_void };
    true
}

#[no_mangle]
pub extern "C" fn vpn_stop(coordinator_ptr: *mut c_void, error: *mut *mut c_char) -> bool {
    let coordinator = unsafe { Box::from_raw(coordinator_ptr as *mut Coordinator) };

    let handle = coordinator.handle;
    if let Err(_) = coordinator.terminator.send(()) {
        return_error!("Error terminating VPN loop", error)
    }

    let result = match run_coroutine_sync!(async { handle.await }) {
        Ok(_) => true,
        Err(err) => return_error!(format!("Error joining VPN loop termination: {err}"), error)
    };

    return result;
}
