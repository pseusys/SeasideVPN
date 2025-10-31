use std::any::type_name;
use std::env::var;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::str::FromStr;

use simple_error::bail;

use crate::DynResult;

pub fn parse_env<T: FromStr>(key: &str, default: Option<T>) -> T {
    match var(key) {
        Ok(res) => match res.parse::<T>() {
            Ok(res) => res,
            Err(_) => panic!("'{key}' should be conversable to {}!", type_name::<T>()),
        },
        Err(_) => match default {
            Some(res) => res,
            None => panic!("'{key}' should be set!"),
        },
    }
}

pub fn parse_str_env(key: &str, default: Option<&str>) -> String {
    match var(key) {
        Ok(res) => res,
        Err(_) => match default {
            Some(res) => res.to_string(),
            None => panic!("'{key}' should be set!"),
        },
    }
}

pub fn parse_address(address: &str) -> DynResult<Ipv4Addr> {
    match (address, 0).to_socket_addrs()?.next() {
        Some(socket_addr) => match socket_addr.ip() {
            IpAddr::V4(ipv4) => Ok(ipv4),
            IpAddr::V6(ipv6) => bail!("IPv6 address {ipv6} is not supported!"),
        },
        None => bail!("Could not resolve address: {address}"),
    }
}
