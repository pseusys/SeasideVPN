#[cfg(test)]
#[path = "../../../tests/utils.rs"]
mod utils_test;

use core::str;
use std::net::Ipv4Addr;

use simple_error::bail;

use crate::DynResult;


pub fn verify_ip_address(address: &Ipv4Addr) -> DynResult<()> {
    if [0, 1, 255].contains(&address.octets()[3]) {
        bail!("Last byte of tunnel address should not be equal to {}!", address.octets()[3])
    }
    Ok(())
}

pub fn network_address(address: &Ipv4Addr, netmask: &Ipv4Addr) -> (Ipv4Addr, u32) {
    let cidr = netmask.to_bits().count_ones();
    let mask = !((1u32 << (32 - cidr)) - 1);
    (Ipv4Addr::from_bits(u32::from(*address) & mask), cidr)
}


pub fn bytes_to_int(buffer: &[u8]) -> DynResult<i32> {
    Ok(i32::from_ne_bytes(*<&[u8; 4]>::try_from(buffer)?))
}

pub fn bytes_to_ip_address(buffer: &[u8]) -> DynResult<Ipv4Addr> {
    Ok(Ipv4Addr::from(*<&[u8; 4]>::try_from(buffer)?))
}

pub fn bytes_to_string(buffer: &[u8]) -> DynResult<String> {
    let slice_str = str::from_utf8(buffer)?;
    Ok(String::from(&slice_str[..slice_str.len() - 1]))
}
