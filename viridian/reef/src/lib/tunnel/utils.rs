#[cfg(test)]
#[path = "../../../tests/tunnel/utils.rs"]
mod test_utils;

use std::ffi::{CStr, CString};
use std::net::Ipv4Addr;
use std::str::FromStr;

use crate::DynResult;


pub fn bytes_to_int(buffer: &[u8]) -> DynResult<i32> {
    Ok(i32::from_ne_bytes(*<&[u8; 4]>::try_from(buffer)?))
}

pub fn bytes_to_ip_address(buffer: &[u8]) -> DynResult<Ipv4Addr> {
    Ok(Ipv4Addr::from(*<&[u8; 4]>::try_from(buffer)?))
}

pub fn bytes_to_string(buffer: &[u8]) -> DynResult<String> {
    Ok(CStr::from_bytes_until_nul(buffer)?.to_str()?.to_string())
}

pub fn string_to_bytes<'a>(buffer: &'a str) -> DynResult<CString> {
    Ok(CString::from_str(buffer)?)
}
