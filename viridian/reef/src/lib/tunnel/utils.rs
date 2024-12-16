use std::net::Ipv4Addr;

use simple_error::bail;

use crate::DynResult;


pub fn verify_ip_address(address: &Ipv4Addr) -> DynResult<()> {
    if [0, 1, 255].contains(&address.octets()[3]) {
        bail!("Last byte of tunnel address should not be equal to {}!", address.octets()[3])
    }
    Ok(())
}
