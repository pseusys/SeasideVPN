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
