use core::str;
use std::net::Ipv4Addr;
use std::str::FromStr;

use ipnet::Ipv4Net;
use regex::Regex;
use simple_error::bail;
use tokio::test;

use reeftest::{parse_route_info_from_output, run_command};

use crate::tunnel::linux::{create_tunnel, get_address_device, get_default_interface_by_remote_address};
use crate::DynResult;

fn get_route_device_info(destination: Ipv4Addr) -> DynResult<String> {
    let command = vec!["route".to_string(), "get".to_string(), destination.to_string()];
    let (route_out, _) = run_command("ip", command)?;
    match parse_route_info_from_output(&route_out) {
        Ok((_, Some(dev), _)) => Ok(dev),
        Ok((_, None, _)) | Err(_) => bail!("Error reading route device info!"),
    }
}

fn show_address_info(device: &str) -> DynResult<(Option<u32>, Option<u32>, Option<Ipv4Addr>, Option<u32>)> {
    let (addr_out, _) = run_command("ip", ["addr", "show", device])?;

    let index_regex = Regex::new(r"^(?<index>\d+):")?;
    let index_match = index_regex.captures(&addr_out);
    let index_res = index_match.and_then(|m| u32::from_str(&m["index"]).ok());

    let mtu_regex = Regex::new(r"mtu (?<mtu>\d+)")?;
    let mtu_match = mtu_regex.captures(&addr_out);
    let mtu_res = mtu_match.and_then(|m| u32::from_str(&m["mtu"]).ok());

    let network_regex = Regex::new(r"inet (?<address>\d+\.\d+\.\d+\.\d+)/(?<cidr>\d+)")?;
    let network_match = network_regex.captures(&addr_out);
    let network_res = network_match.and_then(|m| Some((Ipv4Addr::from_str(&m["address"]).ok(), u32::from_str(&m["cidr"]).ok())));
    let (address_res, cidr_res) = match network_res {
        Some((address, cidr)) => (address, cidr),
        None => (None, None),
    };

    Ok((index_res, mtu_res, address_res, cidr_res))
}

#[test]
async fn test_get_default_interface() {
    let external_address = Ipv4Addr::new(8, 8, 8, 8);
    let expected_device = get_route_device_info(external_address).expect("Error reading default interface device name!");
    let (_, expected_mtu, expected_address, expected_cidr) = show_address_info(&expected_device).expect("Error reading default route IP!");

    let (default_address, default_cidr, default_name, default_mtu) = get_default_interface_by_remote_address(external_address).await.expect("Error getting default address!");

    assert_eq!(default_name, expected_device, "Default device name doesn't match!");
    assert!(expected_mtu.is_some_and(|v| v == default_mtu), "Default MTU doesn't match!");
    assert!(expected_address.is_some_and(|v| v == default_address), "Default IP address doesn't match!");
    assert!(expected_cidr.is_some_and(|v| v == u32::from(default_cidr)), "Default CIDR doesn't match!");
}

#[test]
async fn test_create_tunnel() {
    let tun_mtu = 1500;
    let tun_name = "tun_tct";
    let tun_address = Ipv4Addr::new(192, 168, 2, 2);
    let tun_netmask = Ipv4Addr::new(255, 255, 255, 0);

    let _device = create_tunnel(tun_name, tun_address, tun_netmask, tun_mtu).expect("Error creating tunnel!");

    let (_, expected_mtu, expected_address, expected_cidr) = show_address_info(tun_name).expect("Error reading default route IP!");
    assert!(expected_mtu.is_some_and(|v| v == u32::from(tun_mtu)), "Default MTU doesn't match!");
    assert!(expected_address.is_some_and(|v| v == tun_address), "Default IP address doesn't match!");
    assert!(expected_cidr.is_some_and(|v| v == tun_netmask.to_bits().count_ones()), "Default CIDR doesn't match!");
}

#[test]
async fn test_get_address_device() {
    let tun_mtu = 4000;
    let tun_name = "tun_tgad";
    let tun_network = Ipv4Net::from_str("192.168.4.4/24").expect("Error parsing tunnel network!");

    run_command("ip", ["tuntap", "add", "dev", tun_name, "mode", "tun"]).expect("Error creating tunnel interface!");
    run_command("ip", ["addr", "replace", &tun_network.to_string(), "dev", tun_name]).expect("Error setting IP address for tunnel!");
    run_command("ip", ["link", "set", "dev", tun_name, "mtu", &tun_mtu.to_string()]).expect("Error setting MTU for tunnel");
    run_command("ip", ["link", "set", tun_name, "up"]).expect("Error enabling tunnel!");

    let tunnel_device = get_address_device(tun_network).await.expect("Getting tunnel device failed!");

    let (tunnel_index, _, _, _) = show_address_info(tun_name).expect("Reading tunnel address failed!");
    assert!(tunnel_index.is_some_and(|v| v == tunnel_device), "Tunnel index doesn't match!")
}
