use core::str;
use std::ffi::OsStr;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::str::FromStr;

use ipnet::Ipv4Net;
use regex::Regex;
use simple_error::bail;
use tokio::test;

use super::{NFTABLES_TABLE_NAME, NFTABLES_CHAIN_NAME, create_tunnel, disable_firewall, disable_routing, enable_firewall, enable_routing, get_address_device, get_default_interface, restore_svr_table, save_svr_table};
use super::super::DynResult;


fn run_command<I: IntoIterator<Item = S>, S: AsRef<OsStr>>(cmd: &str, args: I) -> DynResult<(String, String)> {
    let cmd = match Command::new(cmd).args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
        Ok(res) => res,
        Err(res) => bail!(res)
    };
    let res = match cmd.wait_with_output() {
        Ok(res) => res,
        Err(res) => bail!(res)
    };
    if res.status.success() {
        Ok((String::from_utf8_lossy(&res.stdout).to_string(), String::from_utf8_lossy(&res.stderr).to_string()))
    } else {
        bail!(String::from_utf8_lossy(&res.stderr).to_string())
    }
}


fn parse_route_info_from_output(route_output: &str) -> DynResult<(Option<String>, Option<String>, Option<Ipv4Addr>)> {
    let destination_regex = Regex::new(r"^(?<destination>\S+)")?;
    let destination_match = destination_regex.captures(route_output);
    let destination_res = destination_match.and_then(|m| Some((&m["destination"]).to_string()));

    let device_regex = Regex::new(r"dev (?<device>\S+)")?;
    let device_match = device_regex.captures(route_output);
    let device_res = device_match.and_then(|m| Some((&m["device"]).to_string()));

    let gateway_regex = Regex::new(r"via (?<gateway>\d+\.\d+\.\d+\.\d+)")?;
    let gateway_match = gateway_regex.captures(route_output);
    let gateway_res = gateway_match.and_then(|m| Ipv4Addr::from_str(&m["gateway"]).ok());

    Ok((destination_res, device_res, gateway_res))
}

fn get_route_device_info(destination: Ipv4Addr) -> DynResult<String> {
    let command = vec!["route".to_string(), "get".to_string(), destination.to_string()];
    let (route_out, _) = run_command("ip", command)?;
    match parse_route_info_from_output(&route_out) {
        Ok((_, Some(dev), _)) => Ok(dev),
        Ok((_, None, _)) | Err(_) => bail!("Error reading route device info!")
    }
}

fn show_route_info(prefix: Option<Ipv4Addr>, table: Option<u8>) -> DynResult<(Option<String>, Option<String>, Option<Ipv4Addr>)> {
    let mut command = vec!["route".to_string(), "list".to_string()];
    if let Some(address) = prefix {
        command = [command, vec!["match".to_string(), address.to_string()]].concat();
    }
    if let Some(index) = table {
        command = [command, vec!["table".to_string(), index.to_string()]].concat();
    }
    let (route_out, _) = run_command("ip", command)?;
    let route_data = route_out.trim().split("\n").last().unwrap();
    parse_route_info_from_output(&route_data)
}

fn show_address_info(device: &str) -> DynResult<(Option<i32>, Option<i32>, Option<Ipv4Addr>, Option<u32>)> {
    let (addr_out, _) = run_command("ip", ["addr", "show", device])?;

    let index_regex = Regex::new(r"^(?<index>\d+):")?;
    let index_match = index_regex.captures(&addr_out);
    let index_res = index_match.and_then(|m| i32::from_str(&m["index"]).ok());

    let mtu_regex = Regex::new(r"mtu (?<mtu>\d+)")?;
    let mtu_match = mtu_regex.captures(&addr_out);
    let mtu_res = mtu_match.and_then(|m| i32::from_str(&m["mtu"]).ok());

    let network_regex = Regex::new(r"inet (?<address>\d+\.\d+\.\d+\.\d+)/(?<cidr>\d+)")?;
    let network_match = network_regex.captures(&addr_out);
    let network_res = network_match.and_then(|m| Some((Ipv4Addr::from_str(&m["address"]).ok(), u32::from_str(&m["cidr"]).ok())));
    let (address_res, cidr_res) = match network_res {
        Some((address, cidr)) => (address, cidr),
        None => (None, None)
    };

    Ok((index_res, mtu_res, address_res, cidr_res))
}

fn show_rule_info(table: u8) -> DynResult<(Option<i32>, Option<i32>)> {
    let (rule_out, _) = run_command("ip", ["rule", "show", "table", &table.to_string()]).expect("Error getting rules!");

    let fwmark_regex = Regex::new(r"fwmark 0x(?<fwmark>\d+)")?;
    let fwmark_match = fwmark_regex.captures(&rule_out);
    let fwmark_res = fwmark_match.and_then(|m| i32::from_str_radix(&m["fwmark"], 16).ok());

    let lookup_regex = Regex::new(r"lookup (?<lookup>\d+)")?;
    let lookup_match = lookup_regex.captures(&rule_out);
    let lookup_res = lookup_match.and_then(|m| i32::from_str(&m["lookup"]).ok());

    Ok((fwmark_res, lookup_res))
}


#[test]
async fn test_get_default_interface() {
    let external_address = Ipv4Addr::new(8, 8, 8, 8);
    let expected_device = get_route_device_info(external_address).expect("Error reading default interface device name!");
    let (_, expected_mtu, expected_address, expected_cidr) = show_address_info(&expected_device).expect("Error reading default route IP!");

    let (default_address, default_cidr, default_name, default_mtu) = get_default_interface(external_address).expect("Error getting default address!");

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
    assert!(expected_mtu.is_some_and(|v| v == i32::from(tun_mtu)), "Default MTU doesn't match!");
    assert!(expected_address.is_some_and(|v| v == tun_address), "Default IP address doesn't match!");
    assert!(expected_cidr.is_some_and(|v| v == tun_netmask.to_bits().count_ones()), "Default CIDR doesn't match!");
}


#[test]
async fn test_save_restore_table() {
    let table_idx = 3;
    let device = "lo";
    let default_destination = Ipv4Addr::new(251, 251, 251, 251);
    let destinations = vec!["default", "1.0.0.0/8", "8.8.0.0/16", "10.0.0.0/24"];
    let ip_destinations: Vec<Ipv4Addr> = destinations.iter().map(|ip| match Ipv4Addr::from_str(ip.split("/").next().unwrap()) {
        Ok(addr) => addr,
        Err(_) => default_destination
    }).collect();

    for destination in destinations.clone() {
        run_command("ip", ["route", "add", destination, "dev", device, "table", &table_idx.to_string()]).expect("Error creating default route!");
    }

    let mut table_data = save_svr_table(table_idx).expect("Error saving SVR table!");

    for destination in ip_destinations.clone() {
        let (real_destination, real_device, _) = show_route_info(Some(destination), Some(table_idx)).unwrap_or_else(|_| panic!("Parsing route '{destination:?}' failed!"));
        assert!(real_destination.is_none(), "Couldn't find destination in route '{destination:?}'!");
        assert!(real_device.is_none(), "Couldn't find device in route '{device:?}'!");
    }

    restore_svr_table(&mut table_data).expect("Error restoring SVR table!");

    for (destination, ip_destination) in destinations.iter().zip(ip_destinations.iter()) {
        let (real_destination, real_device, _) = show_route_info(Some(*ip_destination), Some(table_idx)).unwrap_or_else(|_| panic!("Parsing route '{destination:?}' failed!"));
        assert!(real_destination.is_some_and(|v| v == destination.to_string()), "Could find destination in route '{destination:?}'!");
        assert!(real_device.is_some_and(|v| v == "lo"), "Could find device in route '{device:?}'!");
    }
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

    let tunnel_device = get_address_device(tun_network).expect("Getting tunnel device failed!");

    let (tunnel_index, _, _, _) = show_address_info(tun_name).expect("Reading tunnel address failed!");
    assert!(tunnel_index.is_some_and(|v| v == tunnel_device), "Tunnel index doesn't match!")
}

#[test]
async fn test_enable_disable_routing() {
    let table_idx = 5;
    let tun_mtu = 5000;
    let tun_name = "tun_tedr";
    let tun_network = Ipv4Net::from_str("192.168.5.5/24").expect("Error parsing tunnel network!");

    run_command("ip", ["tuntap", "add", "dev", tun_name, "mode", "tun"]).expect("Error creating tunnel interface!");
    run_command("ip", ["addr", "replace", &tun_network.to_string(), "dev", tun_name]).expect("Error setting IP address for tunnel!");
    run_command("ip", ["link", "set", "dev", tun_name, "mtu",&tun_mtu.to_string()]).expect("Error setting MTU for tunnel");
    run_command("ip", ["link", "set", tun_name, "up"]).expect("Error enabling tunnel!");

    let tunnel_index = match show_address_info(tun_name) {
        Ok((Some(index), _, _, _)) => index,
        Ok((None, _, _, _)) | Err(_) => panic!("Reading tunnel address failed!")
    };

    let (route_message, rule_message) = enable_routing(tun_network.addr(), tunnel_index, table_idx).expect("Error enabling routing!");

    let (routing_destination, routing_device, routing_gateway) = show_route_info(None, Some(table_idx)).expect("Error reading routing info!");
    assert!(routing_destination.is_some_and(|v| v == "default"), "Tunnel destination interface doesn't match!");
    assert!(routing_device.is_some_and(|v| v == tun_name), "Tunnel IP address doesn't match!");
    assert!(routing_gateway.is_some_and(|v| v == tun_network.addr()), "Tunnel name doesn't match!");

    let (routing_fwmark, routing_lookup) = show_rule_info(table_idx).expect("Error reading routing rules info!");
    assert!(routing_fwmark.is_some_and(|v| v == i32::from(table_idx)), "Rule fwmark doesn't match!");
    assert!(routing_lookup.is_some_and(|v| v == i32::from(table_idx)), "Table number doesn't match!");

    disable_routing(&route_message, &rule_message).expect("Error disabling routing!");

    let (routing_destination, _, _) = show_route_info(None, Some(table_idx)).expect("Error reading routing info!");
    assert!(routing_destination.is_none(), "Routing table {table_idx} not empty!");

    let (routing_fwmark, _) = show_rule_info(table_idx).expect("Error reading routing rules info!");
    assert!(routing_fwmark.is_none(), "Rule still exists!");
}


#[test]
async fn test_enable_disable_firewall() {
    let svr_idx = 6;
    let external_address = Ipv4Addr::new(8, 8, 8, 8);
    let seaside_address = Ipv4Addr::new(10, 0, 0, 10);

    let default_device = get_route_device_info(external_address).expect("Error finding default route!");
    let (default_address, default_cidr) = match show_address_info(&default_device) {
        Ok((_, _, Some(address), Some(cidr))) => (address, cidr),
        Ok((_, _, None, _)) | Ok((_, _, _, None)) | Err(_) => panic!("Error finding default IP address and CIDR!")
    };
    let default_net = Ipv4Net::new(default_address, default_cidr as u8).expect("Error parsing network address!");

    let nft_regex = Regex::new(r#"table\s+ip\s+(?<table>\S+)\s+\{\s*chain\s+(?<ochain>\S+)\s+\{\s*oifname\s+"(?<osiface>\S+)"\s+ip\s+saddr\s+(?<ossource>\d+\.\d+\.\d+\.\d+)\s+ip\s+daddr\s+(?<osdest>\d+\.\d+\.\d+\.\d+)\s+accept\s+oifname\s+"(?<ooiface>\S+)"\s+ip\s+daddr\s+!=\s+(?<oodest>\d+\.\d+\.\d+\.\d+/\d+)\s+meta\s+mark\s+set\s+(?<omark>\S+)\s+accept\s*}\s*chain\s+(?<fchain>\S+)\s+\{\s*oifname\s+"(?<fsiface>\S+)"\s+ip\s+saddr\s+(?<fssource>\d+\.\d+\.\d+\.\d+)\s+ip\s+daddr\s+(?<fsdest>\d+\.\d+\.\d+\.\d+)\s+accept\s+oifname\s+"(?<foiface>\S+)"\s+ip\s+daddr\s+!=\s+(?<fodest>\d+\.\d+\.\d+\.\d+/\d+)\s+meta\s+mark\s+set\s+(?<fmark>\S+)\s+accept\s*}\s+}"#).expect("Error compiling iptables SIA regex!");

    let table = enable_firewall(&default_device, &default_net, &seaside_address, svr_idx).expect("Error enabling firewall!");

    let (nftables_out, _) = run_command("nft", ["list", "ruleset"]).expect("Error getting 'iptables' data!");
    let nftables_match = nft_regex.captures(&nftables_out).expect("NFT rule didn't match anything!");

    /*
    assert_eq!(&nftables_match["table"], NFTABLES_TABLE_NAME, "NFT table name doesn't match!");
    for (pref, name) in vec![("o", "output"), ("f", "forward")] {
        assert_eq!(&nftables_match[format!("{pref}chain").as_str()], format!("{NFTABLES_CHAIN_NAME}-{name}"), "NFT {name} chain name doesn't match!");
        assert_eq!(&nftables_match[format!("{pref}siface").as_str()], default_device, "NFT {name} chain Seaside rule output interface doesn't match!");
        assert_eq!(&nftables_match[format!("{pref}ssource").as_str()], default_address.to_string(), "NFT {name} chain Seaside rule source IP address doesn't match!");
        assert_eq!(&nftables_match[format!("{pref}sdest").as_str()], seaside_address.to_string(), "NFT {name} chain Seaside rule destination IP address doesn't match!");
        assert_eq!(&nftables_match[format!("{pref}oiface").as_str()], default_device, "NFT {name} chain tunnel rule output interface doesn't match!");
        assert_eq!(&nftables_match[format!("{pref}odest").as_str()], default_net.trunc().to_string(), "NFT {name} chain tunnel rule destination IP address range doesn't match!");
        assert_eq!(&nftables_match[format!("{pref}mark").as_str()], format!("{svr_idx:#010x}"), "NFT {name} chain tunnel rule mark value doesn't match!");
    }
    */

    disable_firewall(&table).expect("Error disabling firewall!");

}
