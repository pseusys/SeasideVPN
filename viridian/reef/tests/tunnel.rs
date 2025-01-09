use core::str;
use std::ffi::OsStr;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::str::FromStr;

use regex::Regex;
use simple_error::bail;
use tokio::test;

use super::{get_default_interface, create_tunnel, disable_firewall, disable_routing, enable_routing, enable_firewall, restore_svr_table, save_svr_table};
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

fn get_route_with_command(command: Vec<&str>) -> (Ipv4Addr, String) {
    let route_regex = Regex::new(r"via (?<gateway>\d+\.\d+\.\d+\.\d+)[\s\S]*dev (?<device>\S+)").expect("Error compiling default route regex!");
    let (route_out, _) = run_command("ip", command).expect("Error getting default route!");
    let route_match = route_regex.captures(route_out.as_str()).expect("Error finding default route in 'ip' output!");
    let gateway_address = Ipv4Addr::from_str(&route_match["gateway"]).expect("Error parsing gateway IP address!");
    (gateway_address, (&route_match["device"]).to_string())
}

fn get_route_to_match(destination: &Ipv4Addr) -> (Ipv4Addr, String) {
    get_route_with_command(vec!["route", "show", "to", "match", destination.to_string().as_str()])
}

fn get_default_route() -> (Ipv4Addr, String) {
    get_route_with_command(vec!["route", "show", "default"])
}

fn get_address_of_device(device: &str) -> (i32, i32, Ipv4Addr, u32) {
    let addr_regex = Regex::new(r"(?<index>\d+):[\s\S]*mtu (?<mtu>\d+)[\s\S]*inet (?<address>\d+\.\d+\.\d+\.\d+)/(?<cidr>\d+)").expect("Error compiling default IP address regex!");
    let (addr_out, _) = run_command("ip", ["addr", "show", device]).expect("Error getting default IP address!");
    let addr_match = addr_regex.captures(addr_out.as_str()).expect("Error finding default IP address in 'ip' output!");
    let index = i32::from_str(&addr_match["index"]).expect("Error parsing index number!");
    let mtu = i32::from_str(&addr_match["mtu"]).expect("Error parsing MTU number!");
    let address = Ipv4Addr::from_str(&addr_match["address"]).expect("Error parsing IP address!");
    let cidr = u32::from_str(&addr_match["cidr"]).expect("Error parsing CIDR number!");
    (index, mtu, address, cidr)
}


#[test]
async fn test_get_default_interface() {
    let external_address = Ipv4Addr::new(8, 8, 8, 8);
    let (_, expected_device) = get_route_to_match(&external_address);
    let (_, expected_mtu, expected_address, expected_cidr) = get_address_of_device(&expected_device);

    let (default_address, default_cidr, default_name, default_mtu) = get_default_interface(external_address).expect("Error getting default address!");

    assert_eq!(default_name, expected_device, "Default device name doesn't match!");
    assert_eq!(default_mtu, expected_mtu, "Default MTU doesn't match!");
    assert_eq!(default_address, expected_address, "Default IP address doesn't match!");
    assert_eq!(u32::from(default_cidr), expected_cidr, "Default CIDR doesn't match!");
}


#[test]
async fn test_create_tunnel() {
    let tun_mtu = 1500;
    let tun_name = "tun_tct";
    let tun_address = Ipv4Addr::new(192, 168, 2, 2);
    let tun_netmask = Ipv4Addr::new(255, 255, 255, 0);

    let _device = create_tunnel(tun_name, tun_address, tun_netmask, tun_mtu).await.expect("Error creating tunnel!");

    let (_, expected_mtu, expected_address, expected_cidr) = get_address_of_device(tun_name);
    assert_eq!(i32::from(tun_mtu), expected_mtu, "Default MTU doesn't match!");
    assert_eq!(tun_address, expected_address, "Default IP address doesn't match!");
    assert_eq!(tun_netmask.to_bits().count_ones(), expected_cidr, "Default CIDR doesn't match!");
}


#[test]
async fn test_save_restore_table() {
    let table_idx = 3;
    let destinations = vec!["default", "1.0.0.0/8", "8.8.0.0/16", "10.0.0.0/24"];

    for destination in destinations.as_slice() {
        run_command("ip", ["route", "add", *destination, "dev", "lo", "table", table_idx.to_string().as_str()]).expect("Error creating default route!");
    }

    let mut table_data = save_svr_table(table_idx).expect("Error saving SVR table!");

    let (route_out_empty, _) = run_command("ip", ["route", "show", "table", table_idx.to_string().as_str()]).expect("Error getting routes!");
    assert_eq!(route_out_empty, "", "Routing table not empty!");

    restore_svr_table(&mut table_data).expect("Error restoring SVR table!");

    let route_regex = Regex::new(r"(?<destination>\S+) dev lo [\s\S]*").expect("Error compiling route regex!");
    let (route_out_full, _) = run_command("ip", ["route", "show", "table", table_idx.to_string().as_str()]).expect("Error getting routes!");
    for (route_out, destination) in route_out_full.split('\n').zip(destinations.as_slice()) {
        let route_match = route_regex.captures(route_out).expect("Error finding route information in 'ip' output!");
        assert_eq!(*destination, &route_match["destination"], "Route destination doesn't match!");
    }
}


#[test]
async fn test_enable_disable_routing() {
    let tun_idx = 4;
    let tun_name = "tun_ter";
    let tun_address = Ipv4Addr::new(192, 168, 4, 4);
    let tun_netmask = Ipv4Addr::new(255, 255, 255, 0);
    let tun_network = format!("{}/{}", tun_address.to_string(), tun_netmask.to_bits().count_ones().to_string());

    run_command("ip", ["tuntap", "add", "dev", tun_name, "mode", "tun"]).expect("Error creating tunnel interface!");
    run_command("ip", ["addr", "replace", tun_network.as_str(), "dev", tun_name]).expect("Error setting IP address for tunnel!");
    run_command("ip", ["link", "set", tun_name, "up"]).expect("Error enabling tunnel!");
  
    enable_routing(tun_address, tun_idx).expect("Error enabling routing!");

    let route_regex = Regex::new(r"default via (?<address>\d+\.\d+\.\d+\.\d+) dev (?<tunnel>\S+) [\s\S]*").expect("Error compiling route regex!");
    let (route_out_enabled, _) = run_command("ip", ["route", "show", "table", tun_idx.to_string().as_str()]).expect("Error getting routes!");
    let route_match = route_regex.captures(route_out_enabled.as_str()).expect("Error finding route information in 'ip' output!");
    assert_eq!(tun_address.to_string(), &route_match["address"], "Tunnel IP address doesn't match!");
    assert_eq!(tun_name, &route_match["tunnel"], "Tunnel name doesn't match!");

    let rule_regex = Regex::new(r"\d+:\s+from all fwmark (?<fwmark>0x\d+) lookup (?<table>\d+)").expect("Error compiling rule regex!");
    let (rule_out_enabled, _) = run_command("ip", ["rule", "show", "table", tun_idx.to_string().as_str()]).expect("Error getting rules!");
    let rule_match = rule_regex.captures(rule_out_enabled.as_str()).expect("Error finding rule information in 'ip' output!");
    assert_eq!(format!("0x{:x}", tun_idx), &rule_match["fwmark"], "Rule fwmark doesn't match!");
    assert_eq!(tun_idx.to_string(), &rule_match["table"], "Table number doesn't match!");

    disable_routing(tun_address, tun_idx).expect("Error disabling routing!");

    let (route_out_disabled, _) = run_command("ip", ["route", "show", "table", tun_idx.to_string().as_str()]).expect("Error getting routes!");
    assert_eq!(route_out_disabled, "", "Routing table not empty!");

    let (rule_out_disabled, _) = run_command("ip", ["rule", "show", "table", tun_idx.to_string().as_str()]).expect("Error getting rules!");
    assert_eq!(rule_out_disabled, "", "Routing table not empty!");
}


#[test]
async fn test_enable_disable_firewall() {
    let svr_idx = 5;
    let external_address = Ipv4Addr::new(8, 8, 8, 8);
    let seaside_address = Ipv4Addr::new(10, 0, 0, 10);

    let route_regex = Regex::new(r"dev (?<device>\S+)").expect("Error compiling default route regex!");
    let (route_out, _) = run_command("ip", ["route", "show", "to", "match", external_address.to_string().as_str()]).expect("Error getting default route!");
    let route_match = route_regex.captures(route_out.as_str()).expect("Error finding default route in 'ip' output!");

    let addr_regex = Regex::new(r"inet (?<address>\d+\.\d+\.\d+\.\d+)/(?<cidr>\d+)").expect("Error compiling default IP address regex!");
    let (addr_out, _) = run_command("ip", ["addr", "show", &route_match["device"]]).expect("Error getting default IP address!");
    let addr_match = addr_regex.captures(addr_out.as_str()).expect("Error finding default IP address in 'ip' output!");

    let default_name = &route_match["device"];
    let default_addr = Ipv4Addr::from_str(&addr_match["address"]).expect("Error parsing default IP address!");
    let default_cidr = &addr_match["cidr"].parse::<u8>().expect("Error parsing default address CIDR!");
    let default_net = format!("{}/{}", [&default_addr.octets()[..3], &vec![0][..]].concat().iter().map(|&b| b.to_string()).collect::<Vec<String>>().join("."), default_cidr);

    let sia_regex = Regex::new(r"ACCEPT +all[\s\S]+?(?<interface>\S+)\s+(?<source>\d+\.\d+\.\d+\.\d+)\s+(?<destination>\d+\.\d+\.\d+\.\d+)").expect("Error compiling iptables SIA regex!");
    let sim_regex = Regex::new(r"MARK +all[\s\S]+?(?<interface>\S+)\s+(?<source>\d+\.\d+\.\d+\.\d+/\d+)\s+!(?<destination>\d+\.\d+\.\d+\.\d+/\d+)\s+MARK set (?<mark>\S+)").expect("Error compiling iptables SIM regex!");
    let sc_regex = Regex::new(r"ACCEPT +all[\s\S]+?(?<interface>\S+)\s+(?<source>\d+\.\d+\.\d+\.\d+/\d+)\s+!(?<destination>\d+\.\d+\.\d+\.\d+/\d+)").expect("Error compiling iptables SC regex!");

    enable_firewall(default_name, &default_addr, *default_cidr, &seaside_address, svr_idx).expect("Error enabling firewall!");

    for chain in ["OUTPUT", "FORWARD"] {
        let (iptables_out, _) = run_command("iptables", ["-L", chain, "-v", "-n", "-t", "mangle"]).expect("Error getting 'iptables' data!");

        let sia_match = sia_regex.captures(iptables_out.as_str()).expect("Error finding SIA rule in 'iptables' output!");
        assert_eq!(default_name, &sia_match["interface"], "SIA rule interface name doesn't match!");
        assert_eq!(default_addr.to_string(), &sia_match["source"], "SIA rule source address doesn't match!");
        assert_eq!(seaside_address.to_string(), &sia_match["destination"], "SIA rule destination address doesn't match!");

        let sim_match = sim_regex.captures(iptables_out.as_str()).expect("Error finding SIM rule in 'iptables' output!");
        assert_eq!(default_name, &sim_match["interface"], "SIA rule interface name doesn't match!");
        assert_eq!("0.0.0.0/0", &sim_match["source"], "SIA rule source address doesn't match!");
        assert_eq!(default_net, &sim_match["destination"], "SIA rule destination address doesn't match!");
        assert_eq!(format!("0x{:x}", svr_idx), &sim_match["mark"], "SIA rule mark value doesn't match!");

        let sc_match = sc_regex.captures(iptables_out.as_str()).expect("Error finding SC rule in 'iptables' output!");
        assert_eq!(default_name, &sc_match["interface"], "SIA rule interface name doesn't match!");
        assert_eq!("0.0.0.0/0", &sc_match["source"], "SIA rule source address doesn't match!");
        assert_eq!(default_net, &sc_match["destination"], "SIA rule destination address doesn't match!");
    }

    disable_firewall(default_name, &default_addr, *default_cidr, &seaside_address, svr_idx).expect("Error disabling firewall!");
    
    for chain in ["OUTPUT", "FORWARD"] {
        let (iptables_out, _) = run_command("iptables", ["-L", chain, "-v", "-n", "-t", "mangle"]).expect("Error getting 'iptables' data!");

        let sia_match = sia_regex.captures(iptables_out.as_str());
        assert!(sia_match.is_none(), "SIA rule found in 'iptables'!");

        let sim_match = sim_regex.captures(iptables_out.as_str());
        assert!(sim_match.is_none(), "SIM rule found in 'iptables'!");

        let sc_match = sc_regex.captures(iptables_out.as_str());
        assert!(sc_match.is_none(), "SC rule found in 'iptables'!");
    }
}
