#[cfg(test)]
#[path = "../../../tests/tunnel/linux.rs"]
mod linux_test;

use std::collections::HashSet;
use std::error::Error;
use std::fs::{read_to_string, write, File};
use std::io::Write;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use log::{debug, error, info};
use neli::consts::nl::NlTypeWrapper;
use neli::consts::rtnl::{Ifa, Ifla, RtTable, Rta, Rtm};
use neli::rtnl::{Ifinfomsg, Rtmsg};
use neli::socket::NlSocketHandle;
use simple_error::{bail, require_with};
use tun::{create_as_async, AsyncDevice, Configuration};

use super::nl_utils::{copy_rtmsg, create_address_message, create_attr, create_clear_cache_message, create_header, create_interface_message, create_routing_message, create_rtmsg, create_socket, send_netlink_message, send_netlink_stream};
use super::{bytes_to_int, bytes_to_ip_address, bytes_to_string, string_to_bytes, TunnelInternal};
use crate::DynResult;


const FRA_MASK: Rta = Rta::UnrecognizedConst(10);
const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";


fn get_default_address_and_device(socket: &mut NlSocketHandle, target: Ipv4Addr) -> DynResult<(Ipv4Addr, i32)> {
    let sea_addr_vec = Vec::from(target.octets());
    let message = create_routing_message(RtTable::Unspec, Rtm::Getroute, false, false, &[create_attr(Rta::Dst, sea_addr_vec)?])?;
    let answer = send_netlink_message::<Rtm, Rtmsg, NlTypeWrapper>(socket, message, false)?.unwrap();
    let default_ip = answer.rtattrs.iter().find(|a| a.rta_type == Rta::Prefsrc).and_then(|a| bytes_to_ip_address(a.rta_payload.as_ref()).ok());
    let default_dev = answer.rtattrs.iter().find(|a| a.rta_type == Rta::Oif).and_then(|a| bytes_to_int(a.rta_payload.as_ref()).ok());
    Ok((require_with!(default_ip, "Default IP address was not found!"), require_with!(default_dev, "Default network interface was not found!")))
}

fn get_device_name_and_cidr(socket: &mut NlSocketHandle, device: i32) -> DynResult<(String, u8)> {
    let mut default_name: Option<String> = None;
    let mut default_cidr: Option<u8> = None;
    let message = create_address_message(device, Rtm::Getaddr, &[]);
    send_netlink_stream(socket, message, |hdr| {
        if hdr.ifa_index == device {
            default_name = hdr.rtattrs.iter().find(|a| a.rta_type == Ifa::Label).and_then(|a| bytes_to_string(a.rta_payload.as_ref()).ok());
            default_cidr = Some(hdr.ifa_prefixlen);
        }
        Ok(())
    })?;
    Ok((require_with!(default_name, "Default network interface name was not resolved!"), require_with!(default_cidr, "Default IP address CIDR was not resolved!")))
}

fn get_device_address_and_cidr(label: &str) -> DynResult<(Ipv4Addr, u8)> {
    let mut socket = create_socket()?;
    let mut default_name: Option<String> = None;
    let mut default_addr: Option<Ipv4Addr> = None;
    let mut default_cidr: Option<u8> = None;
    let message = create_address_message(0, Rtm::Getaddr, &[create_attr(Ifa::Label, string_to_bytes(label)?.as_bytes())?]);
    send_netlink_stream(&mut socket, message, |hdr| {
        default_name = hdr.rtattrs.iter().find(|a| a.rta_type == Ifa::Label).and_then(|a| bytes_to_string(a.rta_payload.as_ref()).ok());
        if default_name.as_ref().is_some_and(|n| n == label) {
            default_addr = hdr.rtattrs.iter().find(|a| a.rta_type == Ifa::Address).and_then(|a| bytes_to_ip_address(a.rta_payload.as_ref()).ok());
            default_cidr = Some(hdr.ifa_prefixlen);
        }
        Ok(())
    })?;
    Ok((require_with!(default_addr, "Network interface IP address was not resolved!"), require_with!(default_cidr, "Network interface IP address CIDR was not resolved!")))
}

fn get_device_mtu(socket: &mut NlSocketHandle, device: i32) -> DynResult<i32> {
    let message = create_interface_message(device, Rtm::Getlink);
    let answer = send_netlink_message::<Rtm, Ifinfomsg, NlTypeWrapper>(socket, message, false)?.unwrap();
    let default_mtu = answer.rtattrs.iter().find(|a| a.rta_type == Ifla::Mtu).and_then(|a| bytes_to_int(a.rta_payload.as_ref()).ok());
    Ok(require_with!(default_mtu, "Default network interface MTU was not resolved!"))
}

fn get_address_device(network: Ipv4Net) -> DynResult<i32> {
    let mut socket = create_socket()?;

    let tun_router_addr = Vec::from(network.broadcast().octets());
    let message = create_routing_message(RtTable::Unspec, Rtm::Getroute, false, false, &[create_attr(Rta::Dst, tun_router_addr)?])?;
    let recv_payload = send_netlink_message::<Rtm, Rtmsg, Rtm>(&mut socket, message, false)?.unwrap();
    let tunnel_dev = recv_payload.rtattrs.iter().find(|a| a.rta_type == Rta::Oif).and_then(|a| bytes_to_int(a.rta_payload.as_ref()).ok());

    Ok(require_with!(tunnel_dev, "Tunnel device number was not resolved!"))
}

fn get_default_interface(seaside_address: Ipv4Addr) -> DynResult<(Ipv4Addr, u8, String, i32)> {
    let mut socket = create_socket()?;

    let (default_ip, default_dev) = get_default_address_and_device(&mut socket, seaside_address)?;
    let (default_name, default_cidr) = get_device_name_and_cidr(&mut socket, default_dev)?;
    let default_mtu = get_device_mtu(&mut socket, default_dev)?;

    Ok((default_ip, default_cidr, default_name, default_mtu))
}


fn create_tunnel(name: &str, address: Ipv4Addr, netmask: Ipv4Addr, mtu: u16) -> DynResult<AsyncDevice> {
    let mut config = Configuration::default();
    config.address(address).netmask(netmask).tun_name(name).mtu(mtu).up();
    config.platform_config(|conf| { conf.ensure_root_privileges(true); });
    let tunnel = match create_as_async(&config) {
        Ok(device) => Ok(device),
        Err(err) => bail!("Error creating tunnel: {}", err)
    };
    File::create(format!("/proc/sys/net/ipv6/conf/{name}/disable_ipv6"))?.write(&[0x31])?;
    tunnel
}


fn set_dns_server(dns_server: Option<Ipv4Addr>) -> DynResult<(String, Option<String>)> {
    let resolv_conf_data = read_to_string(RESOLV_CONF_PATH)?;
    let resolv_conf_lines: Vec<&str> = resolv_conf_data.lines().collect();

    if let Some(server) = dns_server {
        let filtered: Vec<&str> = resolv_conf_lines.into_iter().filter(|l| !l.trim_start().starts_with("nameserver")).collect();
        let new_contents = format!("{}\nnameserver {}", filtered.join("\n"), server);
        write(RESOLV_CONF_PATH, new_contents)?;
        Ok((resolv_conf_data, Some(server.to_string())))
    } else {
        let existing_dns = resolv_conf_lines.iter().find(|l| l.trim_start().starts_with("nameserver")).map(|l| l.trim_start().trim_start_matches("nameserver").trim().to_string());
        Ok((resolv_conf_data, existing_dns))
    }
}

fn reset_dns_server(resolv_conf_data: &str) -> DynResult<()> {
    write(RESOLV_CONF_PATH, resolv_conf_data)?;
    Ok(())
}


fn save_svr_table(svr_idx: u8) -> DynResult<Vec<Rtmsg>> {
    let svr_table = RtTable::UnrecognizedConst(svr_idx);
    let mut receiver_socket = create_socket()?;
    let mut sender_socket = create_socket()?;

    let mut table_data = Vec::new();
    let message = create_routing_message(svr_table, Rtm::Getroute, false, true, &[])?;
    send_netlink_stream(&mut receiver_socket, message, |hdr| {
        if hdr.rtm_table == svr_table {
            table_data.push(copy_rtmsg(hdr));
            let rm_msg = create_header(Rtm::Delroute, false, copy_rtmsg(hdr));
            send_netlink_message::<Rtm, Rtmsg, Rtm>(&mut sender_socket, rm_msg, true)?;
        }
        Ok(())
    })?;

    Ok(table_data)
}

fn restore_svr_table(table_data: &mut Vec<Rtmsg>) -> DynResult<()> {
    let mut socket = create_socket()?;

    while let Some(entry) = table_data.pop() {
        let add_msg = create_header(Rtm::Newroute, false, entry);
        send_netlink_message::<Rtm, Rtmsg, Rtm>(&mut socket, add_msg, true)?;
    }

    Ok(())
}

fn enable_routing(tunnel_address: Ipv4Addr, tunnel_dev: i32, svr_idx: u8) -> DynResult<(Rtmsg, Rtmsg)> {
    let svr_table = RtTable::UnrecognizedConst(svr_idx);
    let mut socket = create_socket()?;

    let tun_addr_vec = Vec::from(tunnel_address.octets());
    let route_message = create_rtmsg(svr_table, false, true, &[create_attr(Rta::Oif, tunnel_dev)?, create_attr(Rta::Gateway, tun_addr_vec)?])?;
    send_netlink_message::<Rtm, Rtmsg, Rtm>(&mut socket, create_header(Rtm::Newroute, false, copy_rtmsg(&route_message)), true)?;
    send_netlink_message::<Rtm, Rtmsg, Rtm>(&mut socket, create_clear_cache_message(Rtm::Newroute)?, true)?;

    let rule_message = create_rtmsg(svr_table, false, true, &[create_attr(FRA_MASK, svr_idx as i32)?])?;
    send_netlink_message::<Rtm, Rtmsg, Rtm>(&mut socket, create_header(Rtm::Newrule, false, copy_rtmsg(&rule_message)), true)?;
    send_netlink_message::<Rtm, Rtmsg, Rtm>(&mut socket, create_clear_cache_message(Rtm::Newrule)?, true)?;

    Ok((route_message, rule_message))
}

fn disable_routing(route_message: &Rtmsg, rule_message: &Rtmsg) -> DynResult<()> {
    let mut socket = create_socket()?;

    send_netlink_message::<Rtm, Rtmsg, Rtm>(&mut socket, create_header(Rtm::Delroute, false, copy_rtmsg(route_message)), true)?;
    send_netlink_message::<Rtm, Rtmsg, Rtm>(&mut socket, create_clear_cache_message(Rtm::Newroute)?, true)?;

    send_netlink_message::<Rtm, Rtmsg, Rtm>(&mut socket, create_header(Rtm::Delrule, false, copy_rtmsg(rule_message)), true)?;
    send_netlink_message::<Rtm, Rtmsg, Rtm>(&mut socket, create_clear_cache_message(Rtm::Newrule)?, true)?;

    Ok(())
}

fn create_firewall_rules(default_name: &str, default_network: &Ipv4Net, seaside_address: &Ipv4Addr, dns: Option<String>, capture_iface: HashSet<String>, capture_ranges: HashSet<String>, exempt_ranges: HashSet<String>, svr_idx: u8) -> DynResult<Vec<String>> {
    let mut rules = Vec::new();
    for range in exempt_ranges {
        rules.push(format!("-d {range} -j ACCEPT"));
    }
    for range in capture_ranges {
        rules.push(format!("-d {range} -j ACCEPT"));
        rules.push(format!("-d {range} -j MARK --set-mark {svr_idx}"));
    }
    for iface in capture_iface {
        let (address, cidr) = get_device_address_and_cidr(&iface)?;
        rules.push(format!("-o {iface} ! -d {address}/{cidr} -j ACCEPT"));
        rules.push(format!("-o {iface} ! -d {address}/{cidr} -j MARK --set-mark {svr_idx}"));
    }
    if let Some(server) = dns {
        rules.push(format!("-d {server} -j ACCEPT"));
    }
    rules.push(format!("-o {default_name} -s {} -d {seaside_address} -j ACCEPT", default_network.addr()));
    return Ok(rules);
}

fn enable_firewall(firewall_rules: &Vec<String>) -> Result<(), Box<dyn Error>> {
    let ipt = iptables::new(false)?;
    for chain in ["OUTPUT", "FORWARD"].iter() {
        for rule in firewall_rules.iter() {
            ipt.insert_unique("mangle", chain, rule, 1)?;
        }
    }
    Ok(())
}

fn disable_firewall(firewall_rules: &Vec<String>) -> Result<(), Box<dyn Error>> {
    let ipt = iptables::new(false)?;
    for chain in ["OUTPUT", "FORWARD"].iter() {
        for rule in firewall_rules.iter() {
            ipt.delete("mangle", chain, rule)?;
        }
    }
    Ok(())
}


pub struct PlatformInternalConfig {
    resolv_conf: String,
    svr_data: Vec<Rtmsg>,
    route_message: Rtmsg,
    rule_message: Rtmsg,
    firewall_table: Vec<String>
}

impl TunnelInternal {
    pub fn new(seaside_address: Ipv4Addr, tunnel_name: &str, tunnel_network: Ipv4Net, svr_index: u8, dns: Option<Ipv4Addr>, mut capture_iface: HashSet<String>, capture_ranges: HashSet<String>, exempt_ranges: HashSet<String>) -> DynResult<Self> {
        debug!("Checking system default network properties...");
        let (default_address, default_cidr, default_name, default_mtu) = get_default_interface(seaside_address)?;
        debug!("Default network properties received: address {default_address}, CIDR {default_cidr}, name {default_name}, MTU {default_mtu}");

        if capture_iface.is_empty() && capture_ranges.is_empty() {
            debug!("The default interface added to capture: {default_name}");
            capture_iface.insert(default_name.clone());
        }
    
        debug!("Creating tunnel device: address {}, netmask {}...", tunnel_network.addr(), tunnel_network.netmask());
        let tunnel_device = create_tunnel(tunnel_name, tunnel_network.addr(), tunnel_network.netmask(), default_mtu as u16)?;
        let tunnel_index = get_address_device(tunnel_network)?;

        debug!("Resetting DNS server in '{RESOLV_CONF_PATH}' file...");
        let (resolv_conf, new_dns) = set_dns_server(dns)?;
        debug!("New DNS server will be: {new_dns:?}");

        debug!("Clearing seaside-viridian-reef routing table {svr_index}...");
        let svr_data = save_svr_table(svr_index)?;

        debug!("Setting up routing...");
        let (route_message, rule_message) = enable_routing(tunnel_network.addr(), tunnel_index, svr_index)?;

        debug!("Enabling firewall...");
        let default_network = Ipv4Net::new(default_address, default_cidr)?;
        let firewall_table = create_firewall_rules(&default_name, &default_network, &seaside_address, new_dns, capture_iface, capture_ranges, exempt_ranges, svr_index)?;
        match enable_firewall(&firewall_table) {
            Ok(_) => info!("Firewall enabled!"),
            Err(err) => bail!("Error enabling firewall: {err}"),
        };

        let internal = PlatformInternalConfig {resolv_conf, svr_data, route_message, rule_message, firewall_table};
        Ok(Self {def_ip: default_address, def_cidr: default_cidr, tun_device: tunnel_device, _internal: internal})
    }
}

impl Drop for PlatformInternalConfig {
    #[allow(unused_must_use)]
    fn drop(&mut self) {
        debug!("Disabling firewall...");
        disable_firewall(&self.firewall_table).inspect_err(|e| error!("Error disabling firewall: {e}"));

        debug!("Resetting routing...");
        disable_routing(&self.route_message, &self.rule_message).inspect_err(|e| error!("Error resetting routing: {e}"));

        debug!("Restoring seaside-viridian-reef routing table...");
        restore_svr_table(&mut self.svr_data).inspect_err(|e| error!("Error restoring seaside-viridian-reef routing table: {e}"));

        debug!("Restore '{RESOLV_CONF_PATH}' file...");
        reset_dns_server(&self.resolv_conf).inspect_err(|e| error!("Error restoring routing '{RESOLV_CONF_PATH}' file: {e}"));
    }
}
