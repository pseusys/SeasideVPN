#[cfg(test)]
#[path = "../../../tests/tunnel_linux.rs"]
mod tunnel_linux_test;

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use log::{debug, error};
use neli::consts::nl::NlTypeWrapper;
use neli::consts::rtnl::{Ifa, Ifla, RtTable, Rta, Rtm};
use neli::rtnl::{Ifinfomsg, Rtmsg};
use neli::socket::NlSocketHandle;
use simple_error::{bail, require_with};
use tun::{create_as_async, AsyncDevice, Configuration};

use super::nl_utils::{copy_rtmsg, create_address_message, create_attr, create_clear_cache_message, create_header, create_interface_message, create_routing_message, create_rtmsg, create_socket, send_netlink_message, send_netlink_stream};
use super::{bytes_to_int, bytes_to_ip_address, bytes_to_string, Creatable, Tunnel};
use crate::DynResult;


const FRA_MASK: Rta = Rta::UnrecognizedConst(10);


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
    let message = create_address_message(device, Rtm::Getaddr);
    send_netlink_stream(socket, message, |hdr| {
        if hdr.ifa_index == device {
            default_name = hdr.rtattrs.iter().find(|a| a.rta_type == Ifa::Label).and_then(|a| bytes_to_string(a.rta_payload.as_ref()).ok());
            default_cidr = Some(hdr.ifa_prefixlen);
        }
        Ok(())
    })?;
    Ok((require_with!(default_name, "Default network interface name was not resolved!"), require_with!(default_cidr, "Default IP address CIDR was not resolved!")))
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


async fn create_tunnel(name: &str, address: Ipv4Addr, netmask: Ipv4Addr, mtu: u16) -> DynResult<AsyncDevice> {
    let mut config = Configuration::default();
    config.address(address).netmask(netmask).tun_name(name).mtu(mtu).up();
    config.platform_config(|conf| { conf.ensure_root_privileges(true); });
    match create_as_async(&config) {
        Ok(device) => Ok(device),
        Err(err) => bail!("Error creating tunnel: {}", err)
    }
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


fn create_firewall_rules(default_name: &str, default_address: &Ipv4Addr, default_cidr: u8, seaside_address: &Ipv4Addr, svr_idx: u8) -> Vec<String> {
    let sia = format!("-o {default_name} ! --dst {default_address}/{default_cidr} -j ACCEPT");
    let sim = format!("-o {default_name} ! --dst {default_address}/{default_cidr} -j MARK --set-mark {svr_idx}");
    let sc = format!("-o {default_name} --src {default_address} --dst {seaside_address} -j ACCEPT");
    return vec![sia, sim, sc];
}

fn enable_firewall(firewall_rules: &Vec<String>) -> DynResult<()> {
    let ipt = iptables::new(false)?;
    for chain in ["OUTPUT", "FORWARD"].iter() {
        for rule in firewall_rules.iter() {
            ipt.insert_unique("mangle", chain, rule, 1)?;
        }
    }
    Ok(())
}

fn disable_firewall(firewall_rules: &Vec<String>) -> DynResult<()> {
    let ipt = iptables::new(false)?;
    for chain in ["OUTPUT", "FORWARD"].iter() {
        for rule in firewall_rules.iter() {
            ipt.delete("mangle", chain, rule)?;
        }
    }
    Ok(())
}


pub struct PlatformInternalConfig {
    svr_data: Vec<Rtmsg>,
    route_message: Rtmsg,
    rule_message: Rtmsg,
    firewall_rules: Vec<String>
}

impl Creatable for Tunnel {
    async fn new(seaside_address: Ipv4Addr, tunnel_name: &str, tunnel_network: Ipv4Net, svr_index: u8) -> DynResult<Tunnel> {
        debug!("Checking system default network properties...");
        let (default_address, default_cidr, default_name, default_mtu) = get_default_interface(seaside_address)?;
        debug!("Default network properties received: address {default_address}, CIDR {default_cidr}, name {default_name}, MTU {default_mtu}");
    
        debug!("Creating tunnel device...");
        let tunnel_device = create_tunnel(tunnel_name, tunnel_network.addr(), tunnel_network.netmask(), default_mtu as u16).await?;
        let tunnel_index = get_address_device(tunnel_network)?;

        debug!("Clearing seaside-viridian-reef routing table...");
        let svr_data = save_svr_table(svr_index)?;

        debug!("Setting up routing...");
        let (route_message, rule_message) = enable_routing(tunnel_network.addr(), tunnel_index, svr_index)?;

        debug!("Enabling firewall...");
        let firewall_rules = create_firewall_rules(&default_name, &default_address, default_cidr, &seaside_address, svr_index);
        enable_firewall(&firewall_rules)?;

        let internal = PlatformInternalConfig {svr_data, route_message, rule_message, firewall_rules};
        Ok(Tunnel {def_ip: default_address, def_cidr: default_cidr, tun_device: tunnel_device, internal})
    }
}

impl Drop for Tunnel {
    #[allow(unused_must_use)]
    fn drop(&mut self) {
        debug!("Disabling firewall...");
        disable_firewall(&self.internal.firewall_rules).inspect_err(|e| error!("Error disabling firewall: {}", e));

        debug!("Resetting routing...");
        disable_routing(&self.internal.route_message, &self.internal.rule_message).inspect_err(|e| error!("Error resetting routing: {}", e));

        debug!("Restoring seaside-viridian-reef routing table...");
        restore_svr_table(&mut self.internal.svr_data).inspect_err(|e| error!("Error restoring seaside-viridian-reef routing table: {}", e));
    }
}
