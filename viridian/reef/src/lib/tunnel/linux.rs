#[cfg(test)]
#[path = "../../../tests/tunnel/linux.rs"]
mod linux_test;

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use log::{debug, error};
use neli::consts::nl::NlTypeWrapper;
use neli::consts::rtnl::{Ifa, Ifla, RtTable, Rta, Rtm};
use neli::rtnl::{Ifinfomsg, Rtmsg};
use neli::socket::NlSocketHandle;
use nftables::batch::Batch;
use nftables::expr::{Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField, Prefix};
use nftables::helper::apply_ruleset;
use nftables::schema::{Chain, NfListObject, Rule, Table};
use nftables::stmt::{Accept, Mangle, Match, Operator, Statement};
use nftables::types::{NfChainType, NfFamily, NfHook};
use simple_error::{bail, require_with};
use tun::{create, Configuration, Device};

use super::nl_utils::{copy_rtmsg, create_address_message, create_attr, create_clear_cache_message, create_header, create_interface_message, create_routing_message, create_rtmsg, create_socket, send_netlink_message, send_netlink_stream};
use super::{bytes_to_int, bytes_to_ip_address, bytes_to_string, TunnelInternal};
use crate::DynResult;


const FRA_MASK: Rta = Rta::UnrecognizedConst(10);
const NFTABLES_TABLE_NAME: &str = "seaside-reef-table";
const NFTABLES_CHAIN_NAME: &str = "seaside-reef-chain";


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


fn create_tunnel(name: &str, address: Ipv4Addr, netmask: Ipv4Addr, mtu: u16) -> DynResult<Device> {
    let mut config = Configuration::default();
    config.address(address).netmask(netmask).tun_name(name).mtu(mtu).up();
    config.platform_config(|conf| { conf.ensure_root_privileges(true); });
    match create(&config) {
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


fn enable_firewall(default_interface: &str, default_network: &Ipv4Net, seaside_address: &Ipv4Addr, svr_index: u8) -> DynResult<Table> {
    let mut batch = Batch::new();

    let table = Table {
        family: NfFamily::IP,
        name: NFTABLES_TABLE_NAME.to_string(),
        ..Default::default()
    };
    batch.add(NfListObject::Table(table.clone()));

    for (hook, name) in vec![(NfHook::Output, "output"), (NfHook::Forward, "forward")] {
        let chain_name = format!("{NFTABLES_CHAIN_NAME}-{name}");
        batch.add(NfListObject::Chain(Chain {
            family: NfFamily::IP,
            table: NFTABLES_TABLE_NAME.to_string(),
            name: chain_name.clone(),
            _type: Some(NfChainType::Filter),
            hook: Some(hook),
            ..Default::default()
        }));
        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::IP,
            table: NFTABLES_TABLE_NAME.to_string(),
            chain: chain_name.clone(),
            expr: vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Meta(Meta {
                        key: MetaKey::Oifname
                    })),
                    right: Expression::String(default_interface.to_string()),
                    op: Operator::EQ
                }),
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField {
                        protocol: "ip".to_string(),
                        field: "saddr".to_string()
                    }))),
                    right: Expression::String(default_network.addr().to_string()),
                    op: Operator::EQ
                }),
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField {
                        protocol: "ip".to_string(),
                        field: "daddr".to_string()
                    }))),
                    right: Expression::String(seaside_address.to_string()),
                    op: Operator::EQ
                }),
                Statement::Accept(Some(Accept {}))
            ],
            ..Default::default()
        }));
        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::IP,
            table: NFTABLES_TABLE_NAME.to_string(),
            chain: chain_name,
            expr: vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Meta(Meta {
                        key: MetaKey::Oifname
                    })),
                    right: Expression::String(default_interface.to_string()),
                    op: Operator::EQ
                }),
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField {
                        protocol: "ip".to_string(),
                        field: "daddr".to_string()
                    }))),
                    right: Expression::Named(NamedExpression::Prefix(Prefix {
                        addr: Box::new(Expression::String(default_network.network().to_string())),
                        len: u32::from(default_network.prefix_len())
                    })),
                    op: Operator::NEQ
                }),
                Statement::Mangle(Mangle {
                    key: Expression::Named(NamedExpression::Meta(Meta {
                        key: MetaKey::Mark
                    })),
                    value: Expression::Number(u32::from(svr_index))
                }),
                Statement::Accept(Some(Accept {}))
            ],
            ..Default::default()
        }));
    }

    apply_ruleset(&batch.to_nftables(), None, None)?;
    Ok(table)
}

fn disable_firewall(nftable: &Table) -> DynResult<()> {
    let mut batch = Batch::new();

    batch.delete(NfListObject::Table(nftable.clone()));

    apply_ruleset(&batch.to_nftables(), None, None)?;
    Ok(())
}


pub struct PlatformInternalConfig {
    svr_data: Vec<Rtmsg>,
    route_message: Rtmsg,
    rule_message: Rtmsg,
    firewall_table: Table
}

impl TunnelInternal {
    pub fn new(seaside_address: Ipv4Addr, tunnel_name: &str, tunnel_network: Ipv4Net, svr_index: u8) -> DynResult<Self> {
        debug!("Checking system default network properties...");
        let (default_address, default_cidr, default_name, default_mtu) = get_default_interface(seaside_address)?;
        debug!("Default network properties received: address {default_address}, CIDR {default_cidr}, name {default_name}, MTU {default_mtu}");
    
        debug!("Creating tunnel device...");
        let tunnel_device = create_tunnel(tunnel_name, tunnel_network.addr(), tunnel_network.netmask(), default_mtu as u16)?;
        let tunnel_index = get_address_device(tunnel_network)?;

        debug!("Clearing seaside-viridian-reef routing table...");
        let svr_data = save_svr_table(svr_index)?;

        debug!("Setting up routing...");
        let (route_message, rule_message) = enable_routing(tunnel_network.addr(), tunnel_index, svr_index)?;

        debug!("Enabling firewall...");
        let default_network = Ipv4Net::new(default_address, default_cidr)?;
        let firewall_table = enable_firewall(&default_name, &default_network, &seaside_address, svr_index)?;

        let internal = PlatformInternalConfig {svr_data, route_message, rule_message, firewall_table};
        Ok(Self {def_ip: default_address, def_cidr: default_cidr, tun_device: tunnel_device, internal})
    }
}

impl Drop for TunnelInternal {
    #[allow(unused_must_use)]
    fn drop(&mut self) {
        debug!("Disabling firewall...");
        disable_firewall(&self.internal.firewall_table).inspect_err(|e| error!("Error disabling firewall: {}", e));

        debug!("Resetting routing...");
        disable_routing(&self.internal.route_message, &self.internal.rule_message).inspect_err(|e| error!("Error resetting routing: {}", e));

        debug!("Restoring seaside-viridian-reef routing table...");
        restore_svr_table(&mut self.internal.svr_data).inspect_err(|e| error!("Error restoring seaside-viridian-reef routing table: {}", e));
    }
}
