#[cfg(test)]
#[path = "../../../tests/tunnel/linux.rs"]
mod linux_test;

use std::borrow::Cow;
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
use nftables::batch::Batch;
use nftables::expr::{Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField, Range};
use nftables::helper::apply_ruleset;
use nftables::schema::{Chain, NfListObject, Rule, Table};
use nftables::stmt::{Mangle, Match, Operator, Statement};
use nftables::types::{NfChainType, NfFamily, NfHook};
use simple_error::{bail, require_with};
use tun::{create_as_async, AsyncDevice, Configuration};

use crate::tunnel::nl_utils::{copy_rtmsg, create_address_message, create_attr, create_clear_cache_message, create_header, create_interface_message, create_routing_message, create_rtmsg, create_socket, send_netlink_message, send_netlink_stream};
use crate::tunnel::{bytes_to_int, bytes_to_ip_address, bytes_to_string, string_to_bytes, Tunnelling};
use crate::utils::parse_env;
use crate::DynResult;

const NFTABLE_NAME: &str = "seaside";
const NFTABLES_OUTPUT_NAME: &str = "output";
const NFTABLES_OUTPUT_PRIORITY: i32 = -100;
const NFTABLES_FORWARD_NAME: &str = "forward";
const NFTABLES_FORWARD_PRIORITY: i32 = 0;

const NFTABLES_SOURCE_PORT: &str = "sport";
const NFTABLES_SOURCE_ADDRESS: &str = "saddr";
const NFTABLES_DESTINATION_ADDRESS: &str = "daddr";
const NFTABLES_PROTOCOL_IPV4: &str = "ip";
const NFTABLES_PROTOCOL_IPV6: &str = "ip6";
const NFTABLES_PROTOCOL_TCP: &str = "tcp";
const NFTABLES_PROTOCOL_UDP: &str = "udp";

const FRA_MASK: Rta = Rta::UnrecognizedConst(10);
const DEFAULT_RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

fn get_default_address_and_device(socket: &mut NlSocketHandle, target: Ipv4Addr) -> DynResult<(Ipv4Addr, i32)> {
    let sea_addr_vec = Vec::from(target.octets());
    let message = create_routing_message(RtTable::Unspec, Rtm::Getroute, false, false, &[create_attr(Rta::Dst, sea_addr_vec)?])?;
    let answer = send_netlink_message::<Rtm, Rtmsg, NlTypeWrapper>(socket, message, false)?.unwrap();
    let default_ip = answer.rtattrs.iter().find(|a| a.rta_type == Rta::Prefsrc).and_then(|a| bytes_to_ip_address(a.rta_payload.as_ref()).ok());
    let default_dev = answer.rtattrs.iter().find(|a| a.rta_type == Rta::Oif).and_then(|a| bytes_to_int(a.rta_payload.as_ref()).ok());
    Ok((require_with!(default_ip, "Default IP address was not found!"), require_with!(default_dev, "Default network interface was not found!")))
}

fn get_device_by_local_address(socket: &mut NlSocketHandle, target: Ipv4Addr) -> DynResult<i32> {
    let mut default_dev: Option<i32> = None;
    let message = create_address_message(0, Rtm::Getaddr, &[]);
    send_netlink_stream(socket, message, |hdr| {
        let default_address = hdr.rtattrs.iter().find(|a| a.rta_type == Ifa::Address).and_then(|a| bytes_to_ip_address(a.rta_payload.as_ref()).ok());
        if default_address.as_ref().is_some_and(|n| n == &target) {
            default_dev = Some(hdr.ifa_index);
        }
        Ok(())
    })?;
    Ok(require_with!(default_dev, "Default network interface was not found!"))
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

fn get_default_interface_by_local_address(local_address: Ipv4Addr) -> DynResult<(u8, String, i32)> {
    let mut socket = create_socket()?;

    let default_dev = get_device_by_local_address(&mut socket, local_address)?;
    let (default_name, default_cidr) = get_device_name_and_cidr(&mut socket, default_dev)?;
    let default_mtu = get_device_mtu(&mut socket, default_dev)?;

    Ok((default_cidr, default_name, default_mtu))
}

fn get_default_interface_by_remote_address(seaside_address: Ipv4Addr) -> DynResult<(Ipv4Addr, u8, String, i32)> {
    let mut socket = create_socket()?;

    let (default_ip, default_dev) = get_default_address_and_device(&mut socket, seaside_address)?;
    let (default_name, default_cidr) = get_device_name_and_cidr(&mut socket, default_dev)?;
    let default_mtu = get_device_mtu(&mut socket, default_dev)?;

    Ok((default_ip, default_cidr, default_name, default_mtu))
}

fn create_tunnel(name: &str, address: Ipv4Addr, netmask: Ipv4Addr, mtu: u16) -> DynResult<AsyncDevice> {
    let mut config = Configuration::default();
    config.address(address).netmask(netmask).tun_name(name).mtu(mtu).up();
    config.platform_config(|conf| {
        conf.ensure_root_privileges(true);
    });
    let tunnel = match create_as_async(&config) {
        Ok(device) => Ok(device),
        Err(err) => bail!("Error creating tunnel: {}", err),
    };
    File::create(format!("/proc/sys/net/ipv6/conf/{name}/disable_ipv6"))?.write(&[0x31])?;
    tunnel
}

fn set_dns_server(resolv_path: &str, dns_server: Option<Ipv4Addr>) -> DynResult<(String, Option<String>)> {
    let resolv_conf_data = read_to_string(resolv_path)?;
    let resolv_conf_lines: Vec<&str> = resolv_conf_data.lines().collect();

    if let Some(server) = dns_server {
        let filtered: Vec<&str> = resolv_conf_lines.into_iter().filter(|l| !l.trim_start().starts_with("nameserver")).collect();
        let new_contents = format!("{}\nnameserver {}", filtered.join("\n"), server);
        write(resolv_path, new_contents)?;
        Ok((resolv_conf_data, Some(server.to_string())))
    } else {
        let existing_dns = resolv_conf_lines.iter().find(|l| l.trim_start().starts_with("nameserver")).map(|l| l.trim_start().trim_start_matches("nameserver").trim().to_string());
        Ok((resolv_conf_data, existing_dns))
    }
}

fn reset_dns_server(resolv_path: &str, resolv_conf_data: &str) -> DynResult<()> {
    write(resolv_path, resolv_conf_data)?;
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

fn create_firewall_rules<'a>(default_name: &str, default_network: &Ipv4Net, seaside_address: &Ipv4Addr, dns: Option<String>, capture_iface: HashSet<String>, capture_ranges: HashSet<Ipv4Net>, exempt_ranges: HashSet<Ipv4Net>, capture_ports: Option<(u16, u16)>, exempt_ports: Option<(u16, u16)>, svr_idx: u8) -> DynResult<Vec<Rule<'a>>> {
    let mut rules = Vec::new();

    if let Some((lowest, highest)) = capture_ports {
        for proto in &[NFTABLES_PROTOCOL_TCP, NFTABLES_PROTOCOL_TCP] {
            rules.push(Rule {
                expr: vec![
                    Statement::Match(Match { left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Protocol })), right: Expression::String(Cow::Borrowed(proto)), op: Operator::EQ }),
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField { protocol: Cow::Borrowed(proto), field: Cow::Borrowed(NFTABLES_SOURCE_PORT) }))),
                        right: Expression::Range(Box::new(Range { range: [Expression::Number(lowest as u32), Expression::Number(highest as u32)] })),
                        op: Operator::IN,
                    }),
                    Statement::Mangle(Mangle { key: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Mark })), value: Expression::Number(svr_idx as u32) }),
                ]
                .into(),
                ..Default::default()
            });
            rules.push(Rule {
                expr: vec![
                    Statement::Match(Match { left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Protocol })), right: Expression::String(Cow::Borrowed(proto)), op: Operator::EQ }),
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField { protocol: Cow::Borrowed(proto), field: Cow::Borrowed(NFTABLES_SOURCE_PORT) }))),
                        right: Expression::Range(Box::new(Range { range: [Expression::Number(lowest as u32), Expression::Number(highest as u32)] })),
                        op: Operator::IN,
                    }),
                    Statement::Accept(None),
                ]
                .into(),
                ..Default::default()
            });
        }
    }

    for range in capture_ranges {
        for proto in &[NFTABLES_PROTOCOL_IPV4, NFTABLES_PROTOCOL_IPV6] {
            rules.push(Rule {
                expr: vec![
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField { protocol: Cow::Borrowed(proto), field: Cow::Borrowed(NFTABLES_DESTINATION_ADDRESS) }))),
                        right: Expression::String(Cow::Owned(range.to_string())),
                        op: Operator::EQ,
                    }),
                    Statement::Mangle(Mangle { key: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Mark })), value: Expression::Number(svr_idx as u32) }),
                ]
                .into(),
                ..Default::default()
            });
            rules.push(Rule {
                expr: vec![
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField { protocol: Cow::Borrowed(proto), field: Cow::Borrowed(NFTABLES_DESTINATION_ADDRESS) }))),
                        right: Expression::String(Cow::Owned(range.to_string())),
                        op: Operator::EQ,
                    }),
                    Statement::Accept(None),
                ]
                .into(),
                ..Default::default()
            });
        }
    }

    for iface in capture_iface {
        let (address, cidr) = get_device_address_and_cidr(&iface)?;
        let addr_repr = format!("{address}/{cidr}");

        for proto in &[NFTABLES_PROTOCOL_IPV4, NFTABLES_PROTOCOL_IPV6] {
            let iface_val = iface.clone();
            let addr_repr_val = addr_repr.clone();

            rules.push(Rule {
                expr: vec![
                    Statement::Match(Match { left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Oifname })), right: Expression::String(Cow::Owned(iface_val.clone())), op: Operator::EQ }),
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField { protocol: Cow::Borrowed(proto), field: Cow::Borrowed(NFTABLES_DESTINATION_ADDRESS) }))),
                        right: Expression::String(Cow::Owned(addr_repr_val.clone())),
                        op: Operator::NEQ,
                    }),
                    Statement::Mangle(Mangle { key: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Mark })), value: Expression::Number(svr_idx as u32) }),
                ]
                .into(),
                ..Default::default()
            });
            rules.push(Rule {
                expr: vec![
                    Statement::Match(Match { left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Oifname })), right: Expression::String(Cow::Owned(iface_val)), op: Operator::EQ }),
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField { protocol: Cow::Borrowed(proto), field: Cow::Borrowed(NFTABLES_DESTINATION_ADDRESS) }))),
                        right: Expression::String(Cow::Owned(addr_repr_val)),
                        op: Operator::NEQ,
                    }),
                    Statement::Accept(None),
                ]
                .into(),
                ..Default::default()
            });
        }
    }

    if let Some((lowest, highest)) = exempt_ports {
        for proto in &[NFTABLES_PROTOCOL_TCP, NFTABLES_PROTOCOL_UDP] {
            rules.push(Rule {
                expr: vec![
                    Statement::Match(Match { left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Protocol })), right: Expression::String(Cow::Borrowed(proto)), op: Operator::EQ }),
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField { protocol: Cow::Borrowed(proto), field: Cow::Borrowed(NFTABLES_SOURCE_PORT) }))),
                        right: Expression::Range(Box::new(Range { range: [Expression::Number(lowest as u32), Expression::Number(highest as u32)] })),
                        op: Operator::IN,
                    }),
                    Statement::Accept(None),
                ]
                .into(),
                ..Default::default()
            });
        }
    }

    for range in exempt_ranges {
        for proto in &[NFTABLES_PROTOCOL_IPV4, NFTABLES_PROTOCOL_IPV6] {
            rules.push(Rule {
                expr: vec![
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField { protocol: Cow::Borrowed(proto), field: Cow::Borrowed(NFTABLES_DESTINATION_ADDRESS) }))),
                        right: Expression::String(Cow::Owned(range.to_string())),
                        op: Operator::EQ,
                    }),
                    Statement::Accept(None),
                ]
                .into(),
                ..Default::default()
            });
        }
    }

    if let Some(server) = dns {
        for proto in &[NFTABLES_PROTOCOL_IPV4, NFTABLES_PROTOCOL_IPV6] {
            rules.push(Rule {
                expr: vec![
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField { protocol: Cow::Borrowed(proto), field: Cow::Borrowed(NFTABLES_DESTINATION_ADDRESS) }))),
                        right: Expression::String(Cow::Owned(server.clone())),
                        op: Operator::EQ,
                    }),
                    Statement::Accept(None),
                ]
                .into(),
                ..Default::default()
            });
        }
    }

    for proto in &[NFTABLES_PROTOCOL_IPV4, NFTABLES_PROTOCOL_IPV6] {
        rules.push(Rule {
            expr: vec![
                Statement::Match(Match { left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Oifname })), right: Expression::String(Cow::Owned(default_name.to_string())), op: Operator::EQ }),
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField { protocol: Cow::Borrowed(proto), field: Cow::Borrowed(NFTABLES_SOURCE_ADDRESS) }))),
                    right: Expression::String(Cow::Owned(default_network.addr().to_string())),
                    op: Operator::EQ,
                }),
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField { protocol: Cow::Borrowed(proto), field: Cow::Borrowed(NFTABLES_DESTINATION_ADDRESS) }))),
                    right: Expression::String(Cow::Owned(seaside_address.to_string())),
                    op: Operator::EQ,
                }),
                Statement::Accept(None),
            ]
            .into(),
            ..Default::default()
        });
    }

    return Ok(rules);
}

fn enable_firewall(firewall_rules: &Vec<Rule<'_>>) -> Result<(), Box<dyn Error>> {
    let mut batch = Batch::new();
    batch.add(NfListObject::Table(Table { family: NfFamily::INet, name: Cow::Borrowed(NFTABLE_NAME), ..Default::default() }));
    for (cn, hk, tp, pri) in [(NFTABLES_OUTPUT_NAME, NfHook::Output, NfChainType::Route, NFTABLES_OUTPUT_PRIORITY), (NFTABLES_FORWARD_NAME, NfHook::Forward, NfChainType::Filter, NFTABLES_FORWARD_PRIORITY)].iter() {
        batch.add(NfListObject::Chain(Chain { family: NfFamily::INet, table: Cow::Borrowed(NFTABLE_NAME), name: Cow::Borrowed(cn), _type: Some(*tp), hook: Some(*hk), prio: Some(*pri), ..Default::default() }));
        for rule in firewall_rules {
            let mut cloned = rule.clone();
            cloned.family = NfFamily::INet;
            cloned.table = NFTABLE_NAME.into();
            cloned.chain = Cow::Borrowed(cn);
            batch.add(NfListObject::Rule(cloned));
        }
    }
    Ok(apply_ruleset(&batch.to_nftables())?)
}

fn disable_firewall() -> Result<(), Box<dyn Error>> {
    let mut batch = Batch::new();
    batch.delete(NfListObject::Table(Table { family: NfFamily::INet, name: NFTABLE_NAME.into(), ..Default::default() }));
    Ok(apply_ruleset(&batch.to_nftables())?)
}

pub struct TunnelInternal {
    pub default_address: Ipv4Addr,
    tunnel_device: AsyncDevice,
    resolv_conf: String,
    resolv_path: String,
    svr_data: Vec<Rtmsg>,
    route_message: Rtmsg,
    rule_message: Rtmsg,
}

impl TunnelInternal {
    pub async fn new(seaside_address: Ipv4Addr, tunnel_name: &str, tunnel_network: Ipv4Net, svr_index: u8, dns: Option<Ipv4Addr>, mut capture_iface: HashSet<String>, capture_ranges: HashSet<Ipv4Net>, exempt_ranges: HashSet<Ipv4Net>, capture_ports: Option<(u16, u16)>, exempt_ports: Option<(u16, u16)>, local_address: Option<Ipv4Addr>) -> DynResult<Self> {
        debug!("Checking system default network properties...");
        let (default_address, default_cidr, default_name, default_mtu) = if let Some(address) = local_address {
            let (default_cidr, default_name, default_mtu) = get_default_interface_by_local_address(address)?;
            (address, default_cidr, default_name, default_mtu)
        } else {
            get_default_interface_by_remote_address(seaside_address)?
        };
        debug!("Default network properties received: address {default_address}, CIDR {default_cidr}, name {default_name}, MTU {default_mtu}");

        if capture_iface.is_empty() && capture_ranges.is_empty() && capture_ports.is_none() {
            debug!("The default interface added to capture: {default_name}");
            capture_iface.insert(default_name.clone());
        }

        debug!("Creating tunnel device: address {}, netmask {}...", tunnel_network.addr(), tunnel_network.netmask());
        let tunnel_device = create_tunnel(tunnel_name, tunnel_network.addr(), tunnel_network.netmask(), default_mtu as u16)?;
        let tunnel_index = get_address_device(tunnel_network)?;

        let resolv_path = parse_env("SEASIDE_RESOLV_CONF_PATH", Some(DEFAULT_RESOLV_CONF_PATH.to_string()));
        debug!("Resetting DNS server in '{resolv_path}' file...");
        let (resolv_conf, new_dns) = set_dns_server(&resolv_path, dns)?;
        debug!("New DNS server will be: {new_dns:?})");

        debug!("Clearing seaside-viridian-reef routing table {svr_index}...");
        let svr_data = save_svr_table(svr_index)?;

        debug!("Setting up routing...");
        let (route_message, rule_message) = enable_routing(tunnel_network.addr(), tunnel_index, svr_index)?;

        debug!("Enabling firewall...");
        let default_network = Ipv4Net::new(default_address, default_cidr)?;
        let firewall_table = create_firewall_rules(&default_name, &default_network, &seaside_address, new_dns, capture_iface, capture_ranges, exempt_ranges, capture_ports, exempt_ports, svr_index)?;
        match enable_firewall(&firewall_table) {
            Ok(_) => info!("Firewall enabled!"),
            Err(err) => bail!("Error enabling firewall: {err}"),
        };

        debug!("Creating tunnel handle...");
        Ok(Self { default_address, tunnel_device, resolv_conf, resolv_path, svr_data, route_message, rule_message })
    }
}

impl Tunnelling for TunnelInternal {
    async fn recv(&self, buf: &mut [u8]) -> DynResult<usize> {
        Ok(self.tunnel_device.recv(buf).await?)
    }

    async fn send(&self, buf: &[u8]) -> DynResult<usize> {
        Ok(self.tunnel_device.send(buf).await?)
    }
}

impl Drop for TunnelInternal {
    #[allow(unused_must_use)]
    fn drop(&mut self) {
        debug!("Disabling firewall...");
        disable_firewall().inspect_err(|e| error!("Error disabling firewall: {e}"));

        debug!("Resetting routing...");
        disable_routing(&self.route_message, &self.rule_message).inspect_err(|e| error!("Error resetting routing: {e}"));

        debug!("Restoring seaside-viridian-reef routing table...");
        restore_svr_table(&mut self.svr_data).inspect_err(|e| error!("Error restoring seaside-viridian-reef routing table: {e}"));

        debug!("Restore '{}' file...", self.resolv_path);
        reset_dns_server(&self.resolv_path, &self.resolv_conf).inspect_err(|e| error!("Error restoring routing '{}' file: {e}", self.resolv_path));
    }
}
