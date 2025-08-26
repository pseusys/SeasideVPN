#[cfg(test)]
#[path = "../../../tests/tunnel/linux.rs"]
mod linux_test;

use std::collections::HashSet;
use std::error::Error;
use std::fs::{read_to_string, write, File};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};

use futures::TryStreamExt;
use ipnet::Ipv4Net;
use log::{debug, error, info};
use rtnetlink::packet_route::address::AddressAttribute;
use rtnetlink::packet_route::link::LinkAttribute;
use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType};
use rtnetlink::packet_route::rule::RuleMessage;
use rtnetlink::{new_connection, Handle, RouteMessageBuilder};
use simple_error::{bail, require_with};
use tokio::spawn;
use tun::{create_as_async, AsyncDevice, Configuration};

use crate::tunnel::Tunnelling;
use crate::utils::parse_env;
use crate::{run_coroutine_sync, DynResult};

const FULL_MASK: u8 = 32;
const DEFAULT_RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

async fn get_default_address_and_device(handle: &Handle, target: Ipv4Addr) -> DynResult<(Ipv4Addr, u32)> {
    let req = RouteMessageBuilder::<Ipv4Addr>::new().protocol(RouteProtocol::Unspec).scope(RouteScope::Universe).kind(RouteType::Unspec).destination_prefix(target, FULL_MASK).build();
    while let Some(res) = handle.route().get(req).execute().try_next().await? {
        let ip = res.attributes.iter().find_map(|a| match a { RouteAttribute::PrefSource(RouteAddress::Inet(address)) => Some(address), _ => None });
        let dev = res.attributes.iter().find_map(|a| match a { RouteAttribute::Oif(iface) => Some(iface), _ => None });
        return Ok((*require_with!(ip, "Default IP address was not found!"), *require_with!(dev, "Default network interface was not found!")))
    }
    bail!("Couldn't find any route to {target}!")
}

async fn get_device_by_local_address(handle: &Handle, target: Ipv4Addr) -> DynResult<u32> {
    while let Some(res) = handle.address().get().set_address_filter(IpAddr::V4(target)).execute().try_next().await? {
        return Ok(res.header.index);
    }
    bail!("Couldn't find any devices for address {target}!")
}

async fn get_device_name_and_cidr(handle: &Handle, device: u32) -> DynResult<(String, u8)> {
    while let Some(res) = handle.address().get().set_link_index_filter(device).execute().try_next().await? {
        let label = res.attributes.iter().find_map(|a| match a { AddressAttribute::Label(label) => Some(label), _ => None });
        return Ok((require_with!(label, "Device name was not found!").clone(), res.header.prefix_len));
    }
    bail!("Couldn't find any devices for index {device}!")
}

async fn get_device_address_and_cidr(label: &str) -> DynResult<(Ipv4Addr, u8)> {
    let (connection, handle, _) = new_connection()?;
    spawn(connection);

    while let Some(res) = handle.address().get().execute().try_next().await? {
        let name = res.attributes.iter().find_map(|a| match a { AddressAttribute::Label(label) => Some(label), _ => None });
        if name.is_some_and(|n| n == label) {
            let addr = res.attributes.iter().find_map(|a| match a { AddressAttribute::Address(IpAddr::V4(addr)) => Some(addr), _ => None });
            return Ok((*require_with!(addr, "Network interface IP address was not resolved!"), res.header.prefix_len))
        }
    }

    bail!("Couldn't find any devices for name {label}!")
}

async fn get_device_mtu(handle: &Handle, device: u32) -> DynResult<u32> {
    while let Some(res) = handle.link().get().match_index(device).execute().try_next().await? {
        let mtu = res.attributes.iter().find_map(|a| match a { LinkAttribute::Mtu(mtu) => Some(mtu), _ => None });
        return Ok(*require_with!(mtu, "Default network interface MTU was not resolved!"))
    }
    bail!("Couldn't find any links for device {device}!")
}

async fn get_address_device(network: Ipv4Net) -> DynResult<u32> {
    let (connection, handle, _) = new_connection()?;
    spawn(connection);

    let mut req = RouteMessageBuilder::<Ipv4Addr>::new().protocol(RouteProtocol::Unspec).scope(RouteScope::Universe).kind(RouteType::Unspec).build();
    req.attributes.push(RouteAttribute::Destination(RouteAddress::Inet(network.broadcast())));

    while let Some(res) = handle.route().get(req).execute().try_next().await? {
        let dev = res.attributes.iter().find_map(|a| match a { RouteAttribute::Oif(iface) => Some(iface), _ => None });
        return Ok(*require_with!(dev, "Tunnel device number was not resolved!"))
    }
    bail!("Couldn't find any route to {network}!")
}

async fn get_default_interface_by_local_address(local_address: Ipv4Addr) -> DynResult<(u8, String, u32)> {
    let (connection, handle, _) = new_connection()?;
    spawn(connection);

    let default_dev = get_device_by_local_address(&handle, local_address).await?;
    let (default_name, default_cidr) = get_device_name_and_cidr(&handle, default_dev).await?;
    let default_mtu = get_device_mtu(&handle, default_dev).await?;

    Ok((default_cidr, default_name, default_mtu))
}

async fn get_default_interface_by_remote_address(seaside_address: Ipv4Addr) -> DynResult<(Ipv4Addr, u8, String, u32)> {
    let (connection, handle, _) = new_connection()?;
    spawn(connection);

    let (default_ip, default_dev) = get_default_address_and_device(&handle, seaside_address).await?;
    let (default_name, default_cidr) = get_device_name_and_cidr(&handle, default_dev).await?;
    let default_mtu = get_device_mtu(&handle, default_dev).await?;

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

async fn save_svr_table(svr_idx: u8) -> DynResult<Vec<RouteMessage>> {
    let (connection, handle, _) = new_connection()?;
    spawn(connection);

    let mut table_data = Vec::new();
    let req = RouteMessageBuilder::<Ipv4Addr>::new().table_id(svr_idx as u32).protocol(RouteProtocol::Unspec).scope(RouteScope::Universe).kind(RouteType::Unspec).build();

    while let Some(route) = handle.route().get(req.clone()).execute().try_next().await? {
        table_data.push(route.clone());
        handle.route().del(route).execute().await?;
    }

    Ok(table_data)
}

async fn restore_svr_table(table_data: &mut Vec<RouteMessage>) -> DynResult<()> {
    let (connection, handle, _) = new_connection()?;
    spawn(connection);

    while let Some(entry) = table_data.pop() {
        handle.route().add(entry).execute().await?;
    }

    Ok(())
}

async fn enable_routing(tunnel_address: Ipv4Addr, tunnel_dev: u32, svr_idx: u8) -> DynResult<(RouteMessage, RuleMessage)> {
    let (connection, handle, _) = new_connection()?;
    spawn(connection);

    let route_msg = RouteMessageBuilder::<Ipv4Addr>::new().table_id(svr_idx as u32).protocol(RouteProtocol::Unspec).scope(RouteScope::Universe).kind(RouteType::Unspec).output_interface(tunnel_dev).gateway(tunnel_address).build();
    handle.route().add(route_msg.clone()).execute().await?;

    let mut rule_request = handle.rule().add().table_id(svr_idx as u32).fw_mark(svr_idx as u32);
    let rule_msg = rule_request.message_mut().clone();
    rule_request.execute().await?;

    Ok((route_msg, rule_msg))
}

async fn disable_routing(route_message: &RouteMessage, rule_message: &RuleMessage) -> DynResult<()> {
    let (connection, handle, _) = new_connection()?;
    spawn(connection);

    handle.route().del(route_message.clone()).execute().await?;
    handle.rule().del(rule_message.clone()).execute().await?;

    Ok(())
}

async fn create_firewall_rules(default_name: &str, default_network: &Ipv4Net, seaside_address: &Ipv4Addr, dns: Option<String>, capture_iface: HashSet<String>, capture_ranges: HashSet<Ipv4Net>, exempt_ranges: HashSet<Ipv4Net>, capture_ports: Option<(u16, u16)>, exempt_ports: Option<(u16, u16)>, svr_idx: u8) -> DynResult<Vec<String>> {
    let mut rules = Vec::new();
    if let Some((lowest, highest)) = capture_ports {
        rules.push(format!("-p tcp --sport {lowest}:{highest} -j ACCEPT"));
        rules.push(format!("-p tcp --sport {lowest}:{highest} -j MARK --set-mark {svr_idx}"));
        rules.push(format!("-p udp --sport {lowest}:{highest} -j ACCEPT"));
        rules.push(format!("-p udp --sport {lowest}:{highest} -j MARK --set-mark {svr_idx}"));
    }
    for range in capture_ranges {
        rules.push(format!("-d {range} -j ACCEPT"));
        rules.push(format!("-d {range} -j MARK --set-mark {svr_idx}"));
    }
    for iface in capture_iface {
        let (address, cidr) = get_device_address_and_cidr(&iface).await?;
        rules.push(format!("-o {iface} ! -d {address}/{cidr} -j ACCEPT"));
        rules.push(format!("-o {iface} ! -d {address}/{cidr} -j MARK --set-mark {svr_idx}"));
    }
    if let Some((lowest, highest)) = exempt_ports {
        rules.push(format!("-p tcp --sport {lowest}:{highest} -j ACCEPT"));
        rules.push(format!("-p udp --sport {lowest}:{highest} -j ACCEPT"));
    }
    for range in exempt_ranges {
        rules.push(format!("-d {range} -j ACCEPT"));
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

pub struct TunnelInternal {
    pub default_address: Ipv4Addr,
    tunnel_device: AsyncDevice,
    resolv_conf: String,
    resolv_path: String,
    svr_data: Vec<RouteMessage>,
    route_message: RouteMessage,
    rule_message: RuleMessage,
    firewall_table: Vec<String>,
}

impl TunnelInternal {
    pub async fn new(seaside_address: Ipv4Addr, tunnel_name: &str, tunnel_network: Ipv4Net, svr_index: u8, dns: Option<Ipv4Addr>, mut capture_iface: HashSet<String>, capture_ranges: HashSet<Ipv4Net>, exempt_ranges: HashSet<Ipv4Net>, capture_ports: Option<(u16, u16)>, exempt_ports: Option<(u16, u16)>, local_address: Option<Ipv4Addr>) -> DynResult<Self> {
        debug!("Checking system default network properties...");
        let (default_address, default_cidr, default_name, default_mtu) = if let Some(address) = local_address {
            let (default_cidr, default_name, default_mtu) = get_default_interface_by_local_address(address).await?;
            (address, default_cidr, default_name, default_mtu)
        } else {
            get_default_interface_by_remote_address(seaside_address).await?
        };
        debug!("Default network properties received: address {default_address}, CIDR {default_cidr}, name {default_name}, MTU {default_mtu}");

        if capture_iface.is_empty() && capture_ranges.is_empty() && capture_ports.is_none() {
            debug!("The default interface added to capture: {default_name}");
            capture_iface.insert(default_name.clone());
        }

        debug!("Creating tunnel device: address {}, netmask {}...", tunnel_network.addr(), tunnel_network.netmask());
        let tunnel_device = create_tunnel(tunnel_name, tunnel_network.addr(), tunnel_network.netmask(), default_mtu as u16)?;
        let tunnel_index = get_address_device(tunnel_network).await?;

        let resolv_path = parse_env("SEASIDE_RESOLV_CONF_PATH", Some(DEFAULT_RESOLV_CONF_PATH.to_string()));
        debug!("Resetting DNS server in '{resolv_path}' file...");
        let (resolv_conf, new_dns) = set_dns_server(&resolv_path, dns)?;
        debug!("New DNS server will be: {new_dns:?})");

        debug!("Clearing seaside-viridian-reef routing table {svr_index}...");
        let svr_data = save_svr_table(svr_index).await?;

        debug!("Setting up routing...");
        let (route_message, rule_message) = enable_routing(tunnel_network.addr(), tunnel_index, svr_index).await?;

        debug!("Enabling firewall...");
        let default_network = Ipv4Net::new(default_address, default_cidr)?;
        let firewall_table = create_firewall_rules(&default_name, &default_network, &seaside_address, new_dns, capture_iface, capture_ranges, exempt_ranges, capture_ports, exempt_ports, svr_index).await?;
        match enable_firewall(&firewall_table) {
            Ok(_) => info!("Firewall enabled!"),
            Err(err) => bail!("Error enabling firewall: {err}"),
        };

        debug!("Creating tunnel handle...");
        Ok(Self { default_address, tunnel_device, resolv_conf, resolv_path, svr_data, route_message, rule_message, firewall_table })
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
        run_coroutine_sync!(async {
            debug!("Disabling firewall...");
            disable_firewall(&self.firewall_table).inspect_err(|e| error!("Error disabling firewall: {e}"));

            debug!("Resetting routing...");
            disable_routing(&self.route_message, &self.rule_message).await.inspect_err(|e| error!("Error resetting routing: {e}"));

            debug!("Restoring seaside-viridian-reef routing table...");
            restore_svr_table(&mut self.svr_data).await.inspect_err(|e| error!("Error restoring seaside-viridian-reef routing table: {e}"));

            debug!("Restore '{}' file...", self.resolv_path);
            reset_dns_server(&self.resolv_path, &self.resolv_conf).inspect_err(|e| error!("Error restoring routing '{}' file: {e}", self.resolv_path));
        });
    }
}
