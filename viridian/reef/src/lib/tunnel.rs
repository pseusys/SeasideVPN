#[cfg(test)]
#[path = "../../tests/tunnel.rs"]
mod tunnel_test;

use std::str;
use std::net::{IpAddr, Ipv4Addr};

use neli::consts::nl::NlTypeWrapper;
use neli::consts::rtnl::{Ifa, Ifla, RtTable, Rta, Rtm};
use neli::rtnl::{Ifinfomsg, Rtmsg};
use neli::socket::NlSocketHandle;
use simple_error::{bail, require_with};
use tun::{create_as_async, AbstractDevice, AsyncDevice, Configuration};

use crate::nl_utils::{bytes_to_int, bytes_to_ip_address, bytes_to_string, copy_rtmsg, create_address_message, create_attr, create_header, create_interface_message, create_socket, create_routing_message, send_netlink_message, send_netlink_stream};
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

fn get_address_device(socket: &mut NlSocketHandle, address: Ipv4Addr) -> DynResult<i32> {
    let tun_router_addr = [&address.octets()[..3], &vec![1][..]].concat();
    let message = create_routing_message(RtTable::Unspec, Rtm::Getroute, false, false, &[create_attr(Rta::Dst, tun_router_addr)?])?;
    let recv_payload = send_netlink_message::<Rtm, Rtmsg, Rtm>(socket, message, false)?.unwrap();
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


fn save_svs_table(svs_idx: i32) -> DynResult<Vec<Rtmsg>> {
    let svs_table = RtTable::UnrecognizedConst(svs_idx as u8);
    let mut receiver_socket = create_socket()?;
    let mut sender_socket = create_socket()?;

    let mut table_data = Vec::new();
    let message = create_routing_message(svs_table, Rtm::Getroute, false, true, &[])?;
    send_netlink_stream(&mut receiver_socket, message, |hdr| {
        if hdr.rtm_table == svs_table {
            table_data.push(copy_rtmsg(hdr));
            let rm_msg = create_header(Rtm::Delroute, false, copy_rtmsg(hdr));
            send_netlink_message::<Rtm, Rtmsg, Rtm>(&mut sender_socket, rm_msg, true)?;
        }
        Ok(())
    })?;

    Ok(table_data)
}

fn restore_svs_table(table_data: &mut Vec<Rtmsg>) -> DynResult<()> {
    let mut socket = create_socket()?;

    while let Some(entry) = table_data.pop() {
        let add_msg = create_header(Rtm::Newroute, false, entry);
        send_netlink_message::<Rtm, Rtmsg, Rtm>(&mut socket, add_msg, true)?;
    }

    Ok(())
}

fn enable_routing(tunnel_address: Ipv4Addr, svs_idx: i32) -> DynResult<()> {
    let svs_table = RtTable::UnrecognizedConst(svs_idx as u8);
    let mut socket = create_socket()?;

    let tunnel_dev = get_address_device(&mut socket, tunnel_address)?;
    let tun_addr_vec = Vec::from(tunnel_address.octets());
    let route_message = create_routing_message(svs_table, Rtm::Newroute, true, false, &[create_attr(Rta::Oif, tunnel_dev)?, create_attr(Rta::Gateway, tun_addr_vec)?])?;
    send_netlink_message::<Rtm, Rtmsg, Rtm>(&mut socket, route_message, true)?;
    let rule_message = create_routing_message(svs_table, Rtm::Newrule, true, false, &[create_attr(FRA_MASK, svs_idx)?])?;
    send_netlink_message::<Rtm, Rtmsg, Rtm>(&mut socket, rule_message, true)?;

    Ok(())
}

fn disable_routing(tunnel_address: Ipv4Addr, svs_idx: i32) -> DynResult<()> {
    let svs_table = RtTable::UnrecognizedConst(svs_idx as u8);
    let mut socket = create_socket()?;

    let tunnel_dev = get_address_device(&mut socket, tunnel_address)?;
    let tun_addr_vec = Vec::from(tunnel_address.octets());
    let route_message = create_routing_message(svs_table, Rtm::Delroute, true, false, &[create_attr(Rta::Oif, tunnel_dev)?, create_attr(Rta::Gateway, tun_addr_vec)?])?;
    send_netlink_message::<Rtm, Rtmsg, Rtm>(&mut socket, route_message, true)?;
    let rule_message = create_routing_message(svs_table, Rtm::Delrule, true, false, &[create_attr(FRA_MASK, svs_idx)?])?;
    send_netlink_message::<Rtm, Rtmsg, Rtm>(&mut socket, rule_message, true)?;

    Ok(())
}


fn create_firewall_rules(default_name: &str, default_address: &Ipv4Addr, default_cidr: u8, seaside_address: &Ipv4Addr, svs_idx: i32) -> Vec<String> {
    let sia = format!("-o {default_name} ! --dst {default_address}/{default_cidr} -j ACCEPT");
    let sim = format!("-o {default_name} ! --dst {default_address}/{default_cidr} -j MARK --set-mark {svs_idx}");
    let sc = format!("-o {default_name} --src {default_address} --dst {seaside_address} -j ACCEPT");
    return vec![sia, sim, sc];
}

fn enable_firewall(default_name: &str, default_address: &Ipv4Addr, default_cidr: u8, seaside_address: &Ipv4Addr, svs_idx: i32) -> DynResult<()> {
    let ipt = iptables::new(false)?;
    for chain in ["OUTPUT", "FORWARD"].iter() {
        for rule in create_firewall_rules(default_name, default_address, default_cidr, seaside_address, svs_idx).iter() {
            ipt.insert_unique("mangle", chain, rule, 1)?;
        }
    }
    Ok(())
}

fn disable_firewall(default_name: &str, default_address: &Ipv4Addr, default_cidr: u8, seaside_address: &Ipv4Addr, svs_idx: i32) -> DynResult<()> {
    let ipt = iptables::new(false)?;
    for chain in ["OUTPUT", "FORWARD"].iter() {
        for rule in create_firewall_rules(default_name, default_address, default_cidr, seaside_address, svs_idx).iter() {
            ipt.delete("mangle", chain, rule)?;
        }
    }
    Ok(())
}


pub struct Tunnel {
    def_ip: Ipv4Addr,
    def_cidr: u8,
    tun_device: AsyncDevice,

    svs_idx: i32,
    svs_data: Vec<Rtmsg>,
    def_name: String,
    sea_ip: Ipv4Addr
}

impl Tunnel {
    pub async fn new(name: &str, address: Ipv4Addr) -> DynResult<Tunnel> {
        let tunnel_address: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 82);  // TODO: check last byte not 1!
        let tunnet_netmask: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
        let svs_idx: i32 = 82;

        let (default_address, default_cidr, default_name, default_mtu) = get_default_interface(address)?;
        let tunnel_device = create_tunnel(name, tunnel_address, tunnet_netmask, default_mtu as u16).await?;
        let svs_data = save_svs_table(svs_idx)?;
        enable_routing(tunnel_address, svs_idx)?;
        enable_firewall(&default_name, &default_address, default_cidr, &address, svs_idx)?;

        Ok(Tunnel {def_ip: default_address, def_cidr: default_cidr, tun_device: tunnel_device, svs_idx, svs_data, def_name: default_name, sea_ip: address})
    }

    pub fn default_interface(&self) -> (Ipv4Addr, u8) {
        (self.def_ip, self.def_cidr)
    }

    pub async fn read_bytes(&self, bytes: &mut [u8]) -> DynResult<usize> {
        match self.tun_device.recv(bytes).await {
            Ok(res) => Ok(res),
            Err(res) => bail!("Error reading bytes from tunnel: {}", res)
        }
    }

    pub async fn write_bytes(&self, bytes: &[u8]) -> DynResult<usize> {
        match self.tun_device.send(&bytes).await {
            Ok(res) => Ok(res),
            Err(res) => bail!("Error writing bytes to tunnel: {}", res)
        }
    }
}

impl Drop for Tunnel {
    // TODO: log errors
    #[allow(unused_must_use)]
    fn drop(&mut self) {
        disable_firewall(&self.def_name, &self.def_ip, self.def_cidr, &self.sea_ip, self.svs_idx).inspect_err(|e| print!("{}", e));
        match self.tun_device.address() {
            Ok(IpAddr::V4(ripv4)) => {
                disable_routing(ripv4, self.svs_idx).inspect_err(|e| print!("{}", e));
            },
            _ => println!("Tunnel device has unknown address type!")
        };
        restore_svs_table(&mut self.svs_data).inspect_err(|e| print!("{}", e));
    }
}
