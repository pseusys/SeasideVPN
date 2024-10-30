#[cfg(test)]
#[path = "../../tests/tunnel.rs"]
mod tunnel_test;

use std::str;
use std::net::Ipv4Addr;

use neli::consts::nl::NlTypeWrapper;
use neli::consts::rtnl::{Ifa, Ifla, RtTable, Rta, Rtm};
use neli::rtnl::{Ifinfomsg, Rtmsg};
use simple_error::{bail, require_with};
use tun::{create_as_async, Configuration, AsyncDevice};

use crate::nl_utils::{bytes_to_int, bytes_to_ip_address, bytes_to_string, copy_rtmsg, create_address_message, create_attr, create_header, create_interface_message, create_router, create_routing_message, send_netlink_message, send_netlink_stream};
use crate::DynResult;

const FRA_MASK: Rta = Rta::UnrecognizedConst(10);


fn get_default_interface(seaside_address: Ipv4Addr) -> DynResult<(Ipv4Addr, u8, String, i32)> {
    let mut socket = create_router()?;

    let (default_ip, default_dev) = {
        let sea_addr_vec = Vec::from(seaside_address.octets());
        let message = create_routing_message(RtTable::Unspec, Rtm::Getroute, false, false, &[create_attr(Rta::Dst, sea_addr_vec)?])?;
        let answer = send_netlink_message::<Rtm, Rtmsg, NlTypeWrapper>(&mut socket, message, false)?.unwrap();
        let default_ip = answer.rtattrs.iter().find(|a| a.rta_type == Rta::Prefsrc).and_then(|a| bytes_to_ip_address(a.rta_payload.as_ref()).ok());
        let default_dev = answer.rtattrs.iter().find(|a| a.rta_type == Rta::Oif).and_then(|a| bytes_to_int(a.rta_payload.as_ref()).ok());
        (require_with!(default_ip, "Default IP address was not found!"), require_with!(default_dev, "Default network interface was not found!"))
    };

    let (default_name, default_cidr) = {
        let mut default_name: Option<String> = None;
        let mut default_cidr: Option<u8> = None;
        let message = create_address_message(default_dev, Rtm::Getaddr);
        send_netlink_stream(&mut socket, message, |hdr| {
            if hdr.ifa_index == default_dev {
                default_name = hdr.rtattrs.iter().find(|a| a.rta_type == Ifa::Label).and_then(|a| bytes_to_string(a.rta_payload.as_ref()).ok());
                default_cidr = Some(hdr.ifa_prefixlen);
            }
            Ok(())
        })?;
        (require_with!(default_name, "Default network interface name was not resolved!"), require_with!(default_cidr, "Default IP address CIDR was not resolved!"))
    };

    let default_mtu = {
        let message = create_interface_message(default_dev, Rtm::Getlink);
        let answer = send_netlink_message::<Rtm, Ifinfomsg, NlTypeWrapper>(&mut socket, message, false)?.unwrap();
        let default_mtu = answer.rtattrs.iter().find(|a| a.rta_type == Ifla::Mtu).and_then(|a| bytes_to_int(a.rta_payload.as_ref()).ok());
        require_with!(default_mtu, "Default network interface MTU was not resolved!")
    };

    Ok((default_ip, default_cidr, default_name, default_mtu))
}

fn create_tunnel(name: &str, address: Ipv4Addr, netmask: Ipv4Addr, mtu: u16) -> DynResult<AsyncDevice> {
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
    let mut receiver_socket = create_router()?;
    let mut sender_socket = create_router()?;

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

fn restore_svs_table(table_data: &mut Vec<Rtmsg>, svs_idx: i32) -> DynResult<()> {
    let svs_table = RtTable::UnrecognizedConst(svs_idx as u8);
    let mut receiver_socket = create_router()?;
    let mut sender_socket = create_router()?;

    let message = create_routing_message(svs_table, Rtm::Getroute, false, true, &[])?;
    send_netlink_stream(&mut receiver_socket, message, |hdr| {
        if hdr.rtm_table == svs_table {
            let rm_msg = create_header(Rtm::Delroute, false, copy_rtmsg(hdr));
            send_netlink_message::<Rtm, Rtmsg, Rtm>(&mut sender_socket, rm_msg, true)?;
        }
        Ok(())
    })?;

    while let Some(entry) = table_data.pop() {
        let add_msg = create_header(Rtm::Newroute, false, entry);
        send_netlink_message::<Rtm, Rtmsg, Rtm>(&mut sender_socket, add_msg, true)?;
    }

    Ok(())
}

async fn enable_routing(tunnel_address: Ipv4Addr, svs_idx: i32) -> DynResult<()> {
    let svs_table = RtTable::UnrecognizedConst(svs_idx as u8);
    let mut socket = create_router()?;

    let tunnel_dev = {
        let tun_router_addr = [&tunnel_address.octets()[..3], &vec![1][..]].concat();
        let message = create_routing_message(RtTable::Unspec, Rtm::Getroute, false, false, &[create_attr(Rta::Dst, tun_router_addr)?])?;
        let recv_payload = send_netlink_message::<Rtm, Rtmsg, Rtm>(&mut socket, message, false)?.unwrap();
        let tunnel_dev = recv_payload.rtattrs.iter().find(|a| a.rta_type == Rta::Oif).and_then(|a| bytes_to_int(a.rta_payload.as_ref()).ok());
        require_with!(tunnel_dev, "Tunnel device number was not resolved!")
    };

    let tun_addr_vec = Vec::from(tunnel_address.octets());
    let route_message = create_routing_message(svs_table, Rtm::Newroute, true, false, &[create_attr(Rta::Oif, tunnel_dev)?, create_attr(Rta::Gateway, tun_addr_vec)?])?;
    send_netlink_message::<Rtm, Rtmsg, Rtm>(&mut socket, route_message, true)?;
    let rule_message = create_routing_message(svs_table, Rtm::Newrule, true, false, &[create_attr(FRA_MASK, svs_idx)?])?;
    send_netlink_message::<Rtm, Rtmsg, Rtm>(&mut socket, rule_message, true)?;

    Ok(())
}

fn disable_routing(svs_idx: i32) -> DynResult<()> {
    let svs_table = RtTable::UnrecognizedConst(svs_idx as u8);
    let mut socket = create_router()?;

    let message = create_routing_message(svs_table, Rtm::Delrule, true, false, &[create_attr(FRA_MASK, svs_idx)?])?;
    send_netlink_message::<Rtm, Rtmsg, Rtm>(&mut socket, message, true)?;

    Ok(())
}


fn enable_firewall(sia: &str, sim: &str, sc: &str) -> DynResult<()> {
    let ipt = iptables::new(false)?;
    for chain in ["OUTPUT", "FORWARD"].iter() {
        for rule in [sia, sim, sc].iter() {
            ipt.insert_unique("mangle", chain, rule, 1)?;
        }
    }
    Ok(())
}

fn disable_firewall(sia: &str, sim: &str, sc: &str) -> DynResult<()> {
    let ipt = iptables::new(false)?;
    for chain in ["OUTPUT", "FORWARD"].iter() {
        for rule in [sia, sim, sc].iter() {
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
    sia: String,
    sim: String,
    sc: String
}

impl Tunnel {
    pub async fn new(name: &str, address: Ipv4Addr) -> DynResult<Tunnel> {
        let tunnel_address: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 82);  // TODO: check last byte not 1!
        let tunnet_netmask: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
        let svs_idx: i32 = 82;

        let (default_address, default_cidr, default_name, default_mtu) = get_default_interface(address)?;
        let tunnel_device = create_tunnel(name, tunnel_address, tunnet_netmask, default_mtu as u16)?;
        let svs_data = save_svs_table(svs_idx)?;
        enable_routing(tunnel_address, svs_idx).await?;

        let sia = format!("-o {default_name} ! --dst {default_address}/{default_cidr} -j ACCEPT");
        let sim = format!("-o {default_name} ! --dst {default_address}/{default_cidr} -j MARK --set-mark {svs_idx}");
        let sc = format!("-o {default_name} --src {default_address} --dst {address} -j ACCEPT");
        enable_firewall(&sia, &sim, &sc)?;

        Ok(Tunnel {def_ip: default_address, def_cidr: default_cidr, tun_device: tunnel_device, svs_idx, svs_data, sia, sim, sc})
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
        disable_firewall(&self.sia, &self.sim, &self.sc).inspect_err(|e| print!("{}", e));
        disable_routing(self.svs_idx).inspect_err(|e| print!("{}", e));
        restore_svs_table(&mut self.svs_data, self.svs_idx).inspect_err(|e| print!("{}", e));
    }
}
