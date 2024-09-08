use std::io::{Read, Write};
use std::str;
use std::error::Error;
use std::net::Ipv4Addr;

use neli::consts::nl::{NlTypeWrapper, NlmF, NlmFFlags};
use neli::consts::rtnl::{Arphrd, Ifa, IfaFFlags, IffFlags, Ifla, RtAddrFamily, RtScope, RtTable, Rta, Rtm, RtmFFlags, Rtn, Rtprot};
use neli::consts::socket::NlFamily;
use neli::nl::{NlPayload, Nlmsghdr};
use neli::rtnl::{Ifaddrmsg, Ifinfomsg, Rtattr, Rtmsg};
use neli::socket::NlSocketHandle;
use neli::types::RtBuffer;
use tun2::{create, Configuration, Device};

const TUNNEL_ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 82);
const TUNNEL_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

const SVS_CODE: u8 = 82;


fn asciiz_to_string(slice_str: &str) -> String {
    String::from(&slice_str[0..slice_str.len() - 1])
}

fn get_default_interface(seaside_address: Ipv4Addr) -> Result<(Ipv4Addr, u8, String, u32), Box<dyn Error>> {
    let mut socket = NlSocketHandle::connect(NlFamily::Route, None, &[]).unwrap();

    let (default_ip, default_dev) = {
        let mut rtbuff = RtBuffer::new();
        rtbuff.push(Rtattr::new(None, Rta::Dst, Vec::from(seaside_address.octets())).ok().unwrap());
        let send_payload = Rtmsg {rtm_family: RtAddrFamily::Inet, rtm_dst_len: 32, rtm_src_len: 0, rtm_tos: 0, rtm_table: RtTable::Unspec, rtm_protocol: Rtprot::Unspec, rtm_scope: RtScope::Universe, rtm_type: Rtn::Unspec, rtm_flags: RtmFFlags::empty(), rtattrs: rtbuff};
        let send_msg = Nlmsghdr::new(None, Rtm::Getroute, NlmFFlags::new(&[NlmF::Request]), None, None, NlPayload::Payload(send_payload));
        socket.send(send_msg).unwrap();
        let recv_msg = socket.recv::<NlTypeWrapper, Rtmsg>().unwrap().unwrap();
        let recv_payload = recv_msg.get_payload().unwrap();
        let default_ip = recv_payload.rtattrs.iter().find(|a| a.rta_type == Rta::Prefsrc).and_then(|a| Some(Ipv4Addr::from(*<&[u8; 4]>::try_from(a.rta_payload.as_ref()).ok().unwrap())));
        let default_dev = recv_payload.rtattrs.iter().find(|a| a.rta_type == Rta::Oif).and_then(|a| Some(i32::from_ne_bytes(*<&[u8; 4]>::try_from(a.rta_payload.as_ref()).ok().unwrap())));
        (default_ip, default_dev)
    };

    let (default_name, default_cidr) = {
        let send_payload = Ifaddrmsg {ifa_family: RtAddrFamily::Inet, ifa_flags: IfaFFlags::empty(), ifa_index: default_dev.unwrap(), ifa_prefixlen: 0, ifa_scope: RtScope::Host.into(), rtattrs: RtBuffer::new()};
        let send_msg = Nlmsghdr::new(None, Rtm::Getaddr, NlmFFlags::new(&[NlmF::Request, NlmF::Dump]), None, None, NlPayload::Payload(send_payload));
        socket.send(send_msg).unwrap();
        let mut default_name: Option<String> = None;
        let mut default_cidr: Option<u8> = None;
        for response in socket.iter(false) {
            let header: Nlmsghdr<Rtm, Ifaddrmsg> = response.unwrap();
            if let Ok(recv_payload) = header.get_payload() {
                if recv_payload.ifa_index == default_dev.unwrap() {
                    let name = recv_payload.rtattrs.iter().find(|a| a.rta_type == Ifa::Label).and_then(|a| Some(str::from_utf8(a.rta_payload.as_ref())));
                    default_name = Some(asciiz_to_string(name.unwrap().ok().unwrap()));
                    default_cidr = Some(recv_payload.ifa_prefixlen);
                }
            }
        }
        (default_name, default_cidr)
    };

    let default_mtu = {
        let send_payload = Ifinfomsg::new(RtAddrFamily::Unspecified, Arphrd::None, default_dev.unwrap(), IffFlags::empty(), IffFlags::empty(), RtBuffer::new());
        let send_msg = Nlmsghdr::new(None, Rtm::Getlink, NlmFFlags::new(&[NlmF::Request]), None, None, NlPayload::Payload(send_payload));
        socket.send(send_msg).unwrap();
        let recv_msg = socket.recv::<NlTypeWrapper, Ifinfomsg>().unwrap().unwrap();
        let recv_payload = recv_msg.get_payload().unwrap();
        recv_payload.rtattrs.iter().find(|a| a.rta_type == Ifla::Mtu).and_then(|a| Some(u32::from_ne_bytes(*<&[u8; 4]>::try_from(a.rta_payload.as_ref()).ok().unwrap())))
    };

    Ok((default_ip.unwrap(), default_cidr.unwrap(), default_name.unwrap(), default_mtu.unwrap()))
}

fn create_tunnel(name: &str, mtu: u16) -> Result<Device, Box<dyn Error>> {
    let mut config = Configuration::default();
    config.address(TUNNEL_ADDRESS).netmask(TUNNEL_NETMASK).tun_name(name).mtu(mtu).up();
    config.platform_config(|conf| { conf.ensure_root_privileges(true); });
    match create(&config) {
        Ok(device) => Ok(device),
        Err(err) => Err(Box::from(err))
    }
}


fn flush_svs_table(receiver_socket: &mut NlSocketHandle) -> Result<(), Box<dyn Error>> {
    let svs_table = RtTable::UnrecognizedConst(SVS_CODE);
    let mut sender_socket = NlSocketHandle::connect(NlFamily::Route, None, &[]).unwrap();

    let send_payload = Rtmsg {rtm_family: RtAddrFamily::Inet, rtm_dst_len: 0, rtm_src_len: 0, rtm_tos: 0, rtm_table: svs_table, rtm_protocol: Rtprot::Unspec, rtm_scope: RtScope::Universe, rtm_type: Rtn::Unspec, rtm_flags: RtmFFlags::empty(), rtattrs: RtBuffer::new()};
    let send_msg = Nlmsghdr::new(None, Rtm::Getroute, NlmFFlags::new(&[NlmF::Request, NlmF::Dump]), None, None, NlPayload::Payload(send_payload));
    receiver_socket.send(send_msg).unwrap();
    for response in receiver_socket.iter(false) {
        let header: Nlmsghdr<Rtm, Rtmsg> = response.unwrap();
        if let Ok(ref recv_payload) = header.get_payload() {
            if recv_payload.rtm_table == svs_table {
                // TODO: store and restore
                let rm_msg = Nlmsghdr::new(None, Rtm::Delroute, NlmFFlags::new(&[NlmF::Request]), None, None, header.nl_payload);
                sender_socket.send(rm_msg).unwrap();
            }
        }
    }

    Ok(())
}

fn enable_routing(tunnel_interface: &str) -> Result<(), Box<dyn Error>> {
    let mut socket = NlSocketHandle::connect(NlFamily::Route, None, &[]).unwrap();
    flush_svs_table(&mut socket).ok().unwrap();

    let mut route_rtbuff = RtBuffer::new();
    route_rtbuff.push(Rtattr::new(None, Rta::Dst, vec![0, 0, 0, 0]).ok().unwrap());
    route_rtbuff.push(Rtattr::new(None, Rta::Gateway, Vec::from(TUNNEL_ADDRESS.octets())).ok().unwrap());
    route_rtbuff.push(Rtattr::new(None, Rta::Oif, tunnel_interface.as_bytes()).ok().unwrap());
    let route_send_payload = Rtmsg {rtm_family: RtAddrFamily::Inet, rtm_dst_len: 32, rtm_src_len: 0, rtm_tos: 0, rtm_table: RtTable::UnrecognizedConst(SVS_CODE), rtm_protocol: Rtprot::Static, rtm_scope: RtScope::Universe, rtm_type: Rtn::Unicast, rtm_flags: RtmFFlags::empty(), rtattrs: route_rtbuff};
    let route_send_msg = Nlmsghdr::new(None, Rtm::Newroute, NlmFFlags::new(&[NlmF::Request, NlmF::Create]), None, None, NlPayload::Payload(route_send_payload));
    socket.send(route_send_msg).unwrap();

    let mut rule_rtbuff = RtBuffer::new();
    rule_rtbuff.push(Rtattr::new(None, Rta::Mark, SVS_CODE).ok().unwrap());
    let rule_send_payload = Rtmsg {rtm_family: RtAddrFamily::Inet, rtm_dst_len: 0, rtm_src_len: 0, rtm_tos: 0, rtm_table: RtTable::Unspec, rtm_protocol: Rtprot::Static, rtm_scope: RtScope::Universe, rtm_type: Rtn::Unicast, rtm_flags: RtmFFlags::empty(), rtattrs: rule_rtbuff};
    let rule_send_msg = Nlmsghdr::new(None, Rtm::Newrule, NlmFFlags::new(&[NlmF::Request, NlmF::Create]), None, None, NlPayload::Payload(rule_send_payload));
    socket.send(rule_send_msg).unwrap();

    Ok(())
}

fn disable_routing() -> Result<(), Box<dyn Error>> {
    let mut socket = NlSocketHandle::connect(NlFamily::Route, None, &[]).unwrap();
    flush_svs_table(&mut socket).ok().unwrap();

    let mut rtbuff = RtBuffer::new();
    rtbuff.push(Rtattr::new(None, Rta::Mark, SVS_CODE).ok().unwrap());
    let send_payload = Rtmsg {rtm_family: RtAddrFamily::Inet, rtm_dst_len: 0, rtm_src_len: 0, rtm_tos: 0, rtm_table: RtTable::Unspec, rtm_protocol: Rtprot::Unspec, rtm_scope: RtScope::Universe, rtm_type: Rtn::Unspec, rtm_flags: RtmFFlags::empty(), rtattrs: rtbuff};
    let send_msg = Nlmsghdr::new(None, Rtm::Delrule, NlmFFlags::new(&[NlmF::Request]), None, None, NlPayload::Payload(send_payload));
    socket.send(send_msg).unwrap();

    Ok(())
}


fn enable_firewall(sia: &str, sim: &str, sc: &str) -> Result<(), Box<dyn Error>> {
    let ipt = iptables::new(false).unwrap();
    for chain in ["OUTPUT", "FORWARD"].iter() {
        for rule in [sia, sim, sc].iter() {
            ipt.insert_unique("mangle", chain, rule, 1).ok().unwrap();
        }
    }
    Ok(())
}

fn disable_firewall(sia: &str, sim: &str, sc: &str) -> Result<(), Box<dyn Error>> {
    let ipt = iptables::new(false).unwrap();
    for chain in ["OUTPUT", "FORWARD"].iter() {
        for rule in [sia, sim, sc].iter() {
            ipt.delete("mangle", chain, rule).ok().unwrap();
        }
    }
    Ok(())
}


pub struct Tunnel {
    def_ip: Ipv4Addr,
    def_cidr: u8,
    tun_device: Device,

    sia: String,
    sim: String,
    sc: String
}

impl Tunnel {
    pub async fn new(name: &str, address: Ipv4Addr) -> Result<Tunnel, Box<dyn Error>> {
        let (default_address, default_cidr, default_name, default_mtu) = get_default_interface(address).unwrap();
        let tunnel_device = create_tunnel(name, default_mtu as u16)?;
        enable_routing(name).ok().unwrap();

        let sia = format!("-o {default_name} --dst {default_address}/{default_cidr} -j ACCEPT");
        let sim = format!("-o {default_name} --dst {default_address}/{default_cidr} -j MARK --set-mark {SVS_CODE}");
        let sc = format!("-o {default_name} --src {default_address} --dst {address} -j ACCEPT");
        enable_firewall(&sia, &sim, &sc).ok().unwrap();

        Ok(Tunnel {def_ip: default_address, def_cidr: default_cidr, tun_device: tunnel_device, sia, sim, sc})
    }

    pub fn default_interface(&self) -> (Ipv4Addr, u8) {
        (self.def_ip, self.def_cidr)
    }

    fn read_bytes(&mut self, bytes: &mut Vec<u8>) {
        self.tun_device.read(bytes).ok().unwrap();
    }

    fn write_bytes(&mut self, bytes: &Vec<u8>) {
        self.tun_device.write(&bytes).ok().unwrap();
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        disable_firewall(&self.sia, &self.sim, &self.sc).ok().unwrap();
        disable_routing().ok().unwrap();
    }
}
