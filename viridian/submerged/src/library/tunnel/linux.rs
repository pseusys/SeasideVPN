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
use tun2::platform::Device;
use tun2::{create, Configuration};

use super::Tunnel;

const TUNNEL_ADDRESS: (u8, u8, u8, u8) = (192, 168, 0, 65);
const TUNNEL_NETMASK: (u8, u8, u8, u8) = (255, 255, 255, 0);


fn asciiz_to_string(slice_str: &str) -> String {
    String::from(&slice_str[0..slice_str.len() - 1])
}

fn get_default_interface(seaside_address: Ipv4Addr) -> Result<(Ipv4Addr, u8, String, u32), Box<dyn Error>> {
    let mut socket = NlSocketHandle::connect(NlFamily::Route, None, &[]).unwrap();

    let (default_ip, default_dev) = {
        let mut rtbuff = RtBuffer::new();
        rtbuff.push(Rtattr::new(None, Rta::Dst, Vec::from(seaside_address.octets())).ok().unwrap());
        let send_payload = Rtmsg {rtm_family: RtAddrFamily::Inet, rtm_dst_len: 32, rtm_src_len: 0, rtm_tos: 0, rtm_table: RtTable::Unspec, rtm_protocol: Rtprot::Unspec, rtm_scope: RtScope::Universe, rtm_type: Rtn::Unspec, rtm_flags: RtmFFlags::empty(), rtattrs: rtbuff};
        let send_msg = Nlmsghdr::new(None,  Rtm::Getroute, NlmFFlags::new(&[NlmF::Request]), None, None, NlPayload::Payload(send_payload));
        socket.send(send_msg).unwrap();
        let recv_msg = socket.recv::<NlTypeWrapper, Rtmsg>().unwrap().unwrap();
        let recv_payload = recv_msg.get_payload().unwrap();
        let default_ip = recv_payload.rtattrs.iter().find(|a| a.rta_type == Rta::Prefsrc).and_then(|a| Some(Ipv4Addr::from(*<&[u8; 4]>::try_from(a.rta_payload.as_ref()).ok().unwrap())));
        let default_dev = recv_payload.rtattrs.iter().find(|a| a.rta_type == Rta::Oif).and_then(|a| Some(i32::from_ne_bytes(*<&[u8; 4]>::try_from(a.rta_payload.as_ref()).ok().unwrap())));
        (default_ip, default_dev)
    };

    // TODO: run "Ifaddrmsg" request to retrieve single return message.
    let (default_name, default_cidr) = {
        let send_payload = Ifaddrmsg {ifa_family: RtAddrFamily::Inet, ifa_flags: IfaFFlags::empty(), ifa_index: default_dev.unwrap(), ifa_prefixlen: 0, ifa_scope: RtScope::Host.into(), rtattrs: RtBuffer::new()};
        let send_msg = Nlmsghdr::new(None,  Rtm::Getaddr, NlmFFlags::new(&[NlmF::Request, NlmF::Root]), None, None, NlPayload::Payload(send_payload));
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
        let send_payload = Ifinfomsg::new(RtAddrFamily::Inet, Arphrd::None, default_dev.unwrap(), IffFlags::empty(), IffFlags::empty(), RtBuffer::new());
        let send_msg = Nlmsghdr::new(None,  Rtm::Getlink, NlmFFlags::new(&[NlmF::Request]), None, None, NlPayload::Payload(send_payload));
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


pub struct LinuxTunnel {
    def_ip: Ipv4Addr,
    def_cidr: u8,
    tun_device: Device
}


impl Tunnel for LinuxTunnel {
    async fn new(name: &str, address: Ipv4Addr) -> Result<LinuxTunnel, Box<dyn Error>> {
        let (default_address, default_cidr, default_name, default_mtu) = get_default_interface(address).unwrap();
        let tunnel_device = create_tunnel(&name, default_mtu as u16).ok().unwrap();

        println!("We will be wrapping interface: {default_address:?}, {default_cidr:?}, {default_name:?}, {default_mtu:?}");

        // let ipt = iptables::new(false).unwrap();
        // let chain = ipt.new_chain("nat", "NEWCHAINNAME").is_ok();

        Ok(LinuxTunnel {def_ip: default_address, def_cidr: default_cidr, tun_device: tunnel_device})
    }

    fn default_interface(&self) -> (Ipv4Addr, u8) {
        (self.def_ip, self.def_cidr)
    }
}
