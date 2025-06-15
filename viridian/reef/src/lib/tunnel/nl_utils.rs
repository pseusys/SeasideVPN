use std::fmt::Debug;

use neli::consts::nl::{NlType, NlmF, NlmFFlags};
use neli::consts::rtnl::{Arphrd, Ifa, IfaFFlags, IffFlags, RtAddrFamily, RtScope, RtTable, Rta, RtaType, Rtm, RtmF, RtmFFlags, Rtn, Rtprot};
use neli::consts::socket::NlFamily;
use neli::err::NlError;
use neli::nl::{NlPayload, Nlmsghdr};
use neli::rtnl::{Ifaddrmsg, Ifinfomsg, Rtattr, Rtmsg};
use neli::socket::NlSocketHandle;
use neli::types::{Buffer, RtBuffer};
use neli::{FromBytesWithInput, Size, ToBytes};
use simple_error::bail;

use crate::DynResult;


// TODO: remove whenever neli-0.7.0 is out!
fn copy_rtattr(attribute: &Rtattr<Rta, Buffer>) -> Rtattr<Rta, Buffer> {
    let buffer = Buffer::from(attribute.rta_payload.as_ref());
    Rtattr::new(Some(attribute.rta_len), attribute.rta_type, buffer).expect("Error serializing payload!")
}

// TODO: remove whenever neli-0.7.0 is out!
fn copy_ifattr(attribute: &Rtattr<Ifa, Buffer>) -> Rtattr<Ifa, Buffer> {
    let buffer = Buffer::from(attribute.rta_payload.as_ref());
    Rtattr::new(Some(attribute.rta_len), attribute.rta_type, buffer).expect("Error serializing payload!")
}

// TODO: remove whenever neli-0.7.0 is out!
pub fn copy_rtmsg(message: &Rtmsg) -> Rtmsg {
    let flags = [RtmF::Notify, RtmF::Cloned, RtmF::Equalize, RtmF::Prefix, RtmF::LookupTable, RtmF::FibMatch];
    let flags = flags.iter().filter(|x| message.rtm_flags.contains(x)).map(|x| x.clone()).collect::<Vec<_>>();
    let buffer = message.rtattrs.iter().map(|x| copy_rtattr(x));
    Rtmsg {
        rtm_family: message.rtm_family,
        rtm_dst_len: message.rtm_dst_len,
        rtm_src_len: message.rtm_src_len,
        rtm_tos: message.rtm_tos,
        rtm_table: message.rtm_table,
        rtm_protocol: message.rtm_protocol,
        rtm_scope: message.rtm_scope,
        rtm_type: message.rtm_type,
        rtm_flags: RtmFFlags::new(&flags[..]),
        rtattrs: RtBuffer::from_iter(buffer)
    }
}


pub fn send_netlink_message<'a, T: NlType + Debug, P: FromBytesWithInput<'a, Input = usize> + Debug + ToBytes + Size, R: NlType + Debug>(socket: &'a mut NlSocketHandle, mut message: Nlmsghdr<T, P>, ack: bool) -> DynResult<Option<P>> {
    if ack {
        message.nl_flags.set(&NlmF::Ack);
    }
    if let Err(res) = socket.send(message) {
        bail!("Error sending message: {res}")
    }
    let received = match socket.recv::<R, P>() {
        Err(res) => if let NlError::Nlmsgerr(err) = res {
            bail!("Netlink error, errno: {}!", err.error)
        } else {
            bail!("Unknown error: {res:?}!")
        },
        Ok(res) => res
    };
    let response = match received {
        None => bail!("No message received in response!"),
        Some(res) => res
    };
    match (response.nl_payload, ack) {
        (NlPayload::Payload(res), false) => Ok(Some(res)),
        (NlPayload::Ack(_), true) => Ok(None),
        _ => bail!("Unexpected payload received in response!")
    }
}

pub fn send_netlink_stream<'a, T: NlType + Debug, P: for<'b> FromBytesWithInput<'b, Input = usize> + Debug + ToBytes + Size>(socket: &'a mut NlSocketHandle, message: Nlmsghdr<T, P>, mut prc: impl FnMut(&P) -> DynResult<()>) -> DynResult<()> {
    if let Err(res) = socket.send(message) {
        bail!("Error sending message: {res}")
    }
    for response in socket.iter::<T, P>(false) {
        let header = match response {
            Err(res) => bail!("Error receiving message: {res}"),
            Ok(res) => res
        };
        if let Ok(res) = header.get_payload() {
            prc(res)?;
        };
    };
    Ok(())
}


pub fn create_socket() -> DynResult<NlSocketHandle> {
    Ok(NlSocketHandle::connect(NlFamily::Route, None, &[])?)
}

pub fn create_attr<T: RtaType, P: Size + ToBytes>(attr_type: T, buffer: P) -> DynResult<Rtattr<T, Buffer>> {
    Ok(Rtattr::new(None, attr_type, buffer)?)
}

pub fn create_header<P: Size>(nl_type: Rtm, dump: bool, payload: P) -> Nlmsghdr<Rtm, P> {
    let mut flags = vec![NlmF::Request];
    if (nl_type == Rtm::Getlink || nl_type == Rtm::Getaddr || nl_type == Rtm::Getroute || nl_type == Rtm::Getrule) && dump {
        flags.push(NlmF::Dump);
    } else if nl_type == Rtm::Newlink || nl_type == Rtm::Newaddr || nl_type == Rtm::Newroute || nl_type == Rtm::Newrule {
        flags.push(NlmF::Create);
        flags.push(NlmF::Replace);
    }
    Nlmsghdr::new(None, nl_type, NlmFFlags::new(flags.as_slice()), None, None, NlPayload::Payload(payload))
}

pub fn create_rtmsg(table: RtTable, full_length: bool, direct: bool, args: &[Rtattr<Rta, Buffer>]) -> DynResult<Rtmsg> {
    let rtmdl = if full_length { 32 } else { 0 };
    let rtmp = if direct { Rtprot::Static } else { Rtprot::Unspec };
    let rtmt = if direct { Rtn::Unicast } else { Rtn::Unspec };
    let mut rtbuff = RtBuffer::new();
    for arg in args {
        rtbuff.push(copy_rtattr(arg));
    }
    Ok(Rtmsg {rtm_family: RtAddrFamily::Inet, rtm_dst_len: rtmdl, rtm_src_len: 0, rtm_tos: 0, rtm_table: table, rtm_protocol: rtmp, rtm_scope: RtScope::Universe, rtm_type: rtmt, rtm_flags: RtmFFlags::empty(), rtattrs: rtbuff})
}

pub fn create_routing_message(table: RtTable, nl_type: Rtm, direct: bool, dump: bool, args: &[Rtattr<Rta, Buffer>]) -> DynResult<Nlmsghdr<Rtm, Rtmsg>> {
    Ok(create_header(nl_type, dump, create_rtmsg(table, nl_type == Rtm::Getroute, direct, args)?))
}

pub fn create_clear_cache_message(nl_type: Rtm) -> DynResult<Nlmsghdr<Rtm, Rtmsg>> {
    let flags = vec![NlmF::Replace, NlmF::Echo];
    let message = create_rtmsg(RtTable::Unspec, false, false, &[])?;
    let header = Nlmsghdr::new(None, nl_type, NlmFFlags::new(flags.as_slice()), None, None, NlPayload::Payload(message));
    Ok(header)
}

pub fn create_address_message(interface: i32, nl_type: Rtm, args: &[Rtattr<Ifa, Buffer>]) -> Nlmsghdr<Rtm, Ifaddrmsg> {
    let mut rtbuff = RtBuffer::new();
    for arg in args {
        rtbuff.push(copy_ifattr(arg));
    }
    let message = Ifaddrmsg {ifa_family: RtAddrFamily::Inet, ifa_flags: IfaFFlags::empty(), ifa_index: interface, ifa_prefixlen: 0, ifa_scope: RtScope::Host.into(), rtattrs: rtbuff};
    create_header(nl_type, true, message)
}

pub fn create_interface_message(interface: i32, nl_type: Rtm) -> Nlmsghdr<Rtm, Ifinfomsg> {
    let message = Ifinfomsg::new(RtAddrFamily::Unspecified, Arphrd::None, interface, IffFlags::empty(), IffFlags::empty(), RtBuffer::new());
    create_header(nl_type, false, message)
}
