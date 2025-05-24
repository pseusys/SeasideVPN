use bincode::{decode_from_slice, encode_into_slice};
use lazy_static::lazy_static;
use rand::Rng;
use simple_error::bail;

use crate::bytes::{get_buffer, ByteBuffer};
use crate::crypto::{Asymmetric, Symmetric};
use crate::protocol::utils::ENCODE_CONF;
use crate::rng::get_rng;
use crate::utils::parse_env;
use crate::DynResult;
use super::common::{ProtocolFlag, ProtocolMessageType, ProtocolReturnCode};
use super::utils::{encode_to_32_bytes, get_type_size};


pub type ServerInitHeader = (u8, u32, u8, u16, u32, u16);
pub type ClientInitHeader = (u8, u32, [u8; 32], u32, u16);
pub type AnyHandshakeHeader = (u8, u32, u32, u16);
pub type AnyOtherHeader = (u8, u16);

const CLIENT_NAME: &str = concat!("reef-udp-", env!("CARGO_PKG_VERSION"));

lazy_static! {
    pub static ref TYPHOON_ALPHA: f32 = parse_env("TYPHOON_ALPHA", Some(0.125));
    pub static ref TYPHOON_BETA: f32 = parse_env("TYPHOON_BETA", Some(0.25));
    pub static ref TYPHOON_DEFAULT_RTT: f32 = parse_env("TYPHOON_DEFAULT_RTT", Some(5.0)) * 1000.;
    pub static ref TYPHOON_MIN_RTT: f32 = parse_env("TYPHOON_MIN_RTT", Some(1.0)) * 1000.0;
    pub static ref TYPHOON_MAX_RTT: f32 = parse_env("TYPHOON_MAX_RTT", Some(8.0)) * 1000.0;
    pub static ref TYPHOON_RTT_MULT: f32 = parse_env("TYPHOON_RTT_MULT", Some(4.0));
    pub static ref TYPHOON_MIN_TIMEOUT: u32 = (parse_env("TYPHOON_MIN_TIMEOUT", Some(4.0)) * 1000.0) as u32;
    pub static ref TYPHOON_MAX_TIMEOUT: u32 = (parse_env("TYPHOON_MAX_TIMEOUT", Some(32.0)) * 1000.0) as u32;
    pub static ref TYPHOON_DEFAULT_TIMEOUT: u32 = (parse_env("TYPHOON_DEFAULT_TIMEOUT", Some(30.0)) * 1000.0) as u32;
    pub static ref TYPHOON_MIN_NEXT_IN: u32 = (parse_env("TYPHOON_MIN_NEXT_IN", Some(64.0)) * 1000.0) as u32;
    pub static ref TYPHOON_MAX_NEXT_IN: u32 = (parse_env("TYPHOON_MAX_NEXT_IN", Some(256.0)) * 1000.0) as u32;
    pub static ref TYPHOON_INITIAL_NEXT_IN: f32 = parse_env("TYPHOON_INITIAL_NEXT_IN", Some(0.05));
    pub static ref TYPHOON_MAX_RETRIES: usize = parse_env("TYPHOON_MAX_RETRIES", Some(8));
    pub static ref TYPHOON_MAX_TAIL_LENGTH: usize = parse_env("TYPHOON_MAX_TAIL_LENGTH", Some(1024));
}


pub fn build_client_init<'a, 'b>(cipher: &Asymmetric, packet_number: u32, next_in: u32, token: &ByteBuffer<'b>) -> DynResult<(Symmetric, ByteBuffer<'b>)> {
    let buffer_size = get_type_size::<ClientInitHeader>()?;
    let buffer = get_buffer(Some(buffer_size));

    let user_name = encode_to_32_bytes(CLIENT_NAME);
    let tail_len = get_rng().gen_range(0..=*TYPHOON_MAX_TAIL_LENGTH);
    let header: ClientInitHeader = (ProtocolFlag::INIT as u8, packet_number, user_name, next_in, tail_len as u16);
    encode_into_slice(header, &mut buffer.slice_mut(), ENCODE_CONF)?;

    let header_with_body = buffer.append_buf(token);
    let mut message = header_with_body.expand_end(tail_len as isize);
    let (key, packet) = cipher.encrypt(&mut message)?;
    Ok((Symmetric::new(&key)?, packet))
}

#[inline]
pub fn build_client_hdsk<'a>(cipher: &mut Symmetric, packet_number: u32, next_in: u32) -> DynResult<ByteBuffer<'a>> {
    let buffer = get_buffer(None);
    build_client_hdsk_with_data(cipher, ProtocolFlag::HDSK as u8, packet_number, next_in, &buffer)
}

#[inline]
pub fn build_client_hdsk_data<'a>(cipher: &mut Symmetric, packet_number: u32, next_in: u32, data: &ByteBuffer<'a>) -> DynResult<ByteBuffer<'a>> {
    build_client_hdsk_with_data(cipher, ProtocolFlag::HDSK | ProtocolFlag::DATA, packet_number, next_in, data)
}

fn build_client_hdsk_with_data<'a>(cipher: &mut Symmetric, flags: u8, packet_number: u32, next_in: u32, data: &ByteBuffer<'a>) -> DynResult<ByteBuffer<'a>> {
    let tail_len = get_rng().gen_range(0..=*TYPHOON_MAX_TAIL_LENGTH);
    let header: AnyHandshakeHeader = (flags, packet_number, next_in, tail_len as u16);

    let header_size = get_type_size::<AnyHandshakeHeader>()?;
    let header_with_body = data.expand_start(header_size as isize);
    encode_into_slice(header, &mut header_with_body.slice_end_mut(header_size), ENCODE_CONF)?;

    let mut message = header_with_body.expand_end(tail_len as isize);
    Ok(cipher.encrypt(&mut message, None)?)
}

pub fn build_any_data<'a>(cipher: &mut Symmetric, data: &ByteBuffer<'a>) -> DynResult<ByteBuffer<'a>> {
    let tail_len = get_rng().gen_range(0..=*TYPHOON_MAX_TAIL_LENGTH);
    let header: AnyOtherHeader = (ProtocolFlag::DATA as u8, tail_len as u16);

    let header_size = get_type_size::<AnyOtherHeader>()?;
    let header_with_body = data.expand_start(header_size as isize);
    encode_into_slice(header, &mut header_with_body.slice_end_mut(header_size), ENCODE_CONF)?;

    let mut message = header_with_body.expand_end(tail_len as isize);
    Ok(cipher.encrypt(&mut message, None)?)
}

pub fn build_any_term<'a>(cipher: &mut Symmetric) -> DynResult<ByteBuffer<'a>> {
    let buffer_size = get_type_size::<AnyOtherHeader>()?;
    let mut buffer = get_buffer(Some(buffer_size));

    let tail_len = get_rng().gen_range(0..=*TYPHOON_MAX_TAIL_LENGTH);
    let header: AnyOtherHeader = (ProtocolFlag::TERM as u8, tail_len as u16);
    encode_into_slice(header, &mut buffer.slice_mut(), ENCODE_CONF)?;

    Ok(cipher.encrypt(&mut buffer, None)?)
}

pub fn parse_server_init(cipher: &mut Symmetric, packet: &mut ByteBuffer, expected_packet_number: u32) -> DynResult<(u16, u32)> {
    let header_size = get_type_size::<ServerInitHeader>()?;
    let data = cipher.decrypt(packet, None)?;
    let ((flags, packet_number, init_status, user_id, next_in, _), _): (ServerInitHeader, usize) = decode_from_slice(&data.slice_end(header_size), ENCODE_CONF)?;
    if flags != ProtocolFlag::INIT as u8 {
        bail!("Server INIT message flags malformed: {flags} != {}", ProtocolFlag::INIT)
    } else if init_status != ProtocolReturnCode::Success as u8 {
        bail!("Initialization failed with status {init_status}")
    } else if packet_number != expected_packet_number {
        bail!("Server INIT response packet ID doesn't match: {packet_number} != {expected_packet_number}!")
    } else if *TYPHOON_MIN_NEXT_IN > next_in || next_in > *TYPHOON_MAX_NEXT_IN {
        bail!("Incorrect next in value in server init: {} < {next_in} < {}", *TYPHOON_MIN_NEXT_IN, *TYPHOON_MAX_NEXT_IN)
    } else {
        Ok((user_id, next_in))
    }
}

fn parse_any_hdsk<'a>(data: &ByteBuffer<'a>, expected_packet_number: Option<u32>) -> DynResult<(u32, u32, Option<ByteBuffer<'a>>)> {
    let header_size = get_type_size::<AnyHandshakeHeader>()?;
    let ((_, packet_number, next_in, tail_length), _): (AnyHandshakeHeader, usize) = decode_from_slice(&data.slice_end(header_size), ENCODE_CONF)?;
    let tail_offset = data.len() - tail_length as usize;
    let payload  = data.rebuffer_both(header_size as isize, tail_offset as isize);
    if *TYPHOON_MIN_NEXT_IN > next_in || next_in > *TYPHOON_MAX_NEXT_IN {
        bail!("Incorrect next in value in server init: {} < {next_in} < {}", *TYPHOON_MIN_NEXT_IN, *TYPHOON_MAX_NEXT_IN)
    } else if let None = expected_packet_number {
        bail!("Server handshake message received, but expected packet number is still undefined!")
    } if packet_number != expected_packet_number.unwrap() {
        bail!("Server INIT response packet ID doesn't match: {packet_number} != {}!", expected_packet_number.unwrap())
    } else if payload.len() == 0 {
        Ok((packet_number, next_in, None))
    } else {
        Ok((packet_number, next_in, Some(payload)))
    }
}

fn parse_any_data<'a>(data: &ByteBuffer<'a>) -> DynResult<ByteBuffer<'a>> {
    let header_size = get_type_size::<AnyOtherHeader>()?;
    let ((_, tail_length), _): (AnyOtherHeader, usize) = decode_from_slice(&data.slice_end(header_size), ENCODE_CONF)?;
    let tail_offset = data.len() - tail_length as usize;
    Ok(data.rebuffer_both(header_size as isize, tail_offset as isize))
}

pub fn parse_server_message<'a>(cipher: &mut Symmetric, packet: &mut ByteBuffer<'a>, expected_packet_number: Option<u32>) -> DynResult<(ProtocolMessageType, Option<(u32, u32)>, Option<ByteBuffer<'a>>)> {
    let data = cipher.decrypt(packet, None)?;
    let flags = data.get(0);
    if *flags == ProtocolFlag::HDSK | ProtocolFlag::DATA {
        let (packet_number, next_in, payload) = parse_any_hdsk(&data, expected_packet_number)?;
        Ok((ProtocolMessageType::HandshakeData, Some((packet_number, next_in)), payload))
    } else if *flags == ProtocolFlag::HDSK as u8 {
        let (packet_number, next_in, payload) = parse_any_hdsk(&data, expected_packet_number)?;
        Ok((ProtocolMessageType::Handshake, Some((packet_number, next_in)), payload))
    } else if *flags == ProtocolFlag::DATA as u8 {
        let payload = parse_any_data(&data)?;
        Ok((ProtocolMessageType::Data, None, Some(payload)))
    } else if *flags == ProtocolFlag::TERM as u8 {
        Ok((ProtocolMessageType::Termination, None, None))
    } else {
        bail!("Message flags malformed: {flags}!")
    }
}

