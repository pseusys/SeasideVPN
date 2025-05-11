use bincode::{decode_from_slice, encode_to_vec};
use lazy_static::lazy_static;
use rand::distributions::Standard;
use rand::rngs::OsRng;
use rand::Rng;
use simple_error::{bail, require_with};

use crate::crypto::{Asymmetric, Symmetric};
use crate::protocol::utils::ENCODE_CONF;
use crate::utils::{get_packet, parse_env};
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


pub fn build_client_init(cipher: &Asymmetric, packet_number: u32, next_in: u32, token: &Vec<u8>) -> DynResult<(Vec<u8>, Vec<u8>)> {
    let user_name = encode_to_32_bytes(CLIENT_NAME);
    let tail_len = OsRng.gen_range(0..=*TYPHOON_MAX_TAIL_LENGTH);
    let header: ClientInitHeader = (ProtocolFlag::INIT as u8, packet_number, user_name, next_in, tail_len as u16);
    let encoded_header = encode_to_vec(&header, ENCODE_CONF).unwrap();
    let tail = OsRng.sample_iter(Standard).take(tail_len).collect::<Vec<u8>>();
    let packet = [encoded_header, token.to_vec(), tail].concat();
    let (key, encrypted_packet) = cipher.encrypt(&packet)?;
    Ok((key, encrypted_packet))
}

pub fn build_client_hdsk(cipher: &Symmetric, packet_number: u32, next_in: u32) -> DynResult<Vec<u8>> {
    let buffer = get_packet();
    build_client_hdsk_with_data(cipher, ProtocolFlag::HDSK as u8, packet_number, next_in, &buffer)
}

pub fn build_client_hdsk_data(cipher: &Symmetric, packet_number: u32, next_in: u32, data: &Vec<u8>) -> DynResult<Vec<u8>> {
    build_client_hdsk_with_data(cipher, ProtocolFlag::HDSK | ProtocolFlag::DATA, packet_number, next_in, data)
}

fn build_client_hdsk_with_data(cipher: &Symmetric, flags: u8, packet_number: u32, next_in: u32, data: &Vec<u8>) -> DynResult<Vec<u8>> {
    let tail_len = OsRng.gen_range(0..=*TYPHOON_MAX_TAIL_LENGTH);
    let header: AnyHandshakeHeader = (flags, packet_number, next_in, tail_len as u16);
    let encoded_header = encode_to_vec(&header, ENCODE_CONF).unwrap();
    let tail = OsRng.sample_iter(Standard).take(tail_len).collect::<Vec<u8>>();
    let packet = [encoded_header, data.to_vec(), tail].concat();
    Ok(cipher.encrypt(&packet, None)?)
}

pub fn build_any_data(cipher: &Symmetric, data: &Vec<u8>) -> DynResult<Vec<u8>> {
    let tail_len = OsRng.gen_range(0..=*TYPHOON_MAX_TAIL_LENGTH);
    let header: AnyOtherHeader = (ProtocolFlag::DATA as u8, tail_len as u16);
    let encoded_header = encode_to_vec(&header, ENCODE_CONF).unwrap();
    let tail = OsRng.sample_iter(Standard).take(tail_len).collect::<Vec<u8>>();
    let packet = [encoded_header, data.to_vec(), tail].concat();
    Ok(cipher.encrypt(&packet, None)?)
}

pub fn build_any_term(cipher: &Symmetric) -> DynResult<Vec<u8>> {
    let tail_len = OsRng.gen_range(0..=*TYPHOON_MAX_TAIL_LENGTH);
    let header: AnyOtherHeader = (ProtocolFlag::TERM as u8, tail_len as u16);
    let encoded_header = encode_to_vec(&header, ENCODE_CONF).unwrap();
    let tail = OsRng.sample_iter(Standard).take(tail_len).collect::<Vec<u8>>();
    let packet = [encoded_header, tail].concat();
    Ok(cipher.encrypt(&packet, None)?)
}

pub fn parse_server_init(cipher: &Symmetric, packet: &[u8], expected_packet_number: u32) -> DynResult<(u16, u32)> {
    let header_size = get_type_size::<ServerInitHeader>()?;
    let data = cipher.decrypt(packet, None)?;
    let ((flags, packet_number, init_status, user_id, next_in, _), _): (ServerInitHeader, usize) = decode_from_slice(&data[..header_size], ENCODE_CONF)?;
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

fn parse_any_hdsk(data: &[u8], expected_packet_number: Option<u32>) -> DynResult<(u32, u32, Option<Vec<u8>>)> {
    let header_size = get_type_size::<AnyHandshakeHeader>()?;
    let ((_, packet_number, next_in, tail_length), _): (AnyHandshakeHeader, usize) = decode_from_slice(&data[..header_size], ENCODE_CONF)?;
    let tail_offset = data.len() - tail_length as usize;
    let payload  = Vec::from(&data[header_size..tail_offset]);
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

fn parse_any_data(data: &[u8]) -> DynResult<Vec<u8>> {
    let header_size = get_type_size::<AnyOtherHeader>()?;
    let ((_, tail_length), _): (AnyOtherHeader, usize) = decode_from_slice(&data[..header_size], ENCODE_CONF)?;
    let tail_offset = data.len() - tail_length as usize;
    Ok(Vec::from(&data[header_size..tail_offset]))
}

pub fn parse_server_message(cipher: &Symmetric, packet: &[u8], expected_packet_number: Option<u32>) -> DynResult<(ProtocolMessageType, Option<(u32, u32)>, Option<Vec<u8>>)> {
    let data = cipher.decrypt(packet, None)?;
    let flags = require_with!(data.get(0), "Received message length was 0!");
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

