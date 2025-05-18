use std::time::Duration;

use bincode::{decode_from_slice, encode_to_vec};
use rand::distributions::Standard;
use rand::rngs::OsRng;
use rand::Rng;
use simple_error::bail;
use socket2::{Domain, Socket, TcpKeepalive, Type};
use tokio::net::TcpSocket;
use lazy_static::lazy_static;

use crate::crypto::{Asymmetric, Symmetric};
use crate::DynResult;
use super::common::{ProtocolFlag, ProtocolMessageType, ProtocolReturnCode};
use super::super::utils::parse_env;
use super::utils::{encode_to_32_bytes, ENCODE_CONF};


pub type ServerInitHeader = (u8, u8, u16, u16);
pub type ClientInitHeader = (u8, [u8; 32], u16, u16);
pub type AnyOtherHeader = (u8, u16, u16);

const CLIENT_NAME: &str = concat!("reef-tcp-", env!("CARGO_PKG_VERSION"));

lazy_static! {
    static ref PORT_TAIL_LENGTH: usize = parse_env("PORT_TAIL_LENGTH", Some(512));
    pub static ref PORT_TIMEOUT: u32 = parse_env("PORT_TIMEOUT", Some(32));
}


pub fn create_and_configure_socket() -> DynResult<TcpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    let keepalive = TcpKeepalive::new().with_time(Duration::from_secs(7200)).with_interval(Duration::from_secs(75));
    socket.set_tcp_keepalive(&keepalive)?;
    socket.set_reuse_address(true)?;
    Ok(TcpSocket::from_std_stream(socket.into()))
}

pub fn build_client_init(cipher: &Asymmetric, token: &Vec<u8>) -> DynResult<(Vec<u8>, Vec<u8>)> {
    let user_name = encode_to_32_bytes(CLIENT_NAME);
    let data_len = token.len() + Symmetric::ciphertext_overhead();
    let tail_len = OsRng.gen_range(0..=*PORT_TAIL_LENGTH);
    let header: ClientInitHeader = (ProtocolFlag::INIT as u8, user_name, data_len as u16, tail_len as u16);
    let encoded_header = encode_to_vec(&header, ENCODE_CONF).unwrap();
    let (key, encrypted_header) = cipher.encrypt(&encoded_header)?;
    let tail = OsRng.sample_iter(Standard).take(tail_len).collect::<Vec<u8>>();
    Ok((key, [encrypted_header, tail].concat()))
}

pub fn build_any_data(cipher: &Symmetric, data: &Vec<u8>) -> DynResult<Vec<u8>> {
    let data_len = data.len() + Symmetric::ciphertext_overhead();
    let tail_len = OsRng.gen_range(0..=*PORT_TAIL_LENGTH);
    let header: AnyOtherHeader = (ProtocolFlag::DATA as u8, data_len as u16, tail_len as u16);
    let encoded_header = encode_to_vec(&header, ENCODE_CONF).unwrap();
    let encrypted_header = cipher.encrypt(&encoded_header, None)?;
    let encrypted_data = cipher.encrypt(&data, None)?;
    let tail = OsRng.sample_iter(Standard).take(tail_len).collect::<Vec<u8>>();
    Ok([encrypted_header, encrypted_data, tail].concat())
}

pub fn build_any_term(cipher: &Symmetric) -> DynResult<Vec<u8>> {
    let tail_len = OsRng.gen_range(0..=*PORT_TAIL_LENGTH);
    let header: AnyOtherHeader = (ProtocolFlag::TERM as u8, 0 as u16, tail_len as u16);
    let encoded_header = encode_to_vec(&header, ENCODE_CONF).unwrap();
    let encoded_header = cipher.encrypt(&encoded_header, None)?;
    let tail = OsRng.sample_iter(Standard).take(tail_len).collect::<Vec<u8>>();
    Ok([encoded_header, tail].concat())
}

pub fn parse_server_init(cipher: &Symmetric, packet: &[u8]) -> DynResult<(u16, u16)> {
    let header = cipher.decrypt(packet, None)?;
    let ((flags, init_status, user_id, tail_length), _): (ServerInitHeader, usize) = decode_from_slice(&header, ENCODE_CONF)?;
    if flags != ProtocolFlag::INIT as u8 {
        bail!("Server INIT message flags malformed: {flags} != {}", ProtocolFlag::INIT as u8)
    } else if init_status != ProtocolReturnCode::Success as u8 {
        bail!("Initialization failed with status {init_status}");
    } else {
        Ok((user_id, tail_length))
    }
}

pub fn parse_any_message_header(cipher: &Symmetric, packet: &[u8]) -> DynResult<(ProtocolMessageType, Option<(u16, u16)>)> {
    let header = cipher.decrypt(packet, None)?;
    let ((flags, data_length, tail_length), _): (AnyOtherHeader, usize) = decode_from_slice(&header, ENCODE_CONF)?;
    if flags == ProtocolFlag::DATA as u8 {
        Ok((ProtocolMessageType::Data, Some((data_length, tail_length))))
    } else if flags == ProtocolFlag::TERM as u8 {
        Ok((ProtocolMessageType::Termination, None))
    } else {
        bail!("Message flags malformed: {flags}!")
    }
}

pub fn parse_any_any_data(cipher: &Symmetric, packet: &[u8]) -> DynResult<Vec<u8>> {
    Ok(cipher.decrypt(packet, None)?)
}
