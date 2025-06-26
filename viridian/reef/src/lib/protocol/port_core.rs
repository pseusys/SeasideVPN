use std::net::TcpStream;
use std::time::Duration;

use bincode::{decode_from_slice, encode_into_slice};
use rand::{Rng, RngCore};
use simple_error::bail;
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use lazy_static::lazy_static;

use crate::bytes::{get_buffer, ByteBuffer};
use crate::crypto::{Asymmetric, Symmetric, MAC_LEN, NONCE_LEN};
use crate::DynResult;
use crate::rng::get_rng;
use super::common::{ProtocolFlag, ProtocolMessageType, ProtocolReturnCode};
use super::super::utils::parse_env;
use super::utils::{encode_to_32_bytes, get_type_size, ENCODE_CONF};


pub type ServerInitHeader = (u8, u8, u16, u16);
pub type ClientInitHeader = (u8, [u8; 32], u16, u16);
pub type AnyOtherHeader = (u8, u16, u16);

const CLIENT_NAME: &str = concat!("reef-tcp-", env!("CARGO_PKG_VERSION"));

lazy_static! {
    static ref PORT_TAIL_LENGTH: usize = parse_env("PORT_TAIL_LENGTH", Some(512));
    pub static ref PORT_TIMEOUT: u32 = (parse_env("PORT_TIMEOUT", Some(32.0)) * 1000.0) as u32;
}


pub fn create_and_configure_socket() -> DynResult<TcpStream> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    let keepalive = TcpKeepalive::new().with_time(Duration::from_secs(7200)).with_interval(Duration::from_secs(75));
    socket.set_tcp_keepalive(&keepalive)?;
    socket.set_reuse_address(true)?;
    Ok(socket.into())
}

pub async fn build_client_init<'a, 'b>(cipher: &Asymmetric, token: &ByteBuffer<'b>) -> DynResult<(Symmetric, ByteBuffer<'b>)> {
    let mut rand = get_rng();
    let buffer_size = get_type_size::<ClientInitHeader>()?;
    let buffer = get_buffer(Some(buffer_size)).await;

    let user_name = encode_to_32_bytes(CLIENT_NAME);
    let data_len = token.len() + Symmetric::ciphertext_overhead();
    let tail_len = rand.gen_range(0..=*PORT_TAIL_LENGTH);
    let header: ClientInitHeader = (ProtocolFlag::INIT as u8, user_name, data_len as u16, tail_len as u16);
    encode_into_slice(&header, &mut buffer.slice_mut(), ENCODE_CONF)?;
    let (key, encrypted_header) = cipher.encrypt(buffer)?;

    let mut symmetric = Symmetric::new(&key)?;
    let header_length = encrypted_header.len();
    let body_buffer = encrypted_header.expand_end(NONCE_LEN).append_buf(token).rebuffer_start(header_length + NONCE_LEN);
    let encrypted_body = symmetric.encrypt(body_buffer, None)?;
    let encrypted_header_with_body = encrypted_body.expand_start(header_length);

    let encrypted_length = encrypted_header_with_body.len();
    let packet = encrypted_header_with_body.expand_end(tail_len);
    rand.fill_bytes(&mut packet.slice_start_mut(encrypted_length));
    Ok((symmetric, packet))
}

pub async fn build_any_data<'a>(cipher: &mut Symmetric, data: ByteBuffer<'a>) -> DynResult<ByteBuffer<'a>> {
    let data_len = data.len();
    let mut rand = get_rng();
    let encrypted_data = cipher.encrypt(data, None)?;

    let encrypted_data_len = data_len + Symmetric::ciphertext_overhead();
    let tail_len = rand.gen_range(0..=*PORT_TAIL_LENGTH);
    let header: AnyOtherHeader = (ProtocolFlag::DATA as u8, encrypted_data_len as u16, tail_len as u16);

    let header_size = get_type_size::<AnyOtherHeader>()?;
    let header_buffer = encrypted_data.expand_start(header_size + MAC_LEN).rebuffer_end(header_size);
    encode_into_slice(&header, &mut header_buffer.slice_mut(), ENCODE_CONF)?;
    log::error!("Packet header slice created: {:?}", header_buffer.slice());
    let encrypted_header = cipher.encrypt(header_buffer, None)?;
    log::error!("Packet header slice encrypted: {:?} bytes", encrypted_header.len());
    let encrypted_header_with_body = encrypted_header.expand_end(encrypted_data_len);
    log::error!("Packet data slice ready: {:?} bytes", encrypted_header_with_body.len());

    let packet = encrypted_header_with_body.expand_end(tail_len);
    rand.fill_bytes(&mut packet.slice_start_mut(packet.len() - tail_len));
    Ok(packet)
}

pub async fn build_any_term<'a>(cipher: &mut Symmetric) -> DynResult<ByteBuffer<'a>> {
    let mut rand = get_rng();
    let buffer_size = get_type_size::<AnyOtherHeader>()?;
    let buffer = get_buffer(Some(buffer_size)).await;

    let tail_len = rand.gen_range(0..=*PORT_TAIL_LENGTH);
    let header: AnyOtherHeader = (ProtocolFlag::TERM as u8, 0 as u16, tail_len as u16);

    encode_into_slice(&header, &mut buffer.slice_mut(), ENCODE_CONF)?;
    let encrypted_header = cipher.encrypt(buffer, None)?;

    let packet = encrypted_header.expand_end(tail_len);
    rand.fill_bytes(&mut packet.slice_start_mut(packet.len() - tail_len));
    Ok(packet)
}

pub async fn parse_server_init<'a>(cipher: &mut Symmetric, packet: ByteBuffer<'a>) -> DynResult<(u16, u16)> {
    let header = cipher.decrypt(packet, None)?;
    let ((flags, init_status, user_id, tail_length), _): (ServerInitHeader, usize) = decode_from_slice(&header.slice(), ENCODE_CONF)?;
    if flags != ProtocolFlag::INIT as u8 {
        bail!("Server INIT message flags malformed: {flags} != {}", ProtocolFlag::INIT as u8)
    } else if init_status != ProtocolReturnCode::Success as u8 {
        bail!("Initialization failed with status {init_status}");
    } else {
        Ok((user_id, tail_length))
    }
}

pub async fn parse_any_message_header<'a>(cipher: &mut Symmetric, packet: ByteBuffer<'a>) -> DynResult<(ProtocolMessageType, Option<(u16, u16)>)> {
    let header = cipher.decrypt(packet, None)?;
    let ((flags, data_length, tail_length), _): (AnyOtherHeader, usize) = decode_from_slice(&header.slice(), ENCODE_CONF)?;
    if flags == ProtocolFlag::DATA as u8 {
        Ok((ProtocolMessageType::Data, Some((data_length, tail_length))))
    } else if flags == ProtocolFlag::TERM as u8 {
        Ok((ProtocolMessageType::Termination, None))
    } else {
        bail!("Message flags malformed: {flags}!")
    }
}

pub async fn parse_any_any_data<'a>(cipher: &mut Symmetric, packet: ByteBuffer<'a>) -> DynResult<ByteBuffer<'a>> {
    Ok(cipher.decrypt(packet, None)?)
}
