use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use log::{debug, warn};
use simple_error::{bail, require_with};
use socket2::{Socket, SockAddr};

use crate::crypto::{Asymmetric, Symmetric};
use crate::protocol::port_core::build_client_init;
use crate::bytes::{get_buffer, ByteBuffer};
use crate::protocol::utils::{discard_exact, recv_exact, send_exact};
use crate::{DynResult, ReaderWriter};
use super::common::ProtocolMessageType;
use super::port_core::*;
use super::utils::get_type_size;
use super::ProtocolClientHandle;


pub struct PortHandle<'a> {
    peer_address: SocketAddr,
    asymmetric: Asymmetric,
    local: SocketAddr,
    token: ByteBuffer<'a>
}

impl<'a> PortHandle<'a> {
    pub fn read_server_init(&self, cipher: &mut Symmetric, socket: &mut Socket) -> DynResult<u16> {
        let wait = Duration::from_millis(*PORT_TIMEOUT as u64);
        let buffer = get_buffer(None);
        socket.set_read_timeout(Some(wait))?;

        debug!("Reading server initialization message...");
        let header_end = get_type_size::<ServerInitHeader>()? + Symmetric::ciphertext_overhead();
        let header_buff = buffer.rebuffer_end(header_end);
        socket.read_exact(&mut header_buff.slice_mut())?;
        let (user_id, tail_length) = parse_server_init(cipher, header_buff)?;

        debug!("Server initialization message received: user ID {user_id}, tail length {tail_length}");
        discard_exact(socket, tail_length as usize)?;
        Ok(user_id)
    }
}

impl<'a> ProtocolClientHandle<'a> for PortHandle<'a> {
    #[allow(refining_impl_trait)]
    fn new(key: ByteBuffer<'_>, token: ByteBuffer<'a>, address: Ipv4Addr, port: u16, local: Option<Ipv4Addr>) -> DynResult<Self> {
        debug!("Creating PORT protocol handle...");
        let peer_address = SocketAddr::new(IpAddr::V4(address), port);
        let local_address = match local {
            Some(ip) => SocketAddr::new(IpAddr::V4(ip), 0),
            None => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        };
        debug!("Handle set up to connect {local_address} (local) to {peer_address} (caerulean)!");
        Ok(PortHandle {
            peer_address,
            asymmetric: Asymmetric::new(&key)?,
            local: local_address,
            token
        })
    }

    async fn connect(&mut self) -> DynResult<impl ReaderWriter> {
        let mut connection_socket = create_and_configure_socket()?;

        let local_address = SockAddr::from(self.local);
        debug!("Binding connection client to {:?}...", self.local);
        connection_socket.bind(&local_address)?;

        let peer_address = SockAddr::from(self.peer_address);
        debug!("Connecting to listener at {:?}", self.peer_address);
        connection_socket.connect(&peer_address)?;

        let current_address = require_with!(connection_socket.local_addr()?.as_socket_ipv4(), "Not an IPv4 address!");
        debug!("Current user address: {current_address}");

        let (mut symmetric, packet) = build_client_init(&self.asymmetric, &self.token)?;
        connection_socket.write_all(&packet.slice())?;
        debug!("Initialization packet sent: {} bytes", packet.len());

        let user_id = self.read_server_init(&mut symmetric, &mut connection_socket)?;
        debug!("Connection successful, user ID: {user_id}!");

        let main_socket = create_and_configure_socket()?;
        debug!("Binding main client to {}...", self.local);
        main_socket.bind(&local_address)?;

        let mut main_socket_address = self.peer_address.clone();
        main_socket_address.set_port(user_id);
        let main_address = SockAddr::from(main_socket_address);
        debug!("Connecting to listener at {main_socket_address}");
        main_socket.connect(&main_address)?;

        Ok(PortClient {
            socket: Arc::new(main_socket),
            symmetric
        })
    }
}


pub struct PortClient {
    socket: Arc<Socket>,
    symmetric: Symmetric
}

impl Clone for PortClient {
    fn clone(&self) -> Self {
        Self { socket: self.socket.clone(), symmetric: self.symmetric.clone() }
    }
}

impl ReaderWriter for PortClient {
    async fn read_bytes(&mut self) -> DynResult<ByteBuffer> {
        let buffer = get_buffer(None);

        let header_end = get_type_size::<AnyOtherHeader>()? + Symmetric::ciphertext_overhead();
        let packet = buffer.rebuffer_end(header_end);
        recv_exact(&self.socket, &mut packet.slice_mut())?;

        let (msg_type, payload) = parse_any_message_header(&mut self.symmetric, packet)?;
        if msg_type == ProtocolMessageType::Termination {
            bail!("Termination message received!");
        } else if msg_type != ProtocolMessageType::Data {
            bail!("Unexpected message received: {msg_type}!");
        }
        let (data_length, tail_length) = require_with!(payload, "Unexpected error while decrypting, server message!");

        let data_end = header_end + data_length as usize;
        let data_buff = buffer.rebuffer_both(header_end, data_end);
        recv_exact(&self.socket, &mut data_buff.slice_mut())?;
        discard_exact(&self.socket, tail_length as usize)?;

        let data = parse_any_any_data(&mut self.symmetric, data_buff)?;
        debug!("Reading {} bytes from caerulean...", data.len());
        Ok(data)
    }

    async fn write_bytes(&mut self, bytes: ByteBuffer<'_>) -> DynResult<usize> {
        let data = build_any_data(&mut self.symmetric, bytes)?;
        debug!("Writing {} bytes to caerulean...", data.len());
        send_exact(&self.socket, &data.slice())?;
        Ok(data.len())
    }
}

impl Drop for PortClient {
    #[allow(unused_must_use)]
    fn drop(&mut self) {
        let packet = build_any_term(&mut self.symmetric).expect("Couldn't build termination packet!");
        send_exact(&self.socket, &packet.slice()).inspect_err(|e| warn!("Couldn't send termination packet: {e}"));
    }
}
