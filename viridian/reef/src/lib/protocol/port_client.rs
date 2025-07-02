use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use log::{debug, warn};
use simple_error::{bail, require_with};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;

use crate::bytes::{get_buffer, ByteBuffer};
use crate::crypto::{Asymmetric, Symmetric};
use crate::protocol::common::ProtocolMessageType;
use crate::protocol::port_core::build_client_init;
use crate::protocol::port_core::*;
use crate::protocol::utils::get_type_size;
use crate::{run_coroutine_sync, DynResult, Reader, Writer};

macro_rules! discard_exact {
    ($socket:expr, $tail:expr, $wait:expr) => {{
        let buffer = get_buffer(Some($tail)).await;
        match $wait {
            Some(res) => timeout(res, $socket.read_exact(&mut buffer.slice_mut())).await?,
            None => $socket.read_exact(&mut buffer.slice_mut()).await,
        }
    }};
}

pub struct PortHandle<'a> {
    peer_address: SocketAddr,
    asymmetric: Asymmetric,
    local: SocketAddr,
    token: ByteBuffer<'a>,
}

impl<'a> PortHandle<'a> {
    pub async fn read_server_init(&self, cipher: &mut Symmetric, socket: &mut TcpStream) -> DynResult<u16> {
        let wait = Duration::from_millis(*PORT_TIMEOUT as u64);
        let buffer = get_buffer(None).await;

        debug!("Reading server initialization message...");
        let header_end = get_type_size::<ServerInitHeader>()? + Symmetric::ciphertext_overhead();
        let header_buff = buffer.rebuffer_end(header_end);
        timeout(wait, socket.read_exact(&mut header_buff.slice_mut())).await??;
        let (user_id, tail_length) = parse_server_init(cipher, header_buff).await?;

        debug!("Server initialization message received: user ID {user_id}, tail length {tail_length}");
        discard_exact!(socket, tail_length as usize, Some(wait))?;
        Ok(user_id)
    }

    #[allow(refining_impl_trait)]
    pub fn new(key: ByteBuffer<'_>, token: ByteBuffer<'a>, address: Ipv4Addr, port: u16, local: Ipv4Addr) -> DynResult<Self> {
        debug!("Creating PORT protocol handle...");
        let peer_address = SocketAddr::new(IpAddr::V4(address), port);
        let local_address = SocketAddr::new(IpAddr::V4(local), 0);
        debug!("Handle set up to connect {local_address} (local) to {peer_address} (caerulean)!");
        Ok(Self { peer_address, asymmetric: Asymmetric::new(&key)?, local: local_address, token })
    }

    pub async fn connect(&mut self) -> DynResult<(PortClientReader, PortClientWriter)> {
        let connection_socket = TcpSocket::from_std_stream(create_and_configure_socket()?);

        debug!("Binding connection client to {}...", self.local);
        connection_socket.bind(self.local)?;

        debug!("Connecting to listener at {}", self.peer_address);
        let mut connection_stream = connection_socket.connect(self.peer_address).await?;
        debug!("Current user address: {}", connection_stream.local_addr()?);

        let (mut symmetric, packet) = build_client_init(&self.asymmetric, &self.token).await?;
        connection_stream.write_all(&packet.slice()).await?;
        debug!("Initialization packet sent: {} bytes", packet.len());

        let user_id = self.read_server_init(&mut symmetric, &mut connection_stream).await?;
        debug!("Connection successful, user ID: {user_id}!");

        let main_socket = TcpSocket::from_std_stream(create_and_configure_socket()?);
        debug!("Binding main client to {}...", self.local);
        main_socket.bind(self.local)?;

        let mut main_address = self.peer_address.clone();
        main_address.set_port(user_id);
        debug!("Connecting to listener at {main_address}");
        let main_stream = main_socket.connect(main_address).await?;

        let (main_read, main_write) = main_stream.into_split();
        let reader_part = PortClientReader { socket: main_read, symmetric: symmetric.clone() };
        let writer_part = PortClientWriter { socket: main_write, symmetric: symmetric.clone() };
        Ok((reader_part, writer_part))
    }
}

pub struct PortClientReader {
    socket: OwnedReadHalf,
    symmetric: Symmetric,
}

pub struct PortClientWriter {
    socket: OwnedWriteHalf,
    symmetric: Symmetric,
}

impl Reader for PortClientReader {
    async fn read_bytes(&mut self) -> DynResult<ByteBuffer> {
        let buffer = get_buffer(None).await;

        let header_end = get_type_size::<AnyOtherHeader>()? + Symmetric::ciphertext_overhead();
        let packet = buffer.rebuffer_end(header_end);
        self.socket.read_exact(&mut packet.slice_mut()).await?;

        let (msg_type, payload) = parse_any_message_header(&mut self.symmetric, packet).await?;
        if msg_type == ProtocolMessageType::Termination {
            bail!("Termination message received!");
        } else if msg_type != ProtocolMessageType::Data {
            bail!("Unexpected message received: {msg_type}!");
        }
        let (data_length, tail_length) = require_with!(payload, "Unexpected error while decrypting, server message!");

        let data_end = header_end + data_length as usize;
        let data_buff = buffer.rebuffer_both(header_end, data_end);
        self.socket.read_exact(&mut data_buff.slice_mut()).await?;
        discard_exact!(&mut self.socket, tail_length as usize, None)?;

        let data = parse_any_any_data(&mut self.symmetric, data_buff).await?;
        debug!("Reading {} bytes from caerulean...", data.len());
        Ok(data)
    }
}

impl Writer for PortClientWriter {
    async fn write_bytes(&mut self, bytes: ByteBuffer<'_>) -> DynResult<usize> {
        let data = build_any_data(&mut self.symmetric, bytes).await?;
        debug!("Writing {} bytes to caerulean...", data.len());
        self.socket.write_all(&data.slice()).await?;
        Ok(data.len())
    }
}

impl Drop for PortClientWriter {
    #[allow(unused_must_use)]
    fn drop(&mut self) {
        run_coroutine_sync!(async {
            debug!("Preparing termination packet to caerulean...");
            let packet = build_any_term(&mut self.symmetric).await.expect("Couldn't build termination packet!");
            debug!("Termination packet of size {} sending...", packet.len());
            self.socket.write_all(&packet.slice()).await.inspect_err(|e| warn!("Couldn't send termination packet: {e}"));
        });
    }
}
