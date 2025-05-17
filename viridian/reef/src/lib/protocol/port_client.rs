use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_dropper::AsyncDrop;
use log::{debug, warn};
use simple_error::{bail, require_with};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::RwLock;
use tokio::time::timeout;
use tonic::async_trait;

use crate::crypto::{Asymmetric, Symmetric};
use crate::protocol::port_core::build_client_init;
use crate::utils::get_packet;
use crate::DynResult;
use super::common::ProtocolMessageType;
use super::port_core::*;
use super::utils::get_type_size;
use super::{ProtocolClient, ProtocolClientHandle};


pub struct PortHandle {
    peer_address: SocketAddr,
    asymmetric: Asymmetric,
    local: SocketAddr,
    token: Vec<u8>
}

impl PortHandle {
    pub async fn new(key: &Vec<u8>, token: &Vec<u8>, address: Ipv4Addr, port: u16, local: Option<Ipv4Addr>) -> DynResult<PortHandle> {
        debug!("Creating PORT protocol handle...");
        let peer_address = format!("{address}:{port}").parse()?;
        let local_address = match local {
            Some(ip) => format!("{ip}:0"),
            None => "0.0.0.0:0".to_string(),
        }.parse()?;
        debug!("Handle set up to connect {local_address} (local) to {peer_address} (caerulean)!");
        let asymmetric_key = match key.clone().try_into() {
            Ok(res) => res,
            Err(_) => bail!("Error converting key to Asymmetric key!"),
        };
        Ok(PortHandle {
            peer_address,
            asymmetric: Asymmetric::new(&asymmetric_key)?,
            local: local_address,
            token: token.clone()
        })
    }

    pub async fn read_server_init(&self, cipher: &Symmetric, stream: &mut TcpStream) -> DynResult<u16> {
        let wait = Duration::from_millis(*PORT_TIMEOUT as u64);
        let mut buffer = get_packet();

        debug!("Reading server initialization message...");
        let header_end = get_type_size::<ServerInitHeader>()?;
        let header_buff = &mut buffer[..header_end];
        let _ = timeout(wait, stream.read_exact(header_buff)).await?;
        let (user_id, tail_length) = parse_server_init(cipher, header_buff)?;

        debug!("Server initialization message received: user ID {user_id}, tail length {tail_length}");
        let tail_end = header_end + tail_length as usize;
        let tail_buff = &mut buffer[header_end..tail_end];
        let _ = timeout(wait, stream.read_exact(tail_buff)).await?;

        Ok(user_id)
    }
}

#[async_trait]
impl ProtocolClientHandle for PortHandle {
    async fn connect(&mut self) -> DynResult<Arc<dyn ProtocolClient>> {
        let connection_socket = configure_socket(TcpSocket::new_v4()?)?;
        debug!("Binding connection client to {}...", self.local);
        connection_socket.bind(self.local)?;

        debug!("Connecting to listener at {}", self.peer_address);
        let mut connection_stream = connection_socket.connect(self.peer_address).await?;
        debug!("Current user address: {}", connection_stream.local_addr()?);

        let (key, packet) = build_client_init(&self.asymmetric, &self.token)?;
        connection_stream.write_all(&packet).await?;
        debug!("Initialization packet sent: {} bytes", packet.len());

        let symmetric_key = match key.try_into() {
            Ok(res) => res,
            Err(_) => bail!("Error converting key to Symmetric key!"),
        };
        let symmetric = Symmetric::new(&symmetric_key);

        let user_id = self.read_server_init(&symmetric, &mut connection_stream).await?;
        debug!("Connection successful, user ID: {user_id}!");

        let main_socket = configure_socket(TcpSocket::new_v4()?)?;
        debug!("Binding main client to {}...", self.local);
        main_socket.bind(self.local)?;

        let mut main_address = self.peer_address.clone();
        main_address.set_port(user_id);
        debug!("Connecting to listener at {}", main_address);
        let main_stream = main_socket.connect(main_address).await?;

        Ok(Arc::new(RwLock::new(PortClient {
            stream: main_stream,
            symmetric
        })))
    }
}


pub struct PortClient {
    stream: TcpStream,
    symmetric: Symmetric
}

#[async_trait]
impl ProtocolClient for RwLock<PortClient> {
    async fn read_bytes(&self) -> DynResult<Vec<u8>> {
        let mut writer = self.write().await;
        let mut buffer = get_packet();

        let header_end = get_type_size::<AnyOtherHeader>()?;
        let header_buff = &mut buffer[..header_end];
        writer.stream.read_exact(header_buff).await?;

        let (msg_type, payload) = parse_any_message_header(&writer.symmetric, header_buff)?;
        if msg_type == ProtocolMessageType::Termination {
            bail!("Termination message received!");
        } else if msg_type != ProtocolMessageType::Data {
            bail!("Unexpected message received: {msg_type}!");
        }
        let (data_length, tail_length) = require_with!(payload, "Unexpected error while decrypting, server message!");

        let data_end = header_end + data_length as usize;
        let data_buff = &mut buffer[header_end..data_end];
        writer.stream.read_exact(data_buff).await?;
        let data = parse_any_any_data(&writer.symmetric, &data_buff)?;
        debug!("Reading {} bytes from caerulean...", data.len());

        let tail_end = data_end + tail_length as usize;
        let tail_buff = &mut buffer[data_end..tail_end];
        writer.stream.read_exact(tail_buff).await?;

        Ok(data)
    }

    async fn write_bytes(&self, bytes: &Vec<u8>) -> DynResult<usize> {
        let mut writer = self.write().await;
        let data = build_any_data(&writer.symmetric, bytes)?;
        debug!("Writing {} bytes to caerulean...", data.len());
        writer.stream.write_all(&data).await?;
        Ok(data.len())
    }
}

#[async_trait]
impl AsyncDrop for PortClient {
    #[allow(unused_must_use)]
    async fn async_drop(&mut self) {
        let packet = build_any_term(&self.symmetric).expect("Couldn't build termination packet!");
        self.stream.write_all(&packet).await.inspect_err(|e| warn!("Couldn't send termination packet: {e}"));
    }
}
