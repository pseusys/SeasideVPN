use std::net::Ipv4Addr;

use log::{debug, info};
use simple_error::{bail, SimpleError};
use tokio::select;
use tokio::sync::broadcast::{channel, Receiver, Sender};
use tokio::task::JoinHandle;

use crate::bytes::ByteBuffer;
use crate::protocol::{PortHandle, ProtocolClientHandle, ProtocolType, TyphoonHandle};
use crate::{run_coroutine_conditionally, DynResult, ReaderWriter};


async fn worker_task(mut reader: impl ReaderWriter, mut writer: impl ReaderWriter, mut terminator: Receiver<()>, message: &str) -> Result<(), Box<SimpleError>> {
    info!("Setting up worker task {}...", message);
    loop {
        let packet = select! {
            pk = reader.read_bytes() => match pk {
                Err(res) => bail!("Error reading from tunnel: {res}!"),
                Ok(res) => res
            },
            ld = terminator.recv() => match ld {
                Ok(_) => return Ok(()),
                Err(_) => bail!("Terminating worker task with error!")
            }
        };
        debug!("Captured {} bytes {}!", packet.len(), message);
        match writer.write_bytes(packet).await {
            Err(res) => bail!("Error writing to socket: {res}!"),
            Ok(res) => debug!("Sent {res} bytes to caerulean!")
        };
    }
}

fn connect<T: ReaderWriter, C: ReaderWriter>(tunnel: T, client: C) -> (JoinHandle<Result<(), Box<SimpleError>>>, JoinHandle<Result<(), Box<SimpleError>>>, Sender<()>) {
    let (termination_sender, _) = channel(1);
    let (send_handle_tunnel, receive_handle_tunnel) = (tunnel.clone(), tunnel.clone());
    let (send_handle_client, receive_handle_client) = (client.clone(), client.clone());
    let (send_term_receiver, receive_term_receiver) = (termination_sender.subscribe(), termination_sender.subscribe());
    let send_handle = run_coroutine_conditionally!(worker_task(send_handle_tunnel, send_handle_client, send_term_receiver, "viridian -> caerulean"));
    let receive_handle = run_coroutine_conditionally!(worker_task(receive_handle_client, receive_handle_tunnel, receive_term_receiver, "caerulean -> viridian"));
    (send_handle, receive_handle, termination_sender)
}

pub async fn create_handle<T: ReaderWriter>(client_type: &ProtocolType, tunnel: T, key: ByteBuffer<'_>, token: ByteBuffer<'_>, address: Ipv4Addr, port: u16, local: Option<Ipv4Addr>) -> DynResult<(JoinHandle<Result<(), Box<SimpleError>>>, JoinHandle<Result<(), Box<SimpleError>>>, Sender<()>)> {
    match client_type {
        ProtocolType::PORT => {
            let client = PortHandle::new(key.clone(), token.clone(), address, port, local)?.connect().await?;
            debug!("Spawning PORT reader and writer coroutines...");
            Ok(connect(tunnel.clone(), client))
        },
        ProtocolType::TYPHOON => {
            let client = TyphoonHandle::new(key.clone(), token.clone(), address, port, local)?.connect().await?;
            debug!("Spawning TYPHOON reader and writer coroutines...");
            Ok(connect(tunnel.clone(), client))
        }
    }
}
