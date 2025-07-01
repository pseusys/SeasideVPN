use std::net::Ipv4Addr;

use log::{debug, info};
use simple_error::{bail, SimpleError};
use tokio::select;
use tokio::sync::broadcast::{channel, Receiver, Sender};
use tokio::task::JoinHandle;

use crate::bytes::ByteBuffer;
use crate::protocol::{PortHandle, ProtocolType, TyphoonHandle};
use crate::{run_coroutine_in_thread, DynResult, Reader, Writer};

async fn worker_task(mut reader: impl Reader, mut writer: impl Writer, mut terminator: Receiver<()>, message: &str) -> Result<(), Box<SimpleError>> {
    info!("Setting up worker task {}...", message);
    loop {
        debug!("Reading bytes {}...", message);
        let packet = select! {
            pk = reader.read_bytes() => match pk {
                Err(res) => bail!("Error reading from tunnel: {res}!"),
                Ok(res) => res
            },
            ld = terminator.recv() => match ld {
                Ok(_) => {
                    info!("Terminating worker task {}...", message);
                    return Ok(())
                },
                Err(_) => bail!("Terminating worker task with error!")
            }
        };
        debug!("Captured {} bytes {}!", packet.len(), message);
        match writer.write_bytes(packet).await {
            Err(res) => bail!("Error writing to socket: {res}!"),
            Ok(res) => debug!("Sent {res} bytes {}!", message),
        };
    }
}

fn connect<TR: Reader, TW: Writer, CR: Reader, CW: Writer>(tunnel_reader: TR, tunnel_writer: TW, client_reader: CR, client_writer: CW) -> (JoinHandle<Result<(), Box<SimpleError>>>, JoinHandle<Result<(), Box<SimpleError>>>, Sender<()>) {
    let (termination_sender, _) = channel(1);
    let (send_term_receiver, receive_term_receiver) = (termination_sender.subscribe(), termination_sender.subscribe());
    let send_handle = run_coroutine_in_thread!(worker_task(tunnel_reader, client_writer, send_term_receiver, "viridian -> caerulean"));
    let receive_handle = run_coroutine_in_thread!(worker_task(client_reader, tunnel_writer, receive_term_receiver, "caerulean -> viridian"));
    (send_handle, receive_handle, termination_sender)
}

pub async fn create_handle<TR: Reader, TW: Writer>(client_type: &ProtocolType, tunnel_reader: TR, tunnel_writer: TW, key: ByteBuffer<'_>, token: ByteBuffer<'_>, address: Ipv4Addr, port: u16, local: Ipv4Addr) -> DynResult<(JoinHandle<Result<(), Box<SimpleError>>>, JoinHandle<Result<(), Box<SimpleError>>>, Sender<()>)> {
    match client_type {
        ProtocolType::PORT => {
            let (client_reader, client_writer) = PortHandle::new(key.clone(), token.clone(), address, port, local)?.connect().await?;
            debug!("Spawning PORT reader and writer coroutines...");
            Ok(connect(tunnel_reader, tunnel_writer, client_reader, client_writer))
        }
        ProtocolType::TYPHOON => {
            let client = TyphoonHandle::new(key.clone(), token.clone(), address, port, local)?.connect().await?;
            debug!("Spawning TYPHOON reader and writer coroutines...");
            Ok(connect(tunnel_reader, tunnel_writer, client.clone(), client.clone()))
        }
    }
}
