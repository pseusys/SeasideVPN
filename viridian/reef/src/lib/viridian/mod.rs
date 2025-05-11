use std::net::Ipv4Addr;
use std::process::ExitStatus;
use std::sync::Arc;

use base64::engine::general_purpose;
use base64::Engine;
use futures::stream::{FuturesUnordered, StreamExt};
use ipnet::Ipv4Net;
use log::{debug, error, info};
use simple_error::{bail, require_with, SimpleError};
use tokio::net::lookup_host;
use tokio::process::Command;
use tokio::{select, spawn};

use crate::utils::get_packet;
use crate::DynResult;
use super::tunnel::{Creatable, Tunnel};
use super::protocol::{ProtocolClient, ProtocolType};
use super::utils::{parse_env, parse_str_env};


#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::*;


const DEFAULT_TUNNEL_NAME: &str = "seatun";
const DEFAULT_TUNNEL_ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 82);
const DEFAULT_TUNNEL_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
const DEFAULT_SVR_INDEX: u8 = 82;


pub struct Viridian {
    key: Vec<u8>,
    token: Vec<u8>,
    address: Ipv4Addr,
    port: u16,
    tunnel: Arc<Tunnel>,
    client_type: ProtocolType
}


impl Viridian {
    pub async fn new(address: Ipv4Addr, port: u16, token: &str, key: &str, protocol: ProtocolType) -> DynResult<Viridian> {
        let parsed_token = match general_purpose::STANDARD.decode(token) {
            Ok(res) => res,
            Err(err) => bail!("Failed to decode base64: {}", err)
        };
        let parsed_key = match general_purpose::STANDARD.decode(key) {
            Ok(res) => res,
            Err(err) => bail!("Failed to decode base64: {}", err)
        };

        let tunnel_name = parse_str_env("SEASIDE_TUNNEL_NAME", Some(DEFAULT_TUNNEL_NAME));
        let tunnel_address = parse_env("SEASIDE_TUNNEL_ADDRESS", Some(DEFAULT_TUNNEL_ADDRESS));
        let tunnel_netmask = parse_env("SEASIDE_TUNNEL_NETMASK", Some(DEFAULT_TUNNEL_NETMASK));
        let svr_index = parse_env("SEASIDE_SVR_INDEX", Some(DEFAULT_SVR_INDEX));

        let tunnel_network = Ipv4Net::with_netmask(tunnel_address, tunnel_netmask)?;
        if tunnel_address == tunnel_network.network() || tunnel_address == tunnel_network.broadcast() {
            bail!("Tunnel address {tunnel_address} is reserved in tunnel network {tunnel_network}!");
        }

        debug!("Creating tunnel with seaside address {address}, tunnel name {tunnel_name}, tunnel network {tunnel_address}/{tunnel_netmask}, SVR index {svr_index}...");
        let tunnel = Tunnel::new(address, &tunnel_name, tunnel_network, svr_index).await?;

        Ok(Viridian {
            key: parsed_key,
            token: parsed_token,
            address,
            port,
            tunnel: Arc::new(tunnel),
            client_type: protocol
        })
    }

    async fn run_vpn_command(&self, command: Option<String>) -> DynResult<ExitStatus> {
        let cmd = require_with!(command, "Command should not be None!");
        info!("Executing command '{cmd}'...");
        let args = cmd.split_whitespace().collect::<Vec<_>>();
        let status = Command::new(args[0]).args(&args[1..]).spawn().expect("Command failed to spawn!").wait().await?;
        Ok(status)
    }

    async fn send_to_caerulean(tunnel: Arc<Tunnel>, client: Arc<dyn ProtocolClient>) -> Result<(), Box<SimpleError>> {
        info!("Setting up send-to-caerulean coroutine...");
        let mut buffer = get_packet();
        loop {
            let length = match tunnel.read_bytes(&mut buffer).await {
                Err(res) => bail!("Error reading from tunnel: {res}!"),
                Ok(res) => res
            };
            debug!("Captured {length} bytes from tunnel");
            match client.write_bytes(&buffer).await {
                Err(res) => bail!("Error writing to socket: {res}!"),
                Ok(res) => debug!("Sent {res} bytes to caerulean")
            };
        }
    }

    async fn receive_from_caerulean(tunnel: Arc<Tunnel>, client: Arc<dyn ProtocolClient>) -> Result<(), Box<SimpleError>> {
        info!("Setting up receive-freom-caerulean coroutine...");
        loop {
            let packet = match client.read_bytes().await {
                Err(res) => bail!("Error reading from socket: {res}!"),
                Ok(res) => res
            };
            debug!("Received {} bytes from caerulean", packet.len());
            match tunnel.write_bytes(&packet).await {
                Err(res) => bail!("Error writing to tunnel: {res}!"),
                Ok(res) => debug!("Injected {res} bytes into tunnel")
            };
        }
    }

    pub async fn start(&mut self, command: Option<String>) -> DynResult<()> {
        debug!("Creating signal handlers...");
        let signals = create_signal_handlers()?;
        let mut handlers = FuturesUnordered::new();
        for (mut signal, name) in signals {
            handlers.push(async move {
                signal.recv().await;
                info!("Received {name} signal!");
            });
        }

        let mut handle = self.client_type.create_client(&self.key, &self.token, self.address, self.port, None).await?;
        let client = handle.connect().await?;

        let send_handle = spawn(Self::send_to_caerulean(self.tunnel.clone(), client.clone()));
        let receive_handle = spawn(Self::receive_from_caerulean(self.tunnel.clone(), client.clone()));

        debug!("Running DNS probe to check for globally available DNS servers...");
        if lookup_host("example.com").await.is_err() {
            error!("WARNING! DNS probe failed! It is very likely that you have local DNS servers configured only!");
        }

        debug!("Running VPN processes asynchronously...");
        select! {
            res = self.run_vpn_command(command), if command.is_some() => match res {
                Ok(status) => if status.success() {
                    println!("The command exited successfully!")
                } else {
                    bail!("The command exited with error code: {status}")
                },
                Err(err) => bail!("VPN command execution error: {err}")
            },
            serr = send_handle => bail!("Error in sending coroutine: {:#?}", serr.expect("Join error").expect("Infinite loop success")),
            rerr = receive_handle => bail!("Error in receiving coroutine: {:#?}", rerr.expect("Join error").expect("Infinite loop success")),
            _ = handlers.next() => info!("Terminating gracefully...")
        };

        Ok(())
    }
}
