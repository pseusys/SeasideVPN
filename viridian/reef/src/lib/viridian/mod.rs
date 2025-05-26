use std::net::Ipv4Addr;
use std::process::ExitStatus;

use futures::stream::{FuturesUnordered, StreamExt};
use ipnet::Ipv4Net;
use log::{debug, error, info};
use simple_error::{bail, require_with, SimpleError};
use tokio::net::lookup_host;
use tokio::process::Command;
use tokio::select;

use crate::bytes::ByteBuffer;
use crate::general::create_handle;
use crate::DynResult;
use super::tunnel::Tunnel;
use super::protocol::ProtocolType;
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


pub struct Viridian<'a> {
    key: ByteBuffer<'a>,
    token: ByteBuffer<'a>,
    address: Ipv4Addr,
    port: u16,
    tunnel: Tunnel,
    client_type: ProtocolType
}

impl<'a> Viridian<'a> {
    pub async fn new(address: Ipv4Addr, port: u16, token: ByteBuffer<'a>, key: ByteBuffer<'a>, protocol: ProtocolType) -> DynResult<Viridian<'a>> {
        let tunnel_name = parse_str_env("SEASIDE_TUNNEL_NAME", Some(DEFAULT_TUNNEL_NAME));
        let tunnel_address = parse_env("SEASIDE_TUNNEL_ADDRESS", Some(DEFAULT_TUNNEL_ADDRESS));
        let tunnel_netmask = parse_env("SEASIDE_TUNNEL_NETMASK", Some(DEFAULT_TUNNEL_NETMASK));
        let svr_index = parse_env("SEASIDE_SVR_INDEX", Some(DEFAULT_SVR_INDEX));

        let tunnel_network = Ipv4Net::with_netmask(tunnel_address, tunnel_netmask)?;
        if tunnel_address == tunnel_network.network() || tunnel_address == tunnel_network.broadcast() {
            bail!("Tunnel address {tunnel_address} is reserved in tunnel network {tunnel_network}!");
        }

        debug!("Creating tunnel with seaside address {address}, tunnel name {tunnel_name}, tunnel network {tunnel_address}/{tunnel_netmask}, SVR index {svr_index}...");
        let tunnel = Tunnel::new(address, &tunnel_name, tunnel_network, svr_index)?;

        Ok(Viridian {
            key,
            token,
            address,
            port,
            tunnel: tunnel,
            client_type: protocol
        })
    }

    async fn run_vpn_command(&self, command: Option<String>) -> DynResult<ExitStatus> {
        let cmd = require_with!(command, "Command should not be None!");
        info!("Executing command '{cmd}'...");
        let args = cmd.split_whitespace().collect::<Vec<_>>();
        Ok(Command::new(args[0]).args(&args[1..]).kill_on_drop(true).status().await?)
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

        debug!("Creating protocol client handle...");
        let (send_handle, receive_handle, termination) = create_handle(&self.client_type, self.tunnel.clone(), self.key.clone(), self.token.clone(), self.address, self.port, None).await?;

        debug!("Running DNS probe to check for globally available DNS servers...");
        if lookup_host("example.com").await.is_err() {
            error!("WARNING! DNS probe failed! It is very likely that you have local DNS servers configured only!");
        }

        debug!("Running VPN processes asynchronously...");
        let result = select! {
            res = self.run_vpn_command(command), if command.is_some() => match res {
                Ok(status) => {
                    if status.success() {
                        println!("The command exited successfully!");
                        Ok(())
                    } else {
                        Err(SimpleError::new("The command exited with error code: {status}"))
                    }
                },
                Err(err) => Err(SimpleError::new(format!("VPN command execution error: {err}")))
            },
            serr = send_handle => Err(SimpleError::new(format!("Error in sending coroutine: {:#?}", serr.expect("Join error").expect_err("Infinite loop success")))),
            rerr = receive_handle => Err(SimpleError::new(format!("Error in receiving coroutine: {:#?}", rerr.expect("Join error").expect_err("Infinite loop success")))),
            _ = handlers.next() => {
                info!("Terminating gracefully...");
                Ok(())
            }
        };

        termination.send(())?;
        Ok(result?)
    }
}
