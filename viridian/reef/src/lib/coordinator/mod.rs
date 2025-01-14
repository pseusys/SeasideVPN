use std::net::Ipv4Addr;
use std::process::ExitStatus;
use std::time::Duration;
use std::fs::read_to_string;
use std::cmp::min;

use futures::stream::{FuturesUnordered, StreamExt};
use ipnet::Ipv4Net;
use log::{debug, error, info, warn};
use rand::{Rng, RngCore};
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::generic_array::typenum::U32;
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::{XChaCha20Poly1305, KeyInit};
use simple_error::{bail, require_with};
use tokio::net::{lookup_host, UdpSocket};
use tokio::process::Command;
use tokio::select;
use tokio::time::sleep;
use tonic::metadata::MetadataValue;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use tonic::Request;

use generated::whirlpool_viridian_client::WhirlpoolViridianClient;
use generated::{WhirlpoolAuthenticationRequest, ControlHandshakeRequest, ControlHealthcheck};

use crate::DynResult;
use super::tunnel::{Creatable, Tunnel};
use super::viridian::Viridian;
use super::VERSION;

mod generated {
    tonic::include_proto!("generated");
}


#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
use linux::*;


#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
use windows::*;


const GRPC_PROTOCOL: &str = "https";
const MAX_TAIL_LENGTH: usize = 64;
const SEASIDE_TAIL_HEADER: &str = "seaside-tail-bin";


pub struct Coordinator {
    viridian: Viridian,
    client: WhirlpoolViridianClient<Channel>,

    node_payload: String,
    user_name: String,
    min_hc_time: u16,
    max_hc_time: u16
}


impl Coordinator {
    pub async fn new(address: Ipv4Addr, ctrl_port: u16, payload: &str, user_name: &str, min_hc_time: u16, max_hc_time: u16, max_timeout: f32, tunnel_name: &str, tunnel_address: Ipv4Addr, tunnel_netmask: Ipv4Addr, svr_index: u8, ca: Option<&str>) -> DynResult<Coordinator> {
        let viridian_host = format!("{GRPC_PROTOCOL}://{address}:{ctrl_port}");

        if min_hc_time < 1 {
            bail!("Minimum healthcheck time shouldn't be less than 1 second!");
        }
        if max_hc_time < 1 {
            bail!("Maximum healthcheck time shouldn't be less than 1 second!");
        }

        let tunnel_network = Ipv4Net::with_netmask(tunnel_address, tunnel_netmask)?;
        if tunnel_address == tunnel_network.network() || tunnel_address == tunnel_network.broadcast() {
            bail!("Tunnel address {tunnel_address} is reserved in tunnel network {tunnel_network}!");
        }

        debug!("Creating client TLS config with CA {ca:?}...");
        let tls = match ca {
            Some(certificate) => ClientTlsConfig::new().ca_certificate(Certificate::from_pem(read_to_string(certificate)?.as_bytes())),
            None => ClientTlsConfig::new().with_webpki_roots()
        };
        let caerulean_max_timeout = Duration::from_secs_f32(max_timeout);
        let channel = Channel::from_shared(viridian_host)?.timeout(caerulean_max_timeout).connect_timeout(caerulean_max_timeout).tls_config(tls)?.connect().await?;

        debug!("Creating client with channel {channel:?}...");
        let client = WhirlpoolViridianClient::new(channel);

        debug!("Creating tunnel with seaside address {address}, tunnel name {tunnel_name}, tunnel network {tunnel_address}/{tunnel_netmask}, SVR index {svr_index}...");
        let tunnel = Tunnel::new(address, tunnel_name, tunnel_network, svr_index).await?;

        let default_interface = (tunnel.default_interface().0, 0);
        debug!("Creating viridian with default interface {default_interface:?}...");
        let socket = UdpSocket::bind(default_interface).await?;
        let viridian = Viridian::new(socket, tunnel, address);

        Ok(Coordinator {
            viridian,
            client,
            node_payload: payload.to_string(),
            user_name: user_name.to_string(),
            min_hc_time,
            max_hc_time
        })
    }

    async fn initialize_connection(&mut self) -> DynResult<u16> {
        let (session_key, session_token) = self.receive_token().await?;
        info!("Connection established, key {session_key:?}, token {session_token:?}");
        let user_id = self.initialize_control(session_key, session_token).await?;
        info!("Control initialized, received user ID: {user_id}");
        Ok(user_id)
    }

    async fn run_vpn_command(command: Option<String>) -> DynResult<ExitStatus> {
        let cmd = require_with!(command, "Command should not be None!");
        info!("Executing command '{cmd}'...");
        let args = cmd.split_whitespace().collect::<Vec<_>>();
        let status = Command::new(args[0]).args(&args[1..]).spawn().expect("Command failed to spawn!").wait().await?;
        Ok(status)
    }

    async fn run_vpn_loop(&mut self, mut user_id: u16) -> DynResult<()> {
        info!("Starting infinite VPN loop...");
        debug!("Sending healthcheck message...");
        let mut control = self.perform_control(user_id).await;
        loop {
            if let Err(ctrl) = control {
                warn!("Healthcheck message exchange failed (status {ctrl}), reinitializating connection...");
                user_id = self.initialize_connection().await?;
            }
            debug!("Sending healthcheck message...");
            control = self.perform_control(user_id).await;
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

        debug!("Initiating connection...");
        let user_id = self.initialize_connection().await?;

        debug!("Running DNS probe to check for globally available DNS servers...");
        if lookup_host("example.com").await.is_err() {
            error!("WARNING! DNS probe failed! It is very likely that you have local DNS servers configured only!");
        }

        debug!("Running VPN processes asynchronously...");
        select! {
            res = Self::run_vpn_command(command), if command.is_some() => match res {
                Ok(status) => if status.success() {
                    println!("The command exited successfully!")
                } else {
                    bail!("The command exited with error code: {status}")
                },
                Err(err) => return Err(err)
            },
            err = self.run_vpn_loop(user_id) => {
                return Ok(err?)
            },
            _ = handlers.next() => info!("Terminating gracefully...")
        };

        Ok(())
    }

    fn make_grpc_request<T>(&mut self, message: T) -> Request<T> {
        let mut tail = Vec::with_capacity(OsRng.gen_range(1..MAX_TAIL_LENGTH));
        OsRng.fill_bytes(&mut tail);

        let mut request = Request::new(message);
        request.metadata_mut().append_bin(SEASIDE_TAIL_HEADER, MetadataValue::from_bytes(&tail));
        request
    }

    async fn receive_token(&mut self) -> Result<(GenericArray<u8, U32>, Vec<u8>), tonic::Status> {
        let session_key = XChaCha20Poly1305::generate_key(&mut OsRng);

        let message = WhirlpoolAuthenticationRequest {uid: self.user_name.clone(), session: session_key.to_vec(), payload: self.node_payload.clone()};
        let request = self.make_grpc_request(message);
        let response = self.client.authenticate(request).await;

        match response {
            Ok(res) => {
                self.min_hc_time = min(self.min_hc_time, res.get_ref().max_next_in as u16);
                self.max_hc_time = min(self.max_hc_time, res.get_ref().max_next_in as u16);
                Ok((session_key, res.get_ref().token.clone()))
            },
            Err(res) => Err(res)
        }
    }

    async fn initialize_control(&mut self, session_key: GenericArray<u8, U32>, session_token: Vec<u8>) -> Result<u16, tonic::Status> {
        let message = ControlHandshakeRequest {
            token: session_token.clone(),
            version: VERSION.to_string(),
            payload: Some(self.node_payload.clone()),
            address: self.viridian.tunnel.default_interface().0.octets().to_vec(),
            port: i32::from(self.viridian.socket.local_addr().ok().unwrap().port())
        };
        let request = self.make_grpc_request(message);
        let response = self.client.handshake(request).await;

        match response {
            Ok(res) => {
                let user_id = res.get_ref().user_id as u16;
                self.viridian.open(session_key, user_id).await;
                Ok(user_id)
            },
            Err(res) => Err(res)
        }
    }

    async fn perform_control(&mut self, user_id: u16) -> Result<(), tonic::Status> {
        let next_in = OsRng.gen_range(self.min_hc_time..=self.max_hc_time);

        let message = ControlHealthcheck {user_id: i32::from(user_id), next_in: i32::from(next_in)};
        let request = self.make_grpc_request(message);
        let response = self.client.healthcheck(request).await;

        match response {
            Ok(_) => {
                debug!("Healthcheck message sent, next in {next_in}");
                sleep(Duration::from_secs(u64::from(next_in))).await;
                Ok(())
            },
            Err(res) => {
                self.viridian.close();
                Err(res)
            }
        }
    }
}
