use std::net::Ipv4Addr;

use futures::stream::{FuturesUnordered, StreamExt};
use ipnet::Ipv4Net;
use log::{debug, info};
use simple_error::{bail, SimpleError};
use tokio::sync::oneshot::Receiver;
use tokio::{select, try_join};

use reeflib::bytes::ByteBuffer;
use reeflib::general::create_handle;
use reeflib::generated::SeasideWhirlpoolClientCertificate;
use reeflib::protocol::ProtocolType;
use reeflib::utils::{parse_address, parse_env, parse_str_env};
use reeflib::viridian::{create_signal_handlers, DEFAULT_DNS_ADDRESS, DEFAULT_TUNNEL_ADDRESS, DEFAULT_TUNNEL_NAME, DEFAULT_TUNNEL_NETMASK};
use reeflib::DynResult;

use crate::tunnel::Tunnel;

pub struct Viridian<'a> {
    key: ByteBuffer<'a>,
    token: ByteBuffer<'a>,
    address: Ipv4Addr,
    port: u16,
    pub tunnel: Tunnel,
    client_type: ProtocolType,
    local_address: Ipv4Addr,
    pub dns: Option<Ipv4Addr>,
}

impl<'a> Viridian<'a> {
    pub async fn new(certificate: SeasideWhirlpoolClientCertificate, protocol: ProtocolType) -> DynResult<Viridian<'a>> {
        let tunnel_name = parse_str_env("SEASIDE_TUNNEL_NAME", Some(DEFAULT_TUNNEL_NAME));
        let tunnel_address = parse_env("SEASIDE_TUNNEL_ADDRESS", Some(DEFAULT_TUNNEL_ADDRESS));
        let tunnel_netmask = parse_env("SEASIDE_TUNNEL_NETMASK", Some(DEFAULT_TUNNEL_NETMASK));

        let tunnel_network = Ipv4Net::with_netmask(tunnel_address, tunnel_netmask)?;
        if tunnel_address == tunnel_network.network() || tunnel_address == tunnel_network.broadcast() {
            bail!("Tunnel address {tunnel_address} is reserved in tunnel network {tunnel_network}!");
        }

        let mut dns = Some(parse_address(&certificate.dns)?);
        if dns.is_some_and(|a| a == DEFAULT_DNS_ADDRESS) {
            dns = None;
        }

        let port = match protocol {
            ProtocolType::PORT => certificate.port_port as u16,
            ProtocolType::TYPHOON => certificate.typhoon_port as u16,
        };

        let address = parse_address(&certificate.address)?;
        debug!("Creating tunnel with seaside address {address}, tunnel name {tunnel_name}, tunnel network {tunnel_address}/{tunnel_netmask}...");
        let tunnel = Tunnel::new(address, &tunnel_name, tunnel_network).await?;

        let default_ip = tunnel.default_ip();
        Ok(Viridian { key: ByteBuffer::from(certificate.typhoon_public), token: ByteBuffer::from(certificate.token), address, port, tunnel, client_type: protocol, local_address: default_ip, dns })
    }

    pub async fn start(&mut self, receiver: &mut Receiver<()>) -> DynResult<()> {
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
        let (mut send_handle, mut receive_handle, termination) = create_handle(&self.client_type, self.tunnel.clone(), self.tunnel.clone(), self.key.clone(), self.token.clone(), self.address, self.port, self.local_address).await?;

        debug!("Running VPN processes asynchronously...");
        let result = select! {
            serr = &mut send_handle => Err(SimpleError::new(format!("Error in sending coroutine: {:#?}", serr.expect("Join error").expect_err("Infinite loop success")))),
            rerr = &mut receive_handle => Err(SimpleError::new(format!("Error in receiving coroutine: {:#?}", rerr.expect("Join error").expect_err("Infinite loop success")))),
            res = receiver => match res {
                Ok(_) => Ok(()),
                Err(err) => Err(SimpleError::new(format!("The loop exited with error: {err}"))),
            },
            _ = handlers.next() => {
                info!("Terminating gracefully...");
                Ok(())
            }
        };

        debug!("Waiting for background task termination...");
        let _ = termination.send(()).inspect_err(|_| debug!("Apparently all the background tasks have already terminated!"));
        match try_join!(send_handle, receive_handle) {
            Ok(_) => debug!("All the background tasks terminated successfully!"),
            Err(res) => debug!("A background task failed with an error: {res}"),
        }

        Ok(result?)
    }
}
