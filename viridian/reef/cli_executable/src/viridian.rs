use std::collections::HashSet;
use std::net::{AddrParseError, Ipv4Addr};
use std::process::ExitStatus;

use futures::stream::{FuturesUnordered, StreamExt};
use ipnet::{self, Ipv4Net, PrefixLenError};
use log::{debug, info};
use regex::Regex;
use simple_error::{bail, require_with, SimpleError};
use tokio::process::Command;
use tokio::{select, try_join};

use reeflib::bytes::ByteBuffer;
use reeflib::general::create_handle;
use reeflib::generated::SeasideWhirlpoolClientCertificate;
use reeflib::protocol::ProtocolType;
use reeflib::utils::{parse_address, parse_env, parse_str_env};
use reeflib::viridian::{create_signal_handlers, DEFAULT_DNS_ADDRESS, DEFAULT_SVR_INDEX, DEFAULT_TUNNEL_ADDRESS, DEFAULT_TUNNEL_NAME, DEFAULT_TUNNEL_NETMASK};
use reeflib::DynResult;

use crate::tunnel::Tunnel;

pub const DEFAULT_SHELL: &str = "sh";
pub const DEFAULT_ARG: &str = "-c";

pub struct Viridian<'a> {
    key: ByteBuffer<'a>,
    token: ByteBuffer<'a>,
    address: Ipv4Addr,
    port: u16,
    tunnel: Tunnel,
    client_type: ProtocolType,
    local_address: Ipv4Addr,
}

impl<'a> Viridian<'a> {
    pub async fn new(certificate: SeasideWhirlpoolClientCertificate, protocol: ProtocolType, capture_iface: Option<Vec<String>>, capture_ranges: Option<Vec<String>>, exempt_ranges: Option<Vec<String>>, capture_addresses: Option<Vec<String>>, exempt_addresses: Option<Vec<String>>, capture_ports: Option<String>, exempt_ports: Option<String>, local_address: Option<Ipv4Addr>) -> DynResult<Self> {
        let tunnel_name = parse_str_env("SEASIDE_TUNNEL_NAME", Some(DEFAULT_TUNNEL_NAME));
        let tunnel_address = parse_env("SEASIDE_TUNNEL_ADDRESS", Some(DEFAULT_TUNNEL_ADDRESS));
        let tunnel_netmask = parse_env("SEASIDE_TUNNEL_NETMASK", Some(DEFAULT_TUNNEL_NETMASK));
        let svr_index = parse_env("SEASIDE_SVR_INDEX", Some(DEFAULT_SVR_INDEX));

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

        let capture_iface_set = if let Some(ifaces) = capture_iface { HashSet::from_iter(ifaces) } else { HashSet::new() };

        let mut capture_ranges_pre = if let Some(ranges) = capture_ranges {
            let networks: Result<Vec<Ipv4Net>, ipnet::AddrParseError> = ranges.iter().map(|a| a.parse()).collect();
            HashSet::from_iter(networks?)
        } else {
            HashSet::new()
        };

        if let Some(addresses) = capture_addresses {
            let addr_networks: Result<Vec<Ipv4Addr>, AddrParseError> = addresses.iter().map(|a| a.parse()).collect();
            let networks: Result<Vec<Ipv4Net>, PrefixLenError> = addr_networks?.iter().map(|a| Ipv4Net::new(a.clone(), 32)).collect();
            capture_ranges_pre.extend(networks?);
        }

        let mut exempt_ranges_pre = if let Some(ranges) = exempt_ranges {
            let networks: Result<Vec<Ipv4Net>, ipnet::AddrParseError> = ranges.iter().map(|a| a.parse::<Ipv4Net>()).collect();
            HashSet::from_iter(networks?)
        } else {
            HashSet::new()
        };

        if let Some(addresses) = exempt_addresses {
            let addr_networks: Result<Vec<Ipv4Addr>, AddrParseError> = addresses.iter().map(|a| a.parse()).collect();
            let networks: Result<Vec<Ipv4Net>, PrefixLenError> = addr_networks?.iter().map(|a| Ipv4Net::new(a.clone(), 32)).collect();
            exempt_ranges_pre.extend(networks?);
        }

        let capture_ranges_set = capture_ranges_pre.difference(&exempt_ranges_pre).cloned().collect();
        let exempt_ranges_set = exempt_ranges_pre.difference(&capture_ranges_pre).cloned().collect();

        let port_match = Regex::new(r"^(?P<lowest>\d+)-(?P<highest>\d+)$")?;

        let capture_port_range = if let None = capture_ports {
            None
        } else if let Some(capture) = port_match.captures(&capture_ports.clone().unwrap()) {
            Some((capture.name("lowest").unwrap().as_str().parse().unwrap(), capture.name("highest").unwrap().as_str().parse().unwrap()))
        } else {
            let port_number: u16 = capture_ports.unwrap().parse()?;
            Some((port_number, port_number))
        };

        let exempt_port_range = if let None = exempt_ports {
            None
        } else if let Some(capture) = port_match.captures(&exempt_ports.clone().unwrap()) {
            Some((capture.name("lowest").unwrap().as_str().parse().unwrap(), capture.name("highest").unwrap().as_str().parse().unwrap()))
        } else {
            let port_number: u16 = exempt_ports.unwrap().parse()?;
            Some((port_number, port_number))
        };

        let address = parse_address(&certificate.address)?;
        debug!("Creating tunnel with seaside address {address}, tunnel name {tunnel_name}, tunnel network {tunnel_address}/{tunnel_netmask}, SVR index {svr_index}...");
        let tunnel = Tunnel::new(address, &tunnel_name, tunnel_network, svr_index, dns, capture_iface_set, capture_ranges_set, exempt_ranges_set, capture_port_range, exempt_port_range, local_address).await?;

        let default_ip = tunnel.default_ip();
        Ok(Viridian { key: ByteBuffer::from(certificate.typhoon_public), token: ByteBuffer::from(certificate.token), address, port, tunnel, client_type: protocol, local_address: default_ip })
    }

    async fn run_vpn_command(&self, command: Option<String>) -> DynResult<ExitStatus> {
        let cmd = require_with!(command, "Command should not be None!");
        Ok(Command::new(DEFAULT_SHELL).arg(DEFAULT_ARG).arg(cmd).kill_on_drop(true).status().await?)
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
        let (mut send_handle, mut receive_handle, termination) = create_handle(&self.client_type, self.tunnel.clone(), self.tunnel.clone(), self.key.clone(), self.token.clone(), self.address, self.port, self.local_address).await?;

        debug!("Running VPN processes asynchronously...");
        let result = select! {
            res = self.run_vpn_command(command), if command.is_some() => match res {
                Ok(status) => {
                    if status.success() {
                        println!("The command exited successfully!");
                        Ok(())
                    } else {
                        Err(SimpleError::new(format!("The command exited with error code: {status}")))
                    }
                },
                Err(err) => Err(SimpleError::new(format!("VPN command execution error: {err}")))
            },
            serr = &mut send_handle => Err(SimpleError::new(format!("Error in sending coroutine: {:#?}", serr.expect("Join error").expect_err("Infinite loop success")))),
            rerr = &mut receive_handle => Err(SimpleError::new(format!("Error in receiving coroutine: {:#?}", rerr.expect("Join error").expect_err("Infinite loop success")))),
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
