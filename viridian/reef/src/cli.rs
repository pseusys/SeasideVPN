use std::env::{set_var, var};
use std::net::{Ipv4Addr, IpAddr, ToSocketAddrs};
use std::str::FromStr;

use log::info;
use reeflib::protocol::ProtocolType;
use simple_error::bail;
use structopt::StructOpt;
use env_logger::init;

use reeflib::viridian::Viridian;
use reeflib::DynResult;


const DEFAULT_CAERULEAN_ADDRESS: &str = "127.0.0.1";
const DEFAULT_CAERULEAN_PORT: &str = "8587";
const DEFAULT_LOG_LEVEL: &str = "INFO";


fn parse_address(address: &str) -> DynResult<Ipv4Addr> {
    match (address, 0).to_socket_addrs()?.next() {
        Some(socket_addr) => match socket_addr.ip() {
            IpAddr::V4(ipv4) => Ok(ipv4),
            IpAddr::V6(ipv6) => bail!("IPv6 address {ipv6} is not supported!"),
        },
        None => bail!("Could not resolve address: {address}"),
    }
}


#[derive(StructOpt, Debug)]
#[structopt()]
struct Opt {
    /// Caerulean remote IP address (default: [`DEFAULT_CAERULEAN_ADDRESS`])
    #[structopt(short = "a", long, default_value = DEFAULT_CAERULEAN_ADDRESS, parse(try_from_str = parse_address))]
    address: Ipv4Addr,

    /// Caerulean port number (default: [`DEFAULT_CAERULEAN_PORT`])
    #[structopt(short = "c", long, default_value = DEFAULT_CAERULEAN_PORT)]
    port: u16,

    /// Caerulean public key (required, if not provided by 'link' argument!)
    #[structopt(short = "k", long)]
    key: Option<String>,

    /// Caerulean token value (required, if not provided by 'link' argument!)
    #[structopt(short = "t", long)]
    token: Option<String>,

    /// Caerulean protocol (required, if not provided by 'link' argument!)
    #[structopt(short = "p", long)]
    protocol: Option<String>,

    /// Connection link, will be used instead of other arguments if specified
    #[structopt(short = "l", long)]
    link: Option<String>,

    /// Print reef version number and exit
    #[structopt(short = "v", long)]
    version: bool,

    /// Install VPN connection, run command and exit after command is finished
    #[structopt(short = "e", long)]
    command: Option<String>
}


fn init_logging() {
    set_var("RUST_LOG", match var("SEASIDE_LOG_LEVEL") {
        Ok(level) => level,
        _ => match var("RUST_LOG") {
            Ok(level) => level,
            _ => DEFAULT_LOG_LEVEL.to_string()
        }
    });
    init();
}


fn parse_link(link: Option<String>) -> (Option<String>, Option<Ipv4Addr>, Option<u16>, Option<String>, Option<String>, Option<String>) {
    if link.is_some() {
        todo!();
    } else {
        (None, None, None, None, None, None)
    }
}

#[tokio::main]
async fn main() -> DynResult<()> {
    init_logging();
    let opt = Opt::from_args();
    if opt.version {
        println!("Seaside Viridian Reef version {}", env!("CARGO_PKG_VERSION"));
    } else {
        let (_link_node, link_address, link_port, link_token, link_key, link_protocol) = parse_link(opt.link);
        let address = link_address.unwrap_or(opt.address);
        let port = link_port.unwrap_or(opt.port);
        let token = link_token.unwrap_or_else(|| opt.token.expect("Caerulean token was not specified!"));
        let key = link_key.unwrap_or_else(|| opt.key.expect("Caerulean public key was not specified!"));
        let protocol = link_protocol.unwrap_or_else(|| opt.protocol.expect("Caerulean protocol was not specified!"));
        let proto_type = ProtocolType::from_str(&protocol)?;

        info!("Creating reef client...");
        let mut constructor = Viridian::new(address, port, &token, &key, proto_type).await?;
        info!("Starting reef Viridian...");
        constructor.start(opt.command).await?;
    }
    Ok(())
}
