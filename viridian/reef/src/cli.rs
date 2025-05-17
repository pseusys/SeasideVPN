use std::env::{set_var, var};
use std::net::{Ipv4Addr, IpAddr, ToSocketAddrs};
use std::str::FromStr;

use log::info;
use reeflib::protocol::ProtocolType;
use simple_error::bail;
use structopt::StructOpt;
use env_logger::init;

use reeflib::link::parse_client_link;
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
    #[structopt(short = "p", long, default_value = DEFAULT_CAERULEAN_PORT)]
    port: u16,

    /// Caerulean token value (required, if not provided by 'link' argument!)
    #[structopt(short = "t", long)]
    token: Option<String>,

    /// Caerulean public key (required, if not provided by 'link' argument!)
    #[structopt(short = "r", long)]
    public: Option<String>,

    /// Caerulean protocol (required, if not provided by 'link' argument!)
    #[structopt(short = "s", long)]
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


fn process_link(link: Option<String>) -> DynResult<(Option<String>, Option<Vec<u8>>, Option<u16>, Option<u16>, Option<Vec<u8>>)> {
    match link {
        Some(res) => parse_client_link(res)?,
        None => (None, None, None, None, None, None)
    }
}

#[tokio::main]
async fn main() -> DynResult<()> {
    init_logging();
    let opt = Opt::from_args();
    if opt.version {
        println!("Seaside Viridian Reef version {}", env!("CARGO_PKG_VERSION"));
    } else {
        let (link_address, link_public, link_port, link_typhoon, link_token) = process_link(opt.link)?;

        let public = match link_public {
            Some(res) => res,
            None => match opt.public {
                Some(res) => res,
                None => bail!("Caerulean public key was not specified!")
            }
        };

        let token = match link_token {
            Some(res) => res,
            None => match opt.token {
                Some(res) => res,
                None => bail!("Caerulean token was not specified!")
            }
        };

        let protocol = match opt.protocol {
            Some(res) => ProtocolType::from_str(&res)?,
            None => bail!("Caerulean protocol was not specified!")
        };

        let link_port_number = match protocol {
            ProtocolType::PORT => link_port,
            ProtocolType::TYPHOON => link_typhoon,
        };
        let port = match link_port_number {
            Some(res) => res,
            None => match opt.port {
                Some(res) => res,
                None => bail!("Caerulean port was not specified!")
            }
        };

        let address = match link_address {
            Some(res) => parse_address(&ip)?,
            None => match opt.link {
                Some(res) => res,
                None => bail!("Caerulean address was not specified!")
            }
        };

        info!("Creating reef client...");
        let mut constructor = Viridian::new(address, port, token, key, proto_type).await?;
        info!("Starting reef Viridian...");
        constructor.start(opt.command).await?;
    }
    Ok(())
}
