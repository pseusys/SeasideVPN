use std::env::{set_var, var};
use std::net::{Ipv4Addr, IpAddr, ToSocketAddrs};

use log::info;
use simple_error::bail;
use gethostname::gethostname;
use structopt::StructOpt;
use env_logger::init;

use reeflib::viridian::Coordinator;
use reeflib::DynResult;


const DEFAULT_CAERULEAN_ADDRESS: &str = "127.0.0.1";
const DEFAULT_CAERULEAN_PORT: &str = "8587";
const DEFAULT_LOG_LEVEL: &str = "INFO";

const DEFAULT_MIN_HC_TIME: &str = "1";
const DEFAULT_MAX_HC_TIME: &str = "5";
const DEFAULT_CONNECTION_TIMEOUT: &str = "3.0";


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

    /// Caerulean control port number (default: [`DEFAULT_CAERULEAN_PORT`])
    #[structopt(short = "c", long, default_value = DEFAULT_CAERULEAN_PORT)]
    ctrl_port: u16,

    /// Admin or caerulean payload value (required, if not provided by 'link' argument!)
    #[structopt(short = "p", long)]
    payload: Option<String>,

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


fn parse_link(link: Option<String>) -> (Option<String>, Option<Ipv4Addr>, Option<u16>, Option<String>) {
    if link.is_some() {
        todo!();
    } else {
        (None, None, None, None)
    }
}

#[tokio::main]
async fn main() -> DynResult<()> {
    init_logging();
    let opt = Opt::from_args();
    if opt.version {
        println!("Seaside Viridian Reef version {}", env!("CARGO_PKG_VERSION"));
    } else {
        let (_link_node, link_address, link_ctrl_port, link_payload) = parse_link(opt.link);
        let address = link_address.unwrap_or(opt.address);
        let port = link_ctrl_port.unwrap_or(opt.ctrl_port);
        let payload = link_payload.unwrap_or_else(|| opt.payload.expect("Caerulean payload value was not specified!"));
        let user = var("SEASIDE_USER_NAME").unwrap_or(gethostname().into_string().expect("Host name can not be parsed into a string!"));
        let min_hc = var("SEASIDE_MIN_HC_TIME").unwrap_or(DEFAULT_MIN_HC_TIME.to_string()).parse::<u16>().expect("'SEASIDE_MIN_HC_TIME' should be an integer!");
        let max_hc = var("SEASIDE_MAX_HC_TIME").unwrap_or(DEFAULT_MAX_HC_TIME.to_string()).parse::<u16>().expect("'SEASIDE_MAX_HC_TIME' should be an integer!");
        let timeout = var("SEASIDE_CONNECTION_TIMEOUT").unwrap_or(DEFAULT_CONNECTION_TIMEOUT.to_string()).parse::<f32>().expect("'SEASIDE_CONNECTION_TIMEOUT' should be a float!");
        let certs = var("SEASIDE_ROOT_CERTIFICATE_AUTHORITY").ok();

        info!("Creating reef coordinator...");
        let constructor = Coordinator::new(address, port, &payload, &user, min_hc, max_hc, timeout, &tunnel, tunnel_address, tunnel_netmask, svr_index, certs.as_deref());
        info!("Starting reef coordinator...");
        constructor.await?.start(opt.command).await?;
    }
    Ok(())
}
