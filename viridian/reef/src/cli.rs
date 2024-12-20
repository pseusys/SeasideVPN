use std::env::{set_var, var};
use std::net::{Ipv4Addr, IpAddr, ToSocketAddrs};

use log::info;
use simple_error::bail;
use gethostname::gethostname;
use structopt::StructOpt;
use env_logger::init;

use reeflib::coordinator::{Coordinator, Startable};
use reeflib::DynResult;

mod generated {
    tonic::include_proto!("generated");
}


const DEFAULT_CAERULEAN_ADDRESS: &str = "127.0.0.1";
const DEFAULT_CAERULEAN_PORT: &str = "8587";
const DEFAULT_LOG_LEVEL: &str = "INFO";

const DEFAULT_MIN_HC_TIME: &str = "1";
const DEFAULT_MAX_HC_TIME: &str = "5";
const DEFAULT_CONNECTION_TIMEOUT: &str = "3.0";
const DEFAULT_TUNNEL_NAME: &str = "seatun";
const DEFAULT_TUNNEL_ADDRESS: &str = "192.168.0.82";
const DEFAULT_TUNNEL_NETMASK: &str = "255.255.255.0";
const DEFAULT_SVR_INDEX: &str = "82";


fn parse_address(address: &str) -> DynResult<Ipv4Addr> {
    match address.parse::<IpAddr>() {
        Ok(IpAddr::V4(pip)) => Ok(pip),
        _ => match address.to_socket_addrs()?.next() {
            Some(rip) => match rip.ip() {
                IpAddr::V4(ripv4) => Ok(ripv4),
                IpAddr::V6(ripv6) => bail!("IP addresses v6 {ripv6} are not yet supported!")
            },
            None => bail!("IP address {address} can't be resolved!")
        }
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
        let tunnel = var("SEASIDE_TUNNEL_NAME").unwrap_or(DEFAULT_TUNNEL_NAME.to_string());
        let tunnel_address = var("SEASIDE_TUNNEL_ADDRESS").unwrap_or(DEFAULT_TUNNEL_ADDRESS.to_string()).parse::<Ipv4Addr>().expect("'SEASIDE_TUNNEL_ADDRESS' should be an IP address!");
        let tunnel_netmask = var("SEASIDE_TUNNEL_NETMASK").unwrap_or(DEFAULT_TUNNEL_NETMASK.to_string()).parse::<Ipv4Addr>().expect("'DEFAULT_TUNNEL_NETMASK' should be an IP netmask!");
        let svr_index = var("SEASIDE_SVR_INDEX").unwrap_or(DEFAULT_SVR_INDEX.to_string()).parse::<u8>().expect("'DEFAULT_SVR_INDEX' should be an integer!");
        let certs = var("SEASIDE_ROOT_CERTIFICATE_AUTHORITY").ok();

        info!("Creating reef coordinator...");
        let constructor = Coordinator::new(address, port, &payload, &user, min_hc, max_hc, timeout, &tunnel, tunnel_address, tunnel_netmask, svr_index, certs.as_deref());
        info!("Starting reef coordinator...");
        constructor.await?.start(opt.command).await?;
    }
    Ok(())
}
