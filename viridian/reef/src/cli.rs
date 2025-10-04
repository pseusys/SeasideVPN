use std::env::{set_var, var};
use std::fs::read;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;

use env_logger::init;
use log::{debug, info};
use prost::Message;
use reeflib::generated::SeasideWhirlpoolClientCertificate;
use reeflib::protocol::ProtocolType;
use simple_error::bail;
use structopt::StructOpt;

use reeflib::utils::parse_address;
use reeflib::viridian::Viridian;
use reeflib::DynResult;

const DEFAULT_LOG_LEVEL: &str = "INFO";

fn parse_path(string: &str) -> DynResult<PathBuf> {
    let path = PathBuf::from(string.to_string());
    if path.exists() {
        Ok(path)
    } else {
        bail!("Connection certificate does not exist at: {string}");
    }
}

#[derive(StructOpt, Debug)]
#[structopt(rename_all = "kebab-case")]
struct Opt {
    /// Connection link, will be used instead of other arguments if specified
    #[structopt(short = "f", long, parse(try_from_str = parse_path))]
    certificate: PathBuf,

    /// Caerulean protocol
    #[structopt(short = "m", long, default_value = "typhoon")]
    protocol: String,

    #[structopt(long)]
    capture_iface: Vec<String>,

    #[structopt(long)]
    capture_ranges: Vec<String>,

    #[structopt(long)]
    exempt_ranges: Vec<String>,

    #[structopt(long)]
    capture_addresses: Vec<String>,

    #[structopt(long)]
    exempt_addresses: Vec<String>,

    #[structopt(long)]
    capture_ports: Option<String>,

    #[structopt(long)]
    exempt_ports: Option<String>,

    #[structopt(long, parse(try_from_str = parse_address))]
    local_address: Option<Ipv4Addr>,

    /// Install VPN connection, run command and exit after command is finished
    #[structopt(short = "c", long)]
    command: Option<String>,
}

fn init_logging() {
    set_var(
        "RUST_LOG",
        match var("SEASIDE_LOG_LEVEL") {
            Ok(level) => level,
            _ => match var("RUST_LOG") {
                Ok(level) => level,
                _ => DEFAULT_LOG_LEVEL.to_string(),
            },
        },
    );
    init();
}

#[tokio::main]
async fn main() -> DynResult<()> {
    init_logging();
    let opt = Opt::from_args();
    
    let protocol = ProtocolType::from_str(&opt.protocol)?;
    let certificate = match read(opt.certificate) {
        Ok(res) => SeasideWhirlpoolClientCertificate::decode(&*res)?,
        Err(err) => bail!("Error reading certificate file: {err}"),
    };

    info!("Creating reef client...");
    debug!("Parameters for reef client: protocol {protocol:?}, certificate {certificate:?}");
    let mut constructor = Viridian::new(certificate, protocol, Some(opt.capture_iface), Some(opt.capture_ranges), Some(opt.exempt_ranges), Some(opt.capture_addresses), Some(opt.exempt_addresses), opt.capture_ports, opt.exempt_ports, opt.local_address).await?;

    info!("Starting reef Viridian...");
    constructor.start(opt.command).await?;

    info!("Destroying reef client...");
    Ok(())
}
