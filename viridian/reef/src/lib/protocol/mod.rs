use std::str::FromStr;

use lazy_static::lazy_static;
use simple_error::{bail, SimpleError};

mod common;
mod port_core;
mod typhoon_core;
mod utils;

mod port_client;
pub use port_client::*;

mod typhoon_client;
pub use typhoon_client::*;

lazy_static! {
    static ref CLIENT_TYPE: u8 = 82;
    static ref CLIENT_VERSION: u8 = env!("CARGO_PKG_VERSION_MAJOR").parse::<u8>().unwrap();
}

#[derive(Debug)]
pub enum ProtocolType {
    PORT,
    TYPHOON,
}

impl FromStr for ProtocolType {
    type Err = SimpleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "port" => Ok(ProtocolType::PORT),
            "typhoon" => Ok(ProtocolType::TYPHOON),
            _ => bail!("Unknown protocol type: {s}"),
        }
    }
}
