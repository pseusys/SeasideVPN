use std::str::FromStr;

use simple_error::{bail, SimpleError};


mod common;
mod port_core;
mod typhoon_core;
mod utils;

mod port_client;
pub use port_client::*;

mod typhoon_client;
pub use typhoon_client::*;


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
