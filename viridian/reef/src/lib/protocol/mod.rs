use std::net::Ipv4Addr;
use std::str::FromStr;

use simple_error::{bail, SimpleError};

use crate::{bytes::ByteBuffer, DynResult, ReaderWriter};


mod common;
mod port_core;
mod typhoon_core;
mod utils;

mod port_client;
pub use port_client::*;

mod typhoon_client;
pub use typhoon_client::*;


pub trait ProtocolClientHandle<'a> {
    fn new(key: ByteBuffer<'_>, token: ByteBuffer<'a>, address: Ipv4Addr, port: u16, local: Option<Ipv4Addr>) -> DynResult<impl ProtocolClientHandle<'a>>;
    fn connect(&mut self) -> DynResult<impl ReaderWriter>;
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
