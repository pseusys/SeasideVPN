use std::{net::Ipv4Addr, sync::Arc};
use std::str::FromStr;

use simple_error::{bail, SimpleError};
use tonic::async_trait;

use crate::DynResult;


mod common;
mod port_core;
mod typhoon_core;
mod utils;

mod port_client;
use port_client::*;

mod typhoon_client;
use typhoon_client::*;


#[async_trait]
pub trait ProtocolClient: Send + Sync {
    async fn read_bytes(&self) -> DynResult<Vec<u8>>;
    async fn write_bytes(&self, bytes: &Vec<u8>) -> DynResult<usize>;
}

#[async_trait]
pub trait ProtocolClientHandle {
    async fn connect(&mut self) -> DynResult<Arc<dyn ProtocolClient>>;
}


#[derive(Debug)]
pub enum ProtocolType {
    PORT,
    TYPHOON,
}

impl ProtocolType {
    pub async fn create_client(&self, key: &Vec<u8>, token: &Vec<u8>, address: Ipv4Addr, port: u16, local: Option<Ipv4Addr>) -> DynResult<Box<dyn ProtocolClientHandle>> {
        match self {
            ProtocolType::PORT => Ok(Box::new(PortHandle::new(key, token, address, port, local).await?)),
            ProtocolType::TYPHOON => Ok(Box::new(TyphoonHandle::new(key, token, address, port, local).await?))
        }
    }
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
