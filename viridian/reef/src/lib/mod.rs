use std::error::Error;
use std::future::Future;

use bytes::ByteBuffer;

pub mod bytes;
pub mod crypto;
pub mod general;
pub mod protocol;
pub mod runtime;
pub mod viridian;
pub mod tunnel;
pub mod link;
pub mod utils;

#[cfg(test)]
#[path = "../../tests/rng.rs"]
pub mod rng;

#[cfg(not(test))]
pub mod rng;


pub type DynResult<T> = Result<T, Box<dyn Error + Sync + Send>>;


pub trait Reader: Send + 'static {
    fn read_bytes(&mut self) -> impl Future<Output = DynResult<ByteBuffer>>;
}

pub trait Writer: Send + 'static {
    fn write_bytes(&mut self, bytes: ByteBuffer) -> impl Future<Output = DynResult<usize>>;
}
