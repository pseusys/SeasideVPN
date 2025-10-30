use std::error::Error;
use std::future::Future;

use bytes::ByteBuffer;

pub mod bytes;
pub mod crypto;
pub mod general;
pub mod protocol;
pub mod rng;
pub mod runtime;
pub mod tunnel;
pub mod utils;
pub mod viridian;

pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}

pub type DynResult<T> = Result<T, Box<dyn Error + Sync + Send>>;

pub trait Reader: Send + 'static {
    fn read_bytes(&mut self) -> impl Future<Output = DynResult<ByteBuffer<'_>>>;
}

pub trait Writer: Send + 'static {
    fn write_bytes(&mut self, bytes: ByteBuffer) -> impl Future<Output = DynResult<usize>>;
}
