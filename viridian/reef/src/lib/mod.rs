use std::error::Error;

use bytes::ByteBuffer;

pub mod bytes;
pub mod crypto;
pub mod protocol;
pub mod viridian;
pub mod tunnel;
pub mod link;
pub mod utils;


pub type DynResult<T> = Result<T, Box<dyn Error + Sync + Send>>;


pub trait ReaderWriter: Clone + Send + 'static {
    fn read_bytes(&mut self) -> DynResult<ByteBuffer>;
    fn write_bytes(&mut self, bytes: &mut ByteBuffer) -> DynResult<usize>;
}
