use lazy_static::lazy_static;

use crate::crypto::Asymmetric;


pub mod buffer;
pub mod pool;
pub mod utils;

use pool::BytePool;
pub use buffer::ByteBuffer;


static INITIAL_POOL_SIZE: usize = 5;
pub static HEADER_OVERHEAD: usize = 64;

lazy_static! {
    static ref PACKET_POOL: BytePool = BytePool::new(HEADER_OVERHEAD + Asymmetric::ciphertext_overhead(), u16::MAX as usize, 0, INITIAL_POOL_SIZE);
}


pub fn get_buffer<'a>(initial_size: Option<usize>) -> ByteBuffer<'a> {
    match initial_size {
        Some(res) => PACKET_POOL.allocate(res),
        None => PACKET_POOL.allocate(0)
    }
}
