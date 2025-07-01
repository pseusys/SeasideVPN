use bincode::config::{standard, BigEndian, Configuration, Fixint};
use bincode::enc::write::SizeWriter;
use bincode::{encode_into_writer, Encode};

use crate::bytes::HEADER_OVERHEAD;
use crate::DynResult;

pub const ENCODE_CONF: Configuration<BigEndian, Fixint> = standard().with_big_endian().with_fixed_int_encoding();

pub fn encode_to_32_bytes(input: &str) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let bytes = input.as_bytes();
    let len = bytes.len().min(32);
    buf[..len].copy_from_slice(&bytes[..len]);
    buf
}

// CACHE VALUES!
pub fn get_type_size<T: Default + Encode>() -> DynResult<usize> {
    let mut writer = SizeWriter::default();
    let default_header_value = T::default();
    encode_into_writer(default_header_value, &mut writer, ENCODE_CONF)?;
    let length = writer.bytes_written;
    assert!(length <= HEADER_OVERHEAD, "Type encoded length greater than maximum possible overhead ({} > {})!", length, HEADER_OVERHEAD);
    Ok(length)
}
