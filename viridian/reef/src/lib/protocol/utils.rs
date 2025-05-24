use std::io::{Error, ErrorKind, Result};
use std::mem::MaybeUninit;

use bincode::config::{standard, BigEndian, Configuration, Fixint};
use bincode::{encode_into_writer, Encode};
use bincode::enc::write::SizeWriter;
use socket2::Socket;

use crate::bytes::{get_buffer, HEADER_OVERHEAD};
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


pub fn recv_exact(socket: &Socket, buf: &mut [u8]) -> Result<()> {
    let length = buf.len();
    let buf = unsafe { &mut *(buf as *mut [u8] as *mut [MaybeUninit<u8>]) };
    let mut read = 0;
    while read < length {
        match socket.recv(&mut buf[read..]) {
            Ok(0) => return Err(Error::new(ErrorKind::UnexpectedEof, "Connection closed!")),
            Ok(nr) => read += nr,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e)
        }
    }
    Ok(())
}

pub fn discard_exact(socket: &Socket, number: usize) -> Result<()> {
    let buffer = get_buffer(Some(number));
    recv_exact(socket, &mut buffer.slice_mut())?;
    Ok(())
}

pub fn send_exact(socket: &Socket, buf: &[u8]) -> Result<()> {
    let mut written = 0;
    while written < buf.len() {
        match socket.send(&buf[written..]) {
            Ok(0) => return Err(Error::new(ErrorKind::WriteZero, "Failed to write to socket!")),
            Ok(nr) => written += nr,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e)
        }
    }
    Ok(())
}
