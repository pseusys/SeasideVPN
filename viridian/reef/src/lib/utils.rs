use std::any::type_name;
use std::env::var;
use std::str::FromStr;

use byte_pool::{Block, BytePool};
use lazy_static::lazy_static;

use crate::crypto::Asymmetric;


pub static HEADER_OVERHEAD: usize = 64;

lazy_static! {
    static ref PACKET_POOL: BytePool = BytePool::new();
}


pub fn get_packet<'a>() -> Block<'a, Vec<u8>> {
    PACKET_POOL.alloc(HEADER_OVERHEAD + Asymmetric::ciphertext_overhead() + u16::MAX as usize)
}


pub fn parse_env<T: FromStr>(key: &str, default: Option<T>) -> T {
    match var(key) {
        Ok(res) => match res.parse::<T>() {
            Ok(res) => res,
            Err(_) => panic!("'{key}' should be conversable to {}!", type_name::<T>()),
        },
        Err(_) => match default {
            Some(res) => res,
            None => panic!("'{key}' should be set!"),
        },
    }
}

pub fn parse_str_env(key: &str, default: Option<&str>) -> String {
    match var(key) {
        Ok(res) => res,
        Err(_) => match default {
            Some(res) => res.to_string(),
            None => panic!("'{key}' should be set!"),
        },
    }
}
