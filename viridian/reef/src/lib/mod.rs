use std::error::Error;

pub mod coordinator;
pub mod tunnel;
pub mod viridian;
mod nl_utils;

const VERSION: &str = "0.0.2";


pub type DynResult<T> = Result<T, Box<dyn Error>>;
