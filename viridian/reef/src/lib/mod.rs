use std::error::Error;

pub mod coordinator;
pub mod tunnel;
pub mod viridian;

const VERSION: &str = "0.0.3";


pub type DynResult<T> = Result<T, Box<dyn Error>>;
