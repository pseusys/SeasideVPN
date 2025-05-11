use std::error::Error;

pub mod crypto;
pub mod protocol;
pub mod viridian;
pub mod tunnel;
pub mod utils;


pub type DynResult<T> = Result<T, Box<dyn Error + Sync + Send>>;
