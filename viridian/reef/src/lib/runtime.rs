use lazy_static::lazy_static;
use tokio::runtime::{Builder, Runtime};


lazy_static! {
    pub static ref LocalTokioRuntime: Runtime = Builder::new_current_thread().enable_all().build().expect("Failed to start TYPHOON runtime!");
}


#[macro_export]
macro_rules! run_coroutine_sync {
    ($future:expr) => {{
        match tokio::runtime::Handle::try_current() {
            Ok(res) => tokio::task::block_in_place(move || { res.block_on($future) }),
            Err(_) => $crate::runtime::LocalTokioRuntime.block_on($future)
        }
    }};
}

#[macro_export]
macro_rules! run_coroutine_in_thread {
    ($future:expr) => {{
        let handle = match tokio::runtime::Handle::try_current() {
            Ok(res) => res,
            Err(_) => $crate::runtime::LocalTokioRuntime.handle().clone()
        };
        handle.clone().spawn_blocking(move || { handle.block_on($future) })
    }};
}
