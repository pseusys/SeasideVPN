use lazy_static::lazy_static;
use tokio::runtime::{Builder, Runtime};


lazy_static! {
    pub static ref LocalTokioRuntime: Runtime = Builder::new_current_thread().enable_all().build().expect("Failed to start TYPHOON runtime!");
}


#[macro_export]
macro_rules! acquire_handle {
    () => {
        match tokio::runtime::Handle::try_current() {
            Ok(res) => {
                log::warn!("Using existing runtime!");
                res
            },
            Err(_) => {
                log::warn!("Creating new runtime!");
                $crate::runtime::LocalTokioRuntime.handle().clone()
            }
        }
    };
}

#[macro_export]
macro_rules! run_coroutine_sync {
    ($future:expr) => {{
        $crate::acquire_handle!().block_on($future)
    }};
}

#[macro_export]
macro_rules! run_coroutine_in_thread {
    ($future:expr) => {
        $crate::acquire_handle!().spawn_blocking(move || { $crate::run_coroutine_sync!($future) })
    };
}
