use lazy_static::lazy_static;
use tokio::runtime::{Builder, Runtime};


lazy_static! {
    pub static ref LocalTokioRuntime: Runtime = Builder::new_current_thread().enable_all().build().expect("Failed to start TYPHOON runtime!");
}


#[macro_export]
macro_rules! run_coroutine_sync {
    ($future:expr) => {{
        match tokio::runtime::Handle::try_current() {
            Ok(res) => res,
            Err(_) => $crate::runtime::LocalTokioRuntime.handle().clone()
        }.block_on($future)
    }};
}

#[macro_export]
macro_rules! run_coroutine_in_thread {
    ($future:expr) => {
        std::thread::spawn(move || { $crate::run_coroutine_sync!($future) })
    };
}

#[macro_export]
macro_rules! run_coroutine_conditionally {
    ($future:expr) => {
        match tokio::runtime::Handle::try_current() {
            Ok(_) => tokio::task::spawn_local(async { tokio::task::LocalSet::new().run_until($future).await }),
            Err(_) => $crate::runtime::LocalTokioRuntime.spawn_blocking(move || { $crate::run_coroutine_sync!($future) })
        }
    };
}
