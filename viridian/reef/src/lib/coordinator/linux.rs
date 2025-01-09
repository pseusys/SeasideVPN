use tokio::signal::unix::{Signal, SignalKind, signal};

use crate::DynResult;


pub fn create_signal_handlers() -> DynResult<Vec<(Signal, String)>> {
    let terminate_name = "SIGTERM".to_string();
    let signal_terminate = signal(SignalKind::terminate())?;
    let interrupt_name = "SIGINT".to_string();
    let signal_interrupt = signal(SignalKind::interrupt())?;
    Ok(vec![(signal_terminate, terminate_name), (signal_interrupt, interrupt_name)])
}
