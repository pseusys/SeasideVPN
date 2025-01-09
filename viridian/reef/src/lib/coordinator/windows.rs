use tokio::signal::windows::{ctrl_c, ctrl_break, ctrl_close, ctrl_shutdown};

use crate::DynResult;


pub fn create_signal_handlers() -> DynResult<Vec<(Signal, String)>> {
    let ctrl_c_name = "Ctrl+C".to_string();
    let signal_ctrl_c = ctrl_c()?;
    let ctrl_break_name = "Ctrl+Break".to_string();
    let signal_ctrl_break = ctrl_break()?;
    let ctrl_close_name = "Ctrl+Close".to_string();
    let signal_ctrl_close = ctrl_close()?;
    let ctrl_shutdown_name = "Ctrl+Shutdown".to_string();
    let signal_ctrl_shutdown = ctrl_shutdown()?;
    Ok(vec![
        (signal_ctrl_c, ctrl_c_name),
        (signal_ctrl_break, ctrl_break_name),
        (signal_ctrl_close, ctrl_close_name),
        (signal_ctrl_shutdown, ctrl_shutdown_name)
    ])
}
