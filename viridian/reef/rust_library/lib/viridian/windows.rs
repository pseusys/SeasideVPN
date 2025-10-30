use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close, ctrl_shutdown, CtrlBreak, CtrlC, CtrlClose, CtrlShutdown};

use crate::DynResult;

pub const DEFAULT_SHELL: &str = "powershell";
pub const DEFAULT_ARG: &str = "-Command";

pub enum Signal {
    CtrlC(CtrlC),
    CtrlBreak(CtrlBreak),
    CtrlClose(CtrlClose),
    CtrlShutdown(CtrlShutdown),
}

impl Signal {
    pub async fn recv(&mut self) -> Option<()> {
        match self {
            Signal::CtrlC(ctrl_c) => ctrl_c.recv().await,
            Signal::CtrlBreak(ctrl_break) => ctrl_break.recv().await,
            Signal::CtrlClose(ctrl_close) => ctrl_close.recv().await,
            Signal::CtrlShutdown(ctrl_shutdown) => ctrl_shutdown.recv().await,
        }
    }
}

pub fn create_signal_handlers() -> DynResult<Vec<(Signal, String)>> {
    let ctrl_c_name = "Ctrl+C".to_string();
    let signal_ctrl_c = Signal::CtrlC(ctrl_c()?);
    let ctrl_break_name = "Ctrl+Break".to_string();
    let signal_ctrl_break = Signal::CtrlBreak(ctrl_break()?);
    let ctrl_close_name = "Ctrl+Close".to_string();
    let signal_ctrl_close = Signal::CtrlClose(ctrl_close()?);
    let ctrl_shutdown_name = "Ctrl+Shutdown".to_string();
    let signal_ctrl_shutdown = Signal::CtrlShutdown(ctrl_shutdown()?);
    Ok(vec![(signal_ctrl_c, ctrl_c_name), (signal_ctrl_break, ctrl_break_name), (signal_ctrl_close, ctrl_close_name), (signal_ctrl_shutdown, ctrl_shutdown_name)])
}
