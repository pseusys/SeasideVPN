use std::any::Any;

use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close, ctrl_shutdown, CtrlBreak, CtrlC, CtrlClose, CtrlShutdown};

use crate::DynResult;


pub struct Signal {
    inner: Box<dyn Any>
}

impl Signal {
    fn create(signal: Box<dyn Any>) -> Self {
        Signal {inner: signal}
    }

    pub async fn recv(&mut self) -> Option<()> {
        if let Some(sig) = self.inner.downcast_mut::<CtrlC>() {
            sig.recv().await
        } else if let Some(sig) = self.inner.downcast_mut::<CtrlBreak>() {
            sig.recv().await
        } else if let Some(sig) = self.inner.downcast_mut::<CtrlClose>() {
            sig.recv().await
        } else if let Some(sig) = self.inner.downcast_mut::<CtrlShutdown>() {
            sig.recv().await
        } else {
            panic!("Signal type {:?} is not supported!", self.inner.type_id())
        }
    }
}


pub fn create_signal_handlers() -> DynResult<Vec<(Signal, String)>> {
    let ctrl_c_name = "Ctrl+C".to_string();
    let signal_ctrl_c = Signal::create(Box::new(ctrl_c()?));
    let ctrl_break_name = "Ctrl+Break".to_string();
    let signal_ctrl_break = Signal::create(Box::new(ctrl_break()?));
    let ctrl_close_name = "Ctrl+Close".to_string();
    let signal_ctrl_close = Signal::create(Box::new(ctrl_close()?));
    let ctrl_shutdown_name = "Ctrl+Shutdown".to_string();
    let signal_ctrl_shutdown = Signal::create(Box::new(ctrl_shutdown()?));
    Ok(vec![
        (signal_ctrl_c, ctrl_c_name),
        (signal_ctrl_break, ctrl_break_name),
        (signal_ctrl_close, ctrl_close_name),
        (signal_ctrl_shutdown, ctrl_shutdown_name)
    ])
}
