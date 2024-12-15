use log::{error, debug, info};

use tokio::net::lookup_host;
use tokio::select;
use tokio::signal::windows::{ctrl_c, ctrl_break, ctrl_close, ctrl_shutdown};

use crate::DynResult;
use super::{Coordinator, Startable};

impl Startable for Coordinator {
    async fn start(&mut self, command: Option<String>) -> DynResult<()> {
        debug!("Creating signal handlers...");
        let mut signal_ctrl_c = ctrl_c()?;
        let mut signal_ctrl_break = ctrl_break()?;
        let mut signal_ctrl_close = ctrl_close()?;
        let mut signal_ctrl_shutdown = ctrl_shutdown()?;

        debug!("Initiating connection...");
        let user_id = self.initialize_connection().await?;

        debug!("Running DNS probe to check for globally available DNS servers...");
        if lookup_host("example.com").await.is_err() {
            error!("WARNING! DNS probe failed! It is very likely that you have local DNS servers configured only!");
        }

        debug!("Running VPN processes asynchronously...");
        select! {
            res = Self::run_vpn_command(command), if command.is_some() => match res {
                Ok(status) => println!("The command exited with: {status}"),
                Err(err) => return Err(err)
            },
            err = self.run_vpn_loop(user_id) => {
                return Ok(err?)
            },
            _ = signal_ctrl_c.recv() => info!("Received CtrlC, terminating gracefully..."),
            _ = signal_ctrl_break.recv() => info!("Received CtrlBreak, terminating gracefully..."),
            _ = signal_ctrl_close.recv() => info!("Received CtrlClose, terminating gracefully..."),
            _ = signal_ctrl_shutdown.recv() => info!("Received CtrlShutdown, terminating gracefully..."),
        };

        Ok(())
    }
}
