use log::{error, debug, info};

use tokio::net::lookup_host;
use tokio::select;
use tokio::signal::unix::{SignalKind, signal};

use crate::DynResult;
use super::{Coordinator, Startable};


impl Startable for Coordinator {
    async fn start(&mut self, command: Option<String>) -> DynResult<()> {
        debug!("Creating signal handlers...");
        let mut signal_terminate = signal(SignalKind::terminate())?;
        let mut signal_interrupt = signal(SignalKind::interrupt())?;

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
            _ = signal_terminate.recv() => info!("Received SIGTERM, terminating gracefully..."),
            _ = signal_interrupt.recv() => info!("Received SIGINT, terminating gracefully..."),
        };

        Ok(())
    }
}
