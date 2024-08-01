use std::error::Error;

use reeflib::coordinator::Coordinator;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut coordinator = Coordinator::new("payload", "10.87.82.87", 8587, "user", 1, 3, 5.0, "tun0").await?;
    coordinator.start().await?;
    Ok(())
}
