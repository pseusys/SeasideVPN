use std::error::Error;

use reef::coordinator::Coordinator;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut coordinator = Coordinator::new("payload", "5.35.95.99", 8587, "user", 1, 1, 1.0, "tun0").await?;
    coordinator.start().await?;
    Ok(())
}
