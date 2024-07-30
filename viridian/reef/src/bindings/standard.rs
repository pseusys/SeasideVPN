use std::error::Error;

use reef::init;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut coordinator = init("payload", "5.35.95.99", 8587, "user", 1, 1, 1.0, "tun0").await?;
    coordinator.start().await?;
    Ok(())
}
