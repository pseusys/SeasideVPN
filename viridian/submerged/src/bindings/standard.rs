use std::error::Error;

use submerged::init;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let coordinator = init("payload", "8.8.8.8", 42, "user", 1, 1, 1.0, "tun0").await?;
    Ok(())
}
