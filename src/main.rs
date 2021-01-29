pub mod socks;

use crate::socks::{NoAuthentication, Socks5Stream, TargetAddr};
use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<()> {
    let mut stream = Socks5Stream::connect(
        "172.18.0.2:1080",
        TargetAddr::Domain("example.com".into(), 80),
        NoAuthentication::create(),
    )
    .await?;

    stream.write_all(b"GET /\n\n").await?;

    let mut buf = Vec::new();
    let n = stream.read_to_end(&mut buf).await?;

    println!("{} bytes read\n\n{}", n, String::from_utf8_lossy(&buf));

    Ok(())
}
