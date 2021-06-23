use tokio::net::TcpStream;

use crate::socks::{NoAuthentication, Result, Socks5Datagram, TargetAddr};

pub mod socks;

#[tokio::main]
async fn main() -> Result<()> {
    let mut socket =
        Socks5Datagram::<NoAuthentication<TcpStream>>::bind("172.18.0.2:1080", "0.0.0.0:7878")
            .await?;

    // An echo UDP server from my VPS.
    let remote = "65.52.160.71:7878".parse().unwrap();

    socket.send_to(b"hello", TargetAddr::Ip(remote)).await?;

    let mut buf = [0; 10];
    let target_addr = socket.recv_from(&mut buf).await?;
    assert_eq!(target_addr, TargetAddr::Ip(remote));

    Ok(())
}
