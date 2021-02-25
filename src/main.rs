pub mod socks;

use std::convert::TryFrom;
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::spawn;

use crate::socks::{NoAuthentication, Result, Socks5Listener, TargetAddr};

const MSG: &[u8] = b"hello world";

#[tokio::main]
async fn main() -> Result<()> {
    let listener = Socks5Listener::<NoAuthentication<TcpStream>>::bind(
        "127.0.0.1:41080",
        TargetAddr::Ip("127.0.0.1:2000".parse().unwrap()),
    )
    .await?;

    let bind_addr = listener.bind_addr();
    spawn(async {
        let engagement: SocketAddr = SocketAddr::try_from(bind_addr).unwrap();
        let mut client_conn = TcpStream::connect(engagement).await.unwrap();
        println!("{:?}", client_conn.local_addr());
        client_conn.write(MSG).await.unwrap();
    });

    let mut buf = vec![0; MSG.len()];
    let mut conn = listener.accept().await?;
    conn.read_exact(&mut buf).await?;

    println!(
        "read: {}\ntarget_addr: {:?}",
        String::from_utf8_lossy(&buf),
        conn.peer_addr()
    );
    Ok(())
}
