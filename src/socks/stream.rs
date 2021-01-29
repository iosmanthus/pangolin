use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, ToSocketAddrs};

use crate::socks::client::{Request, RequestType, Socks5Client};
use crate::socks::{Method, TargetAddr};

pub struct Socks5Stream<M> {
    client: Socks5Client<M>,
}

impl<M: Method> AsyncRead for Socks5Stream<M> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.client).poll_read(cx, buf)
    }
}

impl<M: Method> AsyncWrite for Socks5Stream<M> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.client).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.client).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.client).poll_shutdown(cx)
    }
}

impl<M: Method> Socks5Stream<M> {
    pub async fn connect<F: FnOnce(TcpStream) -> M, A: ToSocketAddrs>(
        proxy_addr: A,
        target_addr: TargetAddr,
        method_factory: F,
    ) -> Result<Self> {
        let socket = TcpStream::connect(proxy_addr).await?;
        let mut client = Socks5Client::connect(socket, method_factory).await?;
        let _ = client
            .send_request(Request::new(RequestType::Connect, target_addr))
            .await?;
        Ok(Self { client })
    }
}
