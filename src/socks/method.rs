use anyhow::Result;

use async_trait::async_trait;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;

#[async_trait]
/// A trait for objects that implement the logic of socks5's method-dependent sub-negotiation.
pub trait Method: AsyncRead + AsyncWrite + Unpin {
    // Establish the method-dependent sub-negotiation context.
    async fn handshake(&mut self) -> Result<()>;

    async fn register_udp_socket(&mut self, socket: UdpSocket) -> Result<()>;
    async fn send(&mut self) -> Result<usize>;
    async fn recv(&mut self) -> Result<usize>;
    fn code() -> u8;
}

#[derive(Default)]
pub struct NoAuthentication<S: Send> {
    socket: S,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> NoAuthentication<S> {
    pub fn new(socket: S) -> Self {
        Self { socket }
    }

    pub fn create() -> Box<dyn FnOnce(S) -> Self> {
        Box::new(NoAuthentication::new)
    }
}

impl<S: AsyncRead + Unpin + Send> AsyncRead for NoAuthentication<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin + Send> AsyncWrite for NoAuthentication<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.socket).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}

#[async_trait]
impl<S: AsyncWrite + AsyncRead + Unpin + Send> Method for NoAuthentication<S> {
    async fn handshake(&mut self) -> Result<()> {
        Ok(())
    }

    async fn register_udp_socket(&mut self, _: UdpSocket) -> Result<()> {
        unimplemented!()
    }

    async fn send(&mut self) -> Result<usize> {
        unimplemented!()
    }

    async fn recv(&mut self) -> Result<usize> {
        unimplemented!()
    }

    fn code() -> u8 {
        0
    }
}
