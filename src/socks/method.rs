use async_trait::async_trait;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::socks::datagram::AsyncDatagram;
use crate::socks::{Result, Socks5Error};
use std::net::SocketAddr;
use std::ops::DerefMut;
use tokio::net::UdpSocket;

#[async_trait]
/// A trait for objects that implement the logic of socks5's method-dependent sub-negotiation.
pub trait Method: AsyncRead + AsyncWrite + AsyncDatagram + Unpin + Send + Sized {
    type Stream: AsyncRead + AsyncWrite + Unpin;
    type Datagram: AsyncDatagram;

    async fn create(socket: Self::Stream) -> Result<Self>;

    // Establish the method-dependent sub-negotiation context.
    async fn handshake(&mut self) -> Result<()>;

    // UDP-related methods
    async fn register_endpoints(&mut self, src: Self::Datagram, dst: SocketAddr) -> Result<()>;

    fn code() -> u8;
}

#[derive(Default)]
pub struct NoAuthentication<S, U = UdpSocket> {
    socket: S,
    datagram_socket: Option<U>,
    dst: Option<SocketAddr>,
}

impl<S, U> AsyncDatagram for NoAuthentication<S, U>
where
    U: AsyncDatagram,
{
    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<Result<usize>> {
        self.datagram_socket.as_ref().map_or_else(
            || Poll::Ready(Err(Socks5Error::DatagramSocketNotRegistered)),
            |datagram| datagram.poll_send_to(cx, buf, target),
        )
    }

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<SocketAddr>> {
        self.datagram_socket.as_ref().map_or_else(
            || Poll::Ready(Err(Socks5Error::DatagramSocketNotRegistered)),
            |datagram| datagram.poll_recv_from(cx, buf),
        )
    }
}

impl<S, U> AsyncRead for NoAuthentication<S, U>
where
    S: AsyncRead + Unpin,
    U: Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.deref_mut();
        Pin::new(&mut self.socket).poll_read(cx, buf)
    }
}

impl<S, U> AsyncWrite for NoAuthentication<S, U>
where
    S: AsyncWrite + Unpin,
    U: Unpin,
{
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
impl<S, U> Method for NoAuthentication<S, U>
where
    S: AsyncWrite + AsyncRead + Unpin + Send,
    U: AsyncDatagram + Unpin + Send,
{
    type Stream = S;
    type Datagram = U;
    async fn create(socket: S) -> Result<Self> {
        Ok(Self {
            socket,
            datagram_socket: None,
            dst: None,
        })
    }

    async fn handshake(&mut self) -> Result<()> {
        Ok(())
    }

    async fn register_endpoints(&mut self, src: Self::Datagram, dst: SocketAddr) -> Result<()> {
        self.datagram_socket = Some(src);
        self.dst = Some(dst);
        Ok(())
    }

    fn code() -> u8 {
        0
    }
}
