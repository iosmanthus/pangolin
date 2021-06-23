use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, ToSocketAddrs};

use crate::socks::client::{Request, RequestType, Socks5Client};
use crate::socks::{Method, Result, TargetAddr};

pub struct Socks5Stream<M> {
    client: Socks5Client<M>,
    peer_addr: TargetAddr,
}

impl<M> Socks5Stream<M> {
    pub(crate) fn new(client: Socks5Client<M>, peer_addr: TargetAddr) -> Self {
        Socks5Stream { client, peer_addr }
    }

    pub fn peer_addr(&self) -> TargetAddr {
        self.peer_addr.clone()
    }
}

impl<M> AsyncRead for Socks5Stream<M>
where
    M: Method,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.client).poll_read(cx, buf)
    }
}

impl<M: Method> AsyncWrite for Socks5Stream<M>
where
    M: Method,
{
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

impl<M> Socks5Stream<M>
where
    M: Method,
{
    pub async fn connect_with_socket(socket: M::Stream, target_addr: TargetAddr) -> Result<Self> {
        let mut client = Socks5Client::<M>::connect(socket).await?;
        let _ = client
            .send_request(Request::new(RequestType::Connect, target_addr.clone()))
            .await?;
        Ok(Self {
            client,
            peer_addr: target_addr,
        })
    }
}

impl<M> Socks5Stream<M>
where
    M: Method<Stream = TcpStream>,
{
    pub async fn connect<A: ToSocketAddrs>(proxy_addr: A, target_addr: TargetAddr) -> Result<Self> {
        let socket = TcpStream::connect(proxy_addr).await?;
        Self::connect_with_socket(socket, target_addr).await
    }
}
