use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::task::{Context, Poll};

use pin_project::pin_project;
use tokio::io::ReadBuf;
use tokio::net::{TcpStream, ToSocketAddrs, UdpSocket};

use crate::socks::client::{Request, RequestType, Socks5Client};
use crate::socks::{Method, Result, TargetAddr};
use std::convert::TryFrom;
use std::pin::Pin;

pub trait AsyncDatagram {
    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<Result<usize>>;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<SocketAddr>>;
}

impl AsyncDatagram for UdpSocket {
    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<Result<usize>> {
        self.poll_send_to(cx, buf, target).map_err(|e| e.into())
    }

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<SocketAddr>> {
        self.poll_recv_from(cx, buf).map_err(|e| e.into())
    }
}

#[pin_project]
pub struct SendTo<'a> {
    #[pin]
    buf: &'a [u8],
    target: SocketAddr,
    inner: &'a dyn AsyncDatagram,
}

pub struct RecvFrom<'a> {
    buf: ReadBuf<'a>,
    inner: &'a dyn AsyncDatagram,
}

impl<'a> Future for SendTo<'a> {
    type Output = Result<usize>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_send_to(cx, self.buf, self.target)
    }
}

impl<'a> Future for RecvFrom<'a> {
    type Output = Result<SocketAddr>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_recv_from(cx, &mut self.buf)
    }
}

pub trait AsyncDatagramExt {
    fn send_to<'a>(&'a self, buf: &'a [u8], target: SocketAddr) -> SendTo<'a>;

    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> RecvFrom<'a>;
}

impl<T> AsyncDatagramExt for T
where
    T: AsyncDatagram,
{
    fn send_to<'a>(&'a self, buf: &'a [u8], target: SocketAddr) -> SendTo<'a> {
        SendTo {
            buf,
            target,
            inner: self,
        }
    }

    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> RecvFrom<'a> {
        RecvFrom {
            buf: ReadBuf::new(buf),
            inner: self,
        }
    }
}

pub struct Socks5Datagram<M> {
    client: Socks5Client<M>,
}

impl<M> Socks5Datagram<M>
where
    M: Method,
{
    pub async fn bind_with_socket_and_datagram(
        socket: M::Stream,
        datagram: M::Datagram,
    ) -> Result<Self> {
        let mut client: Socks5Client<M> = Socks5Client::connect(socket).await?;

        let dst = TargetAddr::Ip(SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0));

        let relay_addr = client
            .send_request(Request::new(RequestType::UdpAssociate, dst))
            .await?;

        client
            .register_endpoints(datagram, SocketAddr::try_from(relay_addr)?)
            .await?;

        Ok(Self { client })
    }

    pub async fn send_to(&mut self, buf: &[u8], addr: TargetAddr) -> Result<usize> {
        self.client.send_to(buf, SocketAddr::try_from(addr)?).await
    }

    pub async fn recv_from(&mut self, buf: &mut [u8]) -> Result<SocketAddr> {
        self.client.recv_from(buf).await
    }
}

impl<M> Socks5Datagram<M>
where
    M: Method<Datagram = UdpSocket>,
{
    pub async fn bind_with_socket<A: ToSocketAddrs>(socket: M::Stream, addr: A) -> Result<Self> {
        let udp_socket = UdpSocket::bind(addr).await?;
        Self::bind_with_socket_and_datagram(socket, udp_socket).await
    }
}

impl<M> Socks5Datagram<M>
where
    M: Method<Stream = TcpStream, Datagram = UdpSocket>,
{
    pub async fn bind<A: ToSocketAddrs, B: ToSocketAddrs>(addr: A, bind: B) -> Result<Self> {
        let socket = TcpStream::connect(addr).await?;

        Self::bind_with_socket(socket, bind).await
    }
}
