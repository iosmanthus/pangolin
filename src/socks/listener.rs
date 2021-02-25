use tokio::net::{TcpStream, ToSocketAddrs};

use crate::socks::client::{Request, RequestType, Socks5Client};
use crate::socks::{Method, Result, Socks5Stream, TargetAddr};

pub struct Socks5Listener<M> {
    client: Socks5Client<M>,
    bind_addr: TargetAddr,
}

impl<M> Socks5Listener<M> {
    pub fn bind_addr(&self) -> TargetAddr {
        self.bind_addr.clone()
    }
}

impl<M> Socks5Listener<M>
where
    M: Method,
{
    pub async fn bind_with_socket(
        socket: M::Stream,
        target_addr: TargetAddr,
    ) -> Result<Socks5Listener<M>> {
        let mut client = Socks5Client::<M>::connect(socket).await?;
        let bind_addr = client
            .send_request(Request::new(RequestType::Bind, target_addr))
            .await?;

        Ok(Self { client, bind_addr })
    }

    pub async fn accept(mut self) -> Result<Socks5Stream<M>> {
        let remote_addr = self.client.recv_reply().await?;

        Ok(Socks5Stream::new(self.client, remote_addr))
    }
}

impl<M> Socks5Listener<M>
where
    M: Method<Stream = TcpStream>,
{
    pub async fn bind<A: ToSocketAddrs>(proxy: A, target_addr: TargetAddr) -> Result<Self> {
        let socket = TcpStream::connect(proxy).await?;
        Self::bind_with_socket(socket, target_addr).await
    }
}
