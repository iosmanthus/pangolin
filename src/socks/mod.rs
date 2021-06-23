mod client;
mod datagram;
mod error;
mod listener;
mod method;
mod stream;

pub use self::datagram::{AsyncDatagram, AsyncDatagramExt, Socks5Datagram};
pub use self::error::{Result, Socks5Error};
pub use self::listener::Socks5Listener;
pub use self::method::{Method, NoAuthentication};
pub use self::stream::Socks5Stream;

use std::convert::TryFrom;
use std::net::{SocketAddr, ToSocketAddrs};

pub const VERSION: u8 = 0x5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl TryFrom<TargetAddr> for SocketAddr {
    type Error = Socks5Error;
    fn try_from(addr: TargetAddr) -> Result<Self> {
        Ok(match addr {
            TargetAddr::Ip(addr) => addr,
            TargetAddr::Domain(domain, port) => (domain, port)
                .to_socket_addrs()?
                .next()
                .ok_or(Socks5Error::InvalidTargetAddress)?,
        })
    }
}
