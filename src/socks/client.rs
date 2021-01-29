use std::convert::TryInto;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{anyhow, bail, Result};
use byteorder::{ByteOrder, NetworkEndian, WriteBytesExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::socks::Method;

const VERSION: u8 = 0x5;

#[derive(Debug, Clone, Copy)]
pub(crate) enum RequestType {
    Connect = 0x01,
    // Bind = 0x02,
    // UdpAssociate = 0x03,
}

#[derive(Debug, Clone)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

pub(crate) struct Request {
    request_type: RequestType,
    target_addr: TargetAddr,
}

impl Request {
    pub fn new(request_type: RequestType, target_addr: TargetAddr) -> Self {
        Self {
            request_type,
            target_addr,
        }
    }
    fn try_into_bytes(self) -> Result<Vec<u8>> {
        use TargetAddr::*;
        let mut buf = Vec::with_capacity(262);

        // +----+-----+-------+------+----------+----------+
        // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        // +----+-----+-------+------+----------+----------+
        // | 1  |  1  | X'00' |  1   | Variable |    2     |
        // +----+-----+-------+------+----------+----------+
        buf.push(VERSION);
        buf.push(self.request_type as u8);
        buf.push(0x00);

        match self.target_addr {
            Ip(SocketAddr::V4(socket)) => {
                buf.push(0x01);
                buf.extend(socket.ip().octets().iter());
                WriteBytesExt::write_u16::<NetworkEndian>(&mut buf, socket.port()).unwrap();
            }
            Domain(domain, port) => {
                buf.push(0x03);
                buf.push(
                    domain
                        .len()
                        .try_into()
                        .map_err(|_| anyhow!("DomainNameTooLong"))?,
                );
                buf.extend(domain.as_bytes());
                WriteBytesExt::write_u16::<NetworkEndian>(&mut buf, port).unwrap();
            }
            Ip(SocketAddr::V6(socket)) => {
                buf.push(0x04);
                buf.extend(socket.ip().octets().iter());
                WriteBytesExt::write_u16::<NetworkEndian>(&mut buf, socket.port()).unwrap();
            }
        }

        Ok(buf)
    }
}

pub(crate) struct Socks5Client<M> {
    method: M,
}

impl<M: Method> Socks5Client<M> {
    pub async fn connect<S: AsyncRead + AsyncWrite + Unpin, F: FnOnce(S) -> M>(
        mut socket: S,
        method_factory: F,
    ) -> Result<Self> {
        // +----+----------+----------+
        // |VER | NMETHODS | METHODS  |
        // +----+----------+----------+
        // | 1  |    1     | 1 to 255 |
        // +----+----------+----------+
        socket.write(&[VERSION, 0x1, M::code()]).await?;

        // +----+--------+
        // |VER | METHOD |
        // +----+--------+
        // | 1  |   1    |
        // +----+--------+
        let mut buf = [0; 2];
        socket.read_exact(&mut buf).await?;

        if buf[0] != VERSION {
            bail!("InvalidResponseVersion")
        }
        if buf[1] == 0xff {
            bail!("NoAcceptableMethod")
        }

        let mut method = method_factory(socket);
        // Enter method dependent sub-negotiation phase
        method.handshake().await?;

        Ok(Self { method })
    }

    // +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    pub async fn send_request(&mut self, request: Request) -> Result<TargetAddr> {
        self.method.write(&request.try_into_bytes()?).await?;
        let addr = self.recv_reply().await?;
        Ok(addr)
    }

    // +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    async fn recv_reply(&mut self) -> Result<TargetAddr> {
        use TargetAddr::*;

        let mut buf = [0; 262];
        self.method.read_exact(&mut buf[..4]).await?;

        if buf[0] != VERSION {
            bail!("InvalidResponseVersion")
        }

        match buf[1] {
            0x00 => {}
            0x01 => bail!("GeneralSocksServerFailure"),
            0x02 => bail!("ConnectionNotAllowed"),
            0x03 => bail!("NetworkUnreachable"),
            0x04 => bail!("HostUnreachable"),
            0x05 => bail!("ConnectionRefused"),
            0x06 => bail!("TtlExpired"),
            0x07 => bail!("CommandNotSupported"),
            0x08 => bail!("AddressTypeNotSupported"),
            _ => bail!("Unassigned"),
        }

        if buf[2] != 0x00 {
            bail!("InvalidReservedByte")
        }

        let target_addr = match buf[3] {
            0x01 => {
                let begin = 4;
                let offset = 4 + 2;
                let buf = &mut buf[begin..begin + offset];

                self.method.read_exact(buf).await?;

                let ip: [u8; 4] = buf[..4].try_into().unwrap();
                let port = NetworkEndian::read_u16(&buf[4..]);
                Ip(SocketAddr::from((ip, port)))
            }
            0x3 => {
                let len = self.method.read_u8().await? as usize;
                let begin = 5;
                let offset = len + 2;
                let buf = &mut buf[begin..offset];

                self.method.read_exact(buf).await?;

                let domain = String::from_utf8_lossy(&buf[..len]).to_string();
                let port = NetworkEndian::read_u16(&buf[len..]);

                Domain(domain, port)
            }
            0x4 => {
                let begin = 4;
                let offset = 16 + 2;
                let buf = &mut buf[begin..begin + offset];

                self.method.read_exact(buf).await?;

                let ip: [u8; 16] = buf[..16].try_into().unwrap();
                let port = NetworkEndian::read_u16(&buf[16..]);
                Ip(SocketAddr::from((ip, port)))
            }

            _ => bail!("InvalidAddressType"),
        };

        Ok(target_addr)
    }
}

impl<M: Method> AsyncRead for Socks5Client<M> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.method).poll_read(cx, buf)
    }
}

impl<M: Method> AsyncWrite for Socks5Client<M> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.method).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.method).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.method).poll_shutdown(cx)
    }
}
