use std::convert::{TryFrom, TryInto};
use std::io;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};

use byteorder::{ByteOrder, NetworkEndian, WriteBytesExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::socks::datagram::AsyncDatagram;
use crate::socks::{Method, Result, Socks5Error, TargetAddr, VERSION};

#[derive(Debug, Clone, Copy)]
pub(crate) enum RequestType {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

pub(crate) struct Request {
    request_type: RequestType,
    target_addr: TargetAddr,
}

impl TryFrom<Request> for Vec<u8> {
    type Error = Socks5Error;
    fn try_from(request: Request) -> Result<Self> {
        use TargetAddr::*;
        let mut buf = Vec::with_capacity(262);

        // +----+-----+-------+------+----------+----------+
        // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        // +----+-----+-------+------+----------+----------+
        // | 1  |  1  | X'00' |  1   | Variable |    2     |
        // +----+-----+-------+------+----------+----------+
        buf.push(VERSION);
        buf.push(request.request_type as u8);
        buf.push(0x00);

        match request.target_addr {
            Ip(SocketAddr::V4(socket)) => {
                buf.push(0x01);
                buf.extend_from_slice(&socket.ip().octets());
                WriteBytesExt::write_u16::<NetworkEndian>(&mut buf, socket.port()).unwrap();
            }
            Domain(domain, port) => {
                buf.push(0x03);
                buf.push(
                    domain
                        .len()
                        .try_into()
                        .map_err(|_| Socks5Error::DomainTooLong)?,
                );
                buf.extend_from_slice(domain.as_bytes());
                WriteBytesExt::write_u16::<NetworkEndian>(&mut buf, port).unwrap();
            }
            Ip(SocketAddr::V6(socket)) => {
                buf.push(0x04);
                buf.extend_from_slice(&socket.ip().octets());
                WriteBytesExt::write_u16::<NetworkEndian>(&mut buf, socket.port()).unwrap();
            }
        }

        Ok(buf)
    }
}

impl Request {
    pub fn new(request_type: RequestType, target_addr: TargetAddr) -> Self {
        Self {
            request_type,
            target_addr,
        }
    }
}

impl<M> Deref for Socks5Client<M> {
    type Target = M;
    fn deref(&self) -> &Self::Target {
        &self.method
    }
}

impl<M> DerefMut for Socks5Client<M> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.method
    }
}

pub(crate) struct Socks5Client<M> {
    method: M,
}

impl<M> Socks5Client<M>
where
    M: Method,
{
    fn pack_datagram(dst: TargetAddr, data: &[u8]) -> Result<Vec<u8>> {
        use TargetAddr::*;
        let mut buf = vec![0x0, 0x0, 0x0];
        match dst {
            Ip(SocketAddr::V4(socket)) => {
                buf.push(0x01);
                buf.extend_from_slice(&socket.ip().octets());
                WriteBytesExt::write_u16::<NetworkEndian>(&mut buf, socket.port()).unwrap();
            }
            Domain(domain, port) => {
                buf.push(0x03);
                buf.push(
                    domain
                        .len()
                        .try_into()
                        .map_err(|_| Socks5Error::DomainTooLong)?,
                );
                buf.extend_from_slice(domain.as_bytes());
                WriteBytesExt::write_u16::<NetworkEndian>(&mut buf, port).unwrap();
            }
            Ip(SocketAddr::V6(socket)) => {
                buf.push(0x04);
                buf.extend_from_slice(&socket.ip().octets());
                WriteBytesExt::write_u16::<NetworkEndian>(&mut buf, socket.port()).unwrap();
            }
        };
        buf.extend_from_slice(data);
        Ok(buf)
    }
    pub async fn connect(mut socket: M::Stream) -> Result<Self> {
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
            return Err(Socks5Error::InvalidResponseVersion {
                expected: VERSION,
                actual: buf[0],
            });
        }

        if buf[1] == 0xff {
            return Err(Socks5Error::NoAcceptableMethod);
        }

        let mut method = M::create(socket).await?;
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
        let data: Vec<u8> = request.try_into()?;
        self.method.write(&data).await?;
        let addr = self.recv_reply().await?;
        Ok(addr)
    }

    // +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    pub async fn recv_reply(&mut self) -> Result<TargetAddr> {
        use TargetAddr::*;

        let mut buf = [0; 262];
        self.method.read_exact(&mut buf[..4]).await?;

        if buf[0] != VERSION {
            return Err(Socks5Error::InvalidResponseVersion {
                expected: VERSION,
                actual: buf[0],
            });
        }

        match buf[1] {
            0x00 => {}
            0x01 => return Err(Socks5Error::GeneralSocksServerFailure),
            0x02 => return Err(Socks5Error::ConnectionNotAllowed),
            0x03 => return Err(Socks5Error::NetworkUnreachable),
            0x04 => return Err(Socks5Error::HostUnreachable),
            0x05 => return Err(Socks5Error::ConnectionRefused),
            0x06 => return Err(Socks5Error::TtlExpired),
            0x07 => return Err(Socks5Error::CommandNotSupported),
            0x08 => return Err(Socks5Error::AddressTypeNotSupported),
            _ => return Err(Socks5Error::Unassigned),
        }

        if buf[2] != 0x00 {
            return Err(Socks5Error::InvalidReservedByte {
                expected: 0x00,
                actual: buf[2],
            });
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

            _ => return Err(Socks5Error::InvalidAddressType),
        };

        Ok(target_addr)
    }
}

impl<M> AsyncDatagram for Socks5Client<M>
where
    M: Method,
{
    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: TargetAddr,
    ) -> Poll<Result<usize>> {
        self.method.poll_send_to(
            cx,
            &Socks5Client::<M>::pack_datagram(target.clone(), buf)?,
            target,
        )
    }

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<TargetAddr>> {
        self.method.poll_recv_from(cx, buf)
    }
}

impl<M> AsyncRead for Socks5Client<M>
where
    M: Method,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.method).poll_read(cx, buf)
    }
}

impl<M> AsyncWrite for Socks5Client<M>
where
    M: Method,
{
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
