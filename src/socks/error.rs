use std::io;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Socks5Error>;

#[derive(Error, Debug)]
pub enum Socks5Error {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("domain address is longer than 255 bytes")]
    DomainTooLong,
    #[error("invalid response version: expected {expected}, actual: {actual}")]
    InvalidResponseVersion { expected: u8, actual: u8 },

    #[error("no acceptable method")]
    NoAcceptableMethod,

    // Reply related error
    #[error("general socks server failure")]
    GeneralSocksServerFailure,
    #[error("connection not allowed")]
    ConnectionNotAllowed,
    #[error("network unreachable")]
    NetworkUnreachable,
    #[error("host unreachable")]
    HostUnreachable,
    #[error("connection refused")]
    ConnectionRefused,
    #[error("ttl expired")]
    TtlExpired,
    #[error("command not supported")]
    CommandNotSupported,
    #[error("address type not supported")]
    AddressTypeNotSupported,
    #[error("unassigned")]
    Unassigned,

    #[error("invalid reserved byte: expected: {expected}, actual: {actual}")]
    InvalidReservedByte { expected: u8, actual: u8 },

    #[error("invalid address type")]
    InvalidAddressType,

    #[error("invalid target address")]
    InvalidTargetAddress,

    #[error("datagram socket not registered")]
    DatagramSocketNotRegistered,
}
