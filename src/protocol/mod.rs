mod address;
mod command;
pub mod handshake;
mod reply;
mod request;
mod response;
mod udp;

pub use self::{
    address::{Address, AddressType},
    command::Command,
    handshake::{
        AuthMethod,
        password_method::{self, UserKey},
    },
    reply::Reply,
    request::Request,
    response::Response,
    udp::UdpHeader,
};
pub use bytes::BufMut;

#[cfg(feature = "tokio")]
use async_trait::async_trait;
#[cfg(feature = "tokio")]
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// SOCKS protocol version, either 4 or 5
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub enum Version {
    V4 = 4,
    #[default]
    V5 = 5,
}

impl TryFrom<u8> for Version {
    type Error = std::io::Error;

    fn try_from(value: u8) -> std::io::Result<Self> {
        match value {
            4 => Ok(Version::V4),
            5 => Ok(Version::V5),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid version")),
        }
    }
}

impl From<Version> for u8 {
    fn from(v: Version) -> Self {
        v as u8
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v: u8 = (*self).into();
        write!(f, "{}", v)
    }
}

pub trait StreamOperation {
    fn retrieve_from_stream<R>(stream: &mut R) -> std::io::Result<Self>
    where
        R: std::io::Read,
        Self: Sized;

    fn write_to_stream<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        let mut buf = Vec::with_capacity(self.len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf)
    }

    fn write_to_buf<B: bytes::BufMut>(&self, buf: &mut B);

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(feature = "tokio")]
#[async_trait]
pub trait AsyncStreamOperation: StreamOperation {
    async fn retrieve_from_async_stream<R>(r: &mut R) -> std::io::Result<Self>
    where
        R: AsyncRead + Unpin + Send + ?Sized,
        Self: Sized;

    async fn write_to_async_stream<W>(&self, w: &mut W) -> std::io::Result<()>
    where
        W: AsyncWrite + Unpin + Send + ?Sized,
    {
        let mut buf = bytes::BytesMut::with_capacity(self.len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }
}
