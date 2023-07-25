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
        password_method::{self, UserKey},
        AuthMethod,
    },
    reply::Reply,
    request::Request,
    response::Response,
    udp::UdpHeader,
};

#[cfg(feature = "tokio")]
use async_trait::async_trait;
#[cfg(feature = "tokio")]
use tokio::io::{AsyncRead, AsyncWrite};

pub const SOCKS_VERSION_V5: u8 = 0x05;
pub const SOCKS_VERSION_V4: u8 = 0x04;

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
}

#[cfg(feature = "tokio")]
#[async_trait]
pub trait AsyncStreamOperation {
    async fn retrieve_from_async_stream<R>(r: &mut R) -> std::io::Result<Self>
    where
        R: AsyncRead + Unpin + Send,
        Self: Sized;

    async fn write_to_async_stream<W>(&self, w: &mut W) -> std::io::Result<()>
    where
        W: AsyncWrite + Unpin + Send;
}
