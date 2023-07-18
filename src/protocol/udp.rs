use crate::protocol::address::Address;
#[cfg(feature = "tokio")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// SOCKS5 UDP packet header
///
/// ```plain
/// +-----+------+------+----------+----------+----------+
/// | RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +-----+------+------+----------+----------+----------+
/// |  2  |  1   |  1   | Variable |    2     | Variable |
/// +-----+------+------+----------+----------+----------+
/// ```
#[derive(Clone, Debug)]
pub struct UdpHeader {
    pub frag: u8,
    pub address: Address,
}

impl UdpHeader {
    pub fn new(frag: u8, address: Address) -> Self {
        Self { frag, address }
    }

    pub fn rebuild_from_stream<R: std::io::Read>(stream: &mut R) -> std::io::Result<Self> {
        let mut buf = [0; 3];
        stream.read_exact(&mut buf)?;

        let frag = buf[2];

        let address = Address::rebuild_from_stream(stream)?;
        Ok(Self { frag, address })
    }

    #[cfg(feature = "tokio")]
    pub async fn async_rebuild_from_stream<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Self> {
        let mut buf = [0; 3];
        r.read_exact(&mut buf).await?;

        let frag = buf[2];

        let address = Address::async_rebuild_from_stream(r).await?;
        Ok(Self { frag, address })
    }

    pub fn write_to_stream<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        let mut buf = Vec::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf)
    }

    #[cfg(feature = "tokio")]
    pub async fn async_write_to_stream<W: AsyncWrite + Unpin>(&self, w: &mut W) -> std::io::Result<()> {
        let mut buf = bytes::BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    pub fn write_to_buf<B: bytes::BufMut>(&self, buf: &mut B) {
        buf.put_bytes(0x00, 2);
        buf.put_u8(self.frag);
        self.address.write_to_buf(buf);
    }

    pub fn serialized_len(&self) -> usize {
        3 + self.address.serialized_len()
    }

    pub const fn max_serialized_len() -> usize {
        3 + Address::max_serialized_len()
    }
}
