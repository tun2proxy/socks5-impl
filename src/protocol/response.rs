use crate::protocol::{Address, Reply, SOCKS_VERSION};
#[cfg(feature = "tokio")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Response
///
/// ```plain
/// +-----+-----+-------+------+----------+----------+
/// | VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
/// +-----+-----+-------+------+----------+----------+
/// |  1  |  1  | X'00' |  1   | Variable |    2     |
/// +-----+-----+-------+------+----------+----------+
/// ```
#[derive(Clone, Debug)]
pub struct Response {
    pub reply: Reply,
    pub address: Address,
}

impl Response {
    pub fn new(reply: Reply, address: Address) -> Self {
        Self { reply, address }
    }

    pub fn rebuild_from_stream<R: std::io::Read>(stream: &mut R) -> std::io::Result<Self> {
        let mut ver = [0u8; 1];
        stream.read_exact(&mut ver)?;
        let ver = ver[0];

        if ver != SOCKS_VERSION {
            let err = format!("Unsupported SOCKS version {0:#x}", ver);
            return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, err));
        }

        let mut buf = [0; 2];
        stream.read_exact(&mut buf)?;

        let reply = Reply::try_from(buf[0])?;
        let address = Address::rebuild_from_stream(stream)?;

        Ok(Self { reply, address })
    }

    #[cfg(feature = "tokio")]
    pub async fn async_rebuild_from_stream<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Self> {
        let ver = r.read_u8().await?;

        if ver != SOCKS_VERSION {
            let err = format!("Unsupported SOCKS version {0:#x}", ver);
            return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, err));
        }

        let mut buf = [0; 2];
        r.read_exact(&mut buf).await?;

        let reply = Reply::try_from(buf[0])?;
        let address = Address::async_rebuild_from_stream(r).await?;

        Ok(Self { reply, address })
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
        buf.put_u8(SOCKS_VERSION);
        buf.put_u8(u8::from(self.reply));
        buf.put_u8(0x00);
        self.address.write_to_buf(buf);
    }

    pub fn serialized_len(&self) -> usize {
        3 + self.address.serialized_len()
    }
}
