#[cfg(feature = "tokio")]
use crate::protocol::AsyncStreamOperation;
use crate::protocol::{Address, Reply, StreamOperation, SOCKS_VERSION_V5};
#[cfg(feature = "tokio")]
use async_trait::async_trait;
#[cfg(feature = "tokio")]
use tokio::io::{AsyncRead, AsyncReadExt};

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
}

impl StreamOperation for Response {
    fn retrieve_from_stream<R: std::io::Read>(stream: &mut R) -> std::io::Result<Self> {
        let mut ver = [0u8; 1];
        stream.read_exact(&mut ver)?;
        let ver = ver[0];

        if ver != SOCKS_VERSION_V5 {
            let err = format!("Unsupported SOCKS version {0:#x}", ver);
            return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, err));
        }

        let mut buf = [0; 2];
        stream.read_exact(&mut buf)?;

        let reply = Reply::try_from(buf[0])?;
        let address = Address::retrieve_from_stream(stream)?;

        Ok(Self { reply, address })
    }

    fn write_to_buf<B: bytes::BufMut>(&self, buf: &mut B) {
        buf.put_u8(SOCKS_VERSION_V5);
        buf.put_u8(u8::from(self.reply));
        buf.put_u8(0x00);
        self.address.write_to_buf(buf);
    }

    fn len(&self) -> usize {
        3 + self.address.len()
    }
}

#[cfg(feature = "tokio")]
#[async_trait]
impl AsyncStreamOperation for Response {
    async fn retrieve_from_async_stream<R>(r: &mut R) -> std::io::Result<Self>
    where
        R: AsyncRead + Unpin + Send,
    {
        let ver = r.read_u8().await?;

        if ver != SOCKS_VERSION_V5 {
            let err = format!("Unsupported SOCKS version {0:#x}", ver);
            return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, err));
        }

        let mut buf = [0; 2];
        r.read_exact(&mut buf).await?;

        let reply = Reply::try_from(buf[0])?;
        let address = Address::retrieve_from_async_stream(r).await?;

        Ok(Self { reply, address })
    }
}
