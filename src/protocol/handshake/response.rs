use crate::protocol::{AuthMethod, SOCKS_VERSION};
#[cfg(feature = "tokio")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// SOCKS5 handshake response
///
/// ```plain
/// +-----+--------+
/// | VER | METHOD |
/// +-----+--------+
/// |  1  |   1    |
/// +-----+--------+
/// ```
#[derive(Clone, Debug)]
pub struct HandshakeResponse {
    pub method: AuthMethod,
}

impl HandshakeResponse {
    pub fn new(method: AuthMethod) -> Self {
        Self { method }
    }

    #[cfg(feature = "tokio")]
    pub async fn rebuild_from_stream<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Self> {
        let ver = r.read_u8().await?;

        if ver != SOCKS_VERSION {
            let err = format!("Unsupported SOCKS version {0:#x}", ver);
            return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, err));
        }

        let method = AuthMethod::from(r.read_u8().await?);

        Ok(Self { method })
    }

    #[cfg(feature = "tokio")]
    pub async fn write_to_stream<W: AsyncWrite + Unpin>(&self, w: &mut W) -> std::io::Result<()> {
        let mut buf = bytes::BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    pub fn write_to_buf<B: bytes::BufMut>(&self, buf: &mut B) {
        buf.put_u8(SOCKS_VERSION);
        buf.put_u8(u8::from(self.method));
    }

    pub fn serialized_len(&self) -> usize {
        2
    }
}
