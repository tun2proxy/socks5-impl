use crate::protocol::{AuthMethod, SOCKS_VERSION};
#[cfg(feature = "tokio")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// SOCKS5 handshake request
///
/// ```plain
/// +-----+----------+----------+
/// | VER | NMETHODS | METHODS  |
/// +-----+----------+----------+
/// |  1  |    1     | 1 to 255 |
/// +-----+----------+----------|
/// ```
#[derive(Clone, Debug)]
pub struct Request {
    pub methods: Vec<AuthMethod>,
}

impl Request {
    pub fn new(methods: Vec<AuthMethod>) -> Self {
        Self { methods }
    }

    #[cfg(feature = "tokio")]
    pub async fn rebuild_from_stream<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Self> {
        let ver = r.read_u8().await?;

        if ver != SOCKS_VERSION {
            let err = format!("Unsupported SOCKS version {0:#x}", ver);
            return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, err));
        }

        let mlen = r.read_u8().await?;
        let mut methods = vec![0; mlen as usize];
        r.read_exact(&mut methods).await?;

        let methods = methods.into_iter().map(AuthMethod::from).collect();

        Ok(Self { methods })
    }

    #[cfg(feature = "tokio")]
    pub async fn write_to_stream<W: AsyncWrite + Unpin>(&self, w: &mut W) -> std::io::Result<()> {
        let mut buf = bytes::BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    pub fn write_to_buf<B: bytes::BufMut>(&self, buf: &mut B) {
        buf.put_u8(SOCKS_VERSION);
        buf.put_u8(self.methods.len() as u8);

        let methods = self.methods.iter().map(u8::from).collect::<Vec<u8>>();
        buf.put_slice(&methods);
    }

    pub fn serialized_len(&self) -> usize {
        2 + self.methods.len()
    }
}
