#[cfg(feature = "tokio")]
use crate::protocol::AsyncStreamOperation;
use crate::protocol::{AuthMethod, StreamOperation, SOCKS_VERSION_V5};
#[cfg(feature = "tokio")]
use async_trait::async_trait;
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
    methods: Vec<AuthMethod>,
}

impl Request {
    pub fn new(methods: Vec<AuthMethod>) -> Self {
        Self { methods }
    }

    pub fn evaluate_method(&self, server_method: AuthMethod) -> bool {
        self.methods.iter().any(|&m| m == server_method)
    }
}

impl StreamOperation for Request {
    fn retrieve_from_stream<R: std::io::Read>(r: &mut R) -> std::io::Result<Self> {
        let mut ver = [0; 1];
        r.read_exact(&mut ver)?;
        let ver = ver[0];

        if ver != SOCKS_VERSION_V5 {
            let err = format!("Unsupported SOCKS version {0:#x}", ver);
            return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, err));
        }

        let mut mlen = [0; 1];
        r.read_exact(&mut mlen)?;
        let mlen = mlen[0];

        let mut methods = vec![0; mlen as usize];
        r.read_exact(&mut methods)?;

        let methods = methods.into_iter().map(AuthMethod::from).collect();

        Ok(Self { methods })
    }

    fn write_to_buf<B: bytes::BufMut>(&self, buf: &mut B) {
        buf.put_u8(SOCKS_VERSION_V5);
        buf.put_u8(self.methods.len() as u8);

        let methods = self.methods.iter().map(u8::from).collect::<Vec<u8>>();
        buf.put_slice(&methods);
    }

    fn len(&self) -> usize {
        2 + self.methods.len()
    }
}

#[cfg(feature = "tokio")]
#[async_trait]
impl AsyncStreamOperation for Request {
    async fn retrieve_from_async_stream<R>(r: &mut R) -> std::io::Result<Self>
    where
        R: AsyncRead + Unpin + Send,
    {
        let ver = r.read_u8().await?;

        if ver != SOCKS_VERSION_V5 {
            let err = format!("Unsupported SOCKS version {0:#x}", ver);
            return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, err));
        }

        let mlen = r.read_u8().await?;
        let mut methods = vec![0; mlen as usize];
        r.read_exact(&mut methods).await?;

        let methods = methods.into_iter().map(AuthMethod::from).collect();

        Ok(Self { methods })
    }

    async fn write_to_async_stream<W>(&self, w: &mut W) -> std::io::Result<()>
    where
        W: AsyncWrite + Unpin + Send,
    {
        let mut buf = bytes::BytesMut::with_capacity(self.len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }
}
