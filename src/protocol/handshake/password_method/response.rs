#[cfg(feature = "tokio")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// SOCKS5 password handshake response
///
/// ```plain
/// +-----+--------+
/// | VER | STATUS |
/// +-----+--------+
/// |  1  |   1    |
/// +-----+--------+
/// ```

#[derive(Clone, Debug)]
pub struct Response {
    pub status: bool,
}

impl Response {
    const STATUS_FAILED: u8 = 0xff;
    const STATUS_SUCCEEDED: u8 = 0x00;

    pub fn new(status: bool) -> Self {
        Self { status }
    }

    pub fn rebuild_from_stream<R: std::io::Read>(r: &mut R) -> std::io::Result<Self> {
        let mut ver = [0; 1];
        r.read_exact(&mut ver)?;
        let ver = ver[0];

        if ver != super::SUBNEGOTIATION_VERSION {
            let err = format!("Unsupported sub-negotiation version {0:#x}", ver);
            return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, err));
        }

        let mut status = [0; 1];
        r.read_exact(&mut status)?;
        let status = status[0];

        match status {
            Self::STATUS_FAILED => Ok(Self { status: false }),
            Self::STATUS_SUCCEEDED => Ok(Self { status: true }),
            code => {
                let err = format!("Invalid sub-negotiation status {0:#x}", code);
                Err(std::io::Error::new(std::io::ErrorKind::InvalidData, err))
            }
        }
    }

    #[cfg(feature = "tokio")]
    pub async fn async_rebuild_from_stream<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Self> {
        let ver = r.read_u8().await?;

        if ver != super::SUBNEGOTIATION_VERSION {
            let err = format!("Unsupported sub-negotiation version {0:#x}", ver);
            return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, err));
        }

        let status = match r.read_u8().await? {
            Self::STATUS_FAILED => false,
            Self::STATUS_SUCCEEDED => true,
            code => {
                let err = format!("Invalid sub-negotiation status {0:#x}", code);
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, err));
            }
        };

        Ok(Self { status })
    }

    pub fn write_to_stream<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        use bytes::BytesMut;
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf)
    }

    #[cfg(feature = "tokio")]
    pub async fn async_write_to_stream<W: AsyncWrite + Unpin>(&self, w: &mut W) -> std::io::Result<()> {
        use bytes::BytesMut;
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    pub fn write_to_buf<B: bytes::BufMut>(&self, buf: &mut B) {
        buf.put_u8(super::SUBNEGOTIATION_VERSION);

        if self.status {
            buf.put_u8(Self::STATUS_SUCCEEDED);
        } else {
            buf.put_u8(Self::STATUS_FAILED);
        }
    }

    pub fn serialized_len(&self) -> usize {
        2
    }
}
