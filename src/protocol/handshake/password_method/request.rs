use super::UserKey;
#[cfg(feature = "tokio")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// SOCKS5 password handshake request
///
/// ```plain
/// +-----+------+----------+------+----------+
/// | VER | ULEN |  UNAME   | PLEN |  PASSWD  |
/// +-----+------+----------+------+----------+
/// |  1  |  1   | 1 to 255 |  1   | 1 to 255 |
/// +-----+------+----------+------+----------+
/// ```

#[derive(Clone, Debug)]
pub struct Request {
    pub user_key: UserKey,
}

impl Request {
    pub fn new(username: &str, password: &str) -> Self {
        let user_key = UserKey::new(username, password);
        Self { user_key }
    }

    #[cfg(feature = "tokio")]
    pub async fn rebuild_from_stream<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Self> {
        let ver = r.read_u8().await?;

        if ver != super::SUBNEGOTIATION_VERSION {
            let err = format!("Unsupported sub-negotiation version {0:#x}", ver);
            return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, err));
        }

        let ulen = r.read_u8().await?;
        let mut buf = vec![0; ulen as usize + 1];
        r.read_exact(&mut buf).await?;

        let plen = buf[ulen as usize];
        buf.truncate(ulen as usize);
        let username = String::from_utf8(buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let mut password = vec![0; plen as usize];
        r.read_exact(&mut password).await?;
        let pwd = String::from_utf8(password).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let user_key = UserKey::new(username, pwd);
        Ok(Self { user_key })
    }

    #[cfg(feature = "tokio")]
    pub async fn write_to_stream<W: AsyncWrite + Unpin>(&self, w: &mut W) -> std::io::Result<()> {
        let mut buf = bytes::BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    pub fn write_to_buf<B: bytes::BufMut>(&self, buf: &mut B) {
        buf.put_u8(super::SUBNEGOTIATION_VERSION);

        let username = self.user_key.username_arr();
        buf.put_u8(username.len() as u8);
        buf.put_slice(&username);

        let password = self.user_key.password_arr();
        buf.put_u8(password.len() as u8);
        buf.put_slice(&password);
    }

    pub fn serialized_len(&self) -> usize {
        3 + self.user_key.username_arr().len() + self.user_key.password_arr().len()
    }
}
