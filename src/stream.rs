use std::io::{Read, Write};

pub trait StreamOperation {
    fn retrieve_from_stream<R>(stream: &mut R) -> std::io::Result<Self>
    where
        R: Read,
        Self: Sized;

    fn write_to_stream<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let mut buffer = bytes::BytesMut::with_capacity(self.len());
        self.write_to_buf(&mut buffer);
        writer.write_all(&buffer)
    }

    fn write_to_buf<B: bytes::BufMut>(&self, buffer: &mut B);

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(feature = "tokio")]
#[async_trait::async_trait]
pub trait AsyncStreamOperation: StreamOperation {
    async fn retrieve_from_async_stream<R>(reader: &mut R) -> std::io::Result<Self>
    where
        R: tokio::io::AsyncRead + Unpin + Send + ?Sized,
        Self: Sized;

    async fn write_to_async_stream<W>(&self, writer: &mut W) -> std::io::Result<()>
    where
        W: tokio::io::AsyncWrite + Unpin + Send + ?Sized,
    {
        use tokio::io::AsyncWriteExt;

        let mut buffer = bytes::BytesMut::with_capacity(self.len());
        self.write_to_buf(&mut buffer);
        writer.write_all(&buffer).await
    }
}
