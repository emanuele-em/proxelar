use bytes::{Buf, Bytes};
use std::{
    cmp, io,
    pin::Pin,
    task::{self, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A stream wrapper that prepends buffered bytes before delegating to the inner stream.
pub(crate) struct Rewind<T> {
    pre: Option<Bytes>,
    inner: T,
}

impl<T> Rewind<T> {
    pub(crate) const fn new_buffered(io: T, buf: Bytes) -> Self {
        Self {
            pre: Some(buf),
            inner: io,
        }
    }
}

impl<T> AsyncRead for Rewind<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(mut prefix) = self.pre.take() {
            if !prefix.is_empty() {
                let copy_len = cmp::min(prefix.len(), buf.remaining());
                buf.put_slice(&prefix[..copy_len]);
                prefix.advance(copy_len);
                if !prefix.is_empty() {
                    self.pre = Some(prefix);
                }

                return Poll::Ready(Ok(()));
            }
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for Rewind<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::IoSlice;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn reads_buffered_prefix_before_inner_stream() {
        let (mut client, server) = tokio::io::duplex(64);
        client.write_all(b"inner").await.unwrap();
        drop(client);

        let mut rewind = Rewind::new_buffered(server, Bytes::from_static(b"prefix-"));
        let mut out = Vec::new();
        rewind.read_to_end(&mut out).await.unwrap();

        assert_eq!(out, b"prefix-inner");
    }

    #[tokio::test]
    async fn reads_prefix_across_multiple_small_buffers() {
        let (_client, server) = tokio::io::duplex(64);
        let mut rewind = Rewind::new_buffered(server, Bytes::from_static(b"abcdef"));

        let mut first = [0; 2];
        rewind.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"ab");

        let mut second = [0; 3];
        rewind.read_exact(&mut second).await.unwrap();
        assert_eq!(&second, b"cde");
    }

    #[tokio::test]
    async fn empty_prefix_delegates_to_inner_stream() {
        let (mut client, server) = tokio::io::duplex(64);
        client.write_all(b"body").await.unwrap();
        drop(client);

        let mut rewind = Rewind::new_buffered(server, Bytes::new());
        let mut out = Vec::new();
        rewind.read_to_end(&mut out).await.unwrap();

        assert_eq!(out, b"body");
    }

    #[tokio::test]
    async fn writes_are_forwarded_to_inner_stream() {
        let (client, mut server) = tokio::io::duplex(64);
        let mut rewind = Rewind::new_buffered(client, Bytes::new());

        rewind.write_all(b"pi").await.unwrap();
        let mut written = rewind
            .write_vectored(&[IoSlice::new(b"n"), IoSlice::new(b"g")])
            .await
            .unwrap();
        let rest = b"ng";
        while written < rest.len() {
            let n = rewind.write(&rest[written..]).await.unwrap();
            assert!(n > 0);
            written += n;
        }
        rewind.flush().await.unwrap();
        rewind.shutdown().await.unwrap();

        let mut out = Vec::new();
        server.read_to_end(&mut out).await.unwrap();

        assert_eq!(out, b"ping");
    }
}
