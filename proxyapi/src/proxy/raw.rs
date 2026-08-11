use std::io;

use proxyapi_models::{StreamDirection, TcpChunk};
use rama::bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::event::{next_id, ProxyEvent};
use crate::handler::now_millis;

const MAX_CAPTURE_BYTES_PER_DIRECTION: usize = 10 * 1024 * 1024;

pub async fn tunnel<C, U>(
    client: C,
    upstream: U,
    target: String,
    event_tx: mpsc::Sender<ProxyEvent>,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let id = next_id();
    let _ = event_tx.try_send(ProxyEvent::TcpConnected {
        id,
        target,
        opened_at: now_millis(),
    });
    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);
    let client_to_server = copy_and_capture(
        client_read,
        upstream_write,
        event_tx.clone(),
        id,
        StreamDirection::ClientToServer,
    );
    let server_to_client = copy_and_capture(
        upstream_read,
        client_write,
        event_tx.clone(),
        id,
        StreamDirection::ServerToClient,
    );
    let (client_result, server_result) = tokio::join!(client_to_server, server_to_client);
    let _ = event_tx.try_send(ProxyEvent::TcpClosed { stream_id: id });
    client_result.and(server_result).map(|_| ())
}

async fn copy_and_capture<R, W>(
    mut reader: R,
    mut writer: W,
    event_tx: mpsc::Sender<ProxyEvent>,
    stream_id: u64,
    direction: StreamDirection,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0_u64;
    let mut captured = 0_usize;
    let mut emitted_truncation = false;
    let mut buffer = vec![0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(total);
        }
        writer.write_all(&buffer[..read]).await?;
        total = total.saturating_add(read as u64);
        let remaining = MAX_CAPTURE_BYTES_PER_DIRECTION.saturating_sub(captured);
        let capture_length = read.min(remaining);
        if capture_length > 0 || !emitted_truncation {
            let truncated = capture_length < read || remaining == 0;
            let _ = event_tx.try_send(ProxyEvent::TcpData {
                stream_id,
                chunk: Box::new(TcpChunk {
                    direction,
                    time: now_millis(),
                    payload: Bytes::copy_from_slice(&buffer[..capture_length]),
                    truncated,
                }),
            });
            captured += capture_length;
            emitted_truncation |= truncated;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tunnels_and_emits_bidirectional_chunks() {
        let (client_side, proxy_client) = tokio::io::duplex(1024);
        let (proxy_upstream, upstream_side) = tokio::io::duplex(1024);
        let (events, mut event_rx) = mpsc::channel(16);
        let tunnel = tokio::spawn(tunnel(
            proxy_client,
            proxy_upstream,
            "example.test:9000".to_owned(),
            events,
        ));
        let (mut client_read, mut client_write) = tokio::io::split(client_side);
        let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream_side);

        client_write.write_all(b"hello").await.unwrap();
        let mut request = [0_u8; 5];
        upstream_read.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"hello");
        upstream_write.write_all(b"world").await.unwrap();
        let mut response = [0_u8; 5];
        client_read.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"world");
        drop(client_write);
        drop(client_read);
        drop(upstream_write);
        drop(upstream_read);
        tunnel.await.unwrap().unwrap();

        let mut directions = Vec::new();
        while let Ok(event) = event_rx.try_recv() {
            if let ProxyEvent::TcpData { chunk, .. } = event {
                directions.push(chunk.direction);
            }
        }
        assert!(directions.contains(&StreamDirection::ClientToServer));
        assert!(directions.contains(&StreamDirection::ServerToClient));
    }
}
