use super::*;
use crate::proxy::test_support::Context;
use crate::ProxyEvent;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::{protocol::Role, Message};
use tokio_tungstenite::WebSocketStream;

#[tokio::test]
async fn reverse_http1_websocket_relays_frames_and_records_lifecycle() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut context = Context::new();
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = format!("http://{}/", origin.local_addr().unwrap())
            .parse()
            .unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") { head.push(stream.read_u8().await.unwrap()); }
            assert!(head.starts_with(b"GET /chat HTTP/1.1"));
            stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n").await.unwrap();
            let mut ws = WebSocketStream::from_raw_socket(stream, Role::Server, None).await;
            assert_eq!(
                ws.next().await.unwrap().unwrap(),
                Message::Text("request".into())
            );
            ws.send(Message::Text("response".into())).await.unwrap();
            assert!(ws.next().await.unwrap().unwrap().is_close());
            let _ = ws.close(None).await;
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = ReverseConnectionConfig::new(
            target,
            context.ca.clone(),
            context.pool(),
            None,
            super::super::outbound::OutboundConnector::new(None),
            Arc::new(context.tls.clone()),
        );
        let handler = context.handler.clone();
        let task = tokio::spawn(async move {
            let (stream, remote) = listener.accept().await.unwrap();
            handle_connection(stream, remote, handler, config).await;
        });
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(format!("GET /chat HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").as_bytes()).await.unwrap();
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") { response.push(stream.read_u8().await.unwrap()); }
        assert!(response.starts_with(b"HTTP/1.1 101"));
        let mut ws = WebSocketStream::from_raw_socket(stream, Role::Client, None).await;
        ws.send(Message::Text("request".into())).await.unwrap();
        assert_eq!(
            ws.next().await.unwrap().unwrap(),
            Message::Text("response".into())
        );
        ws.close(None).await.unwrap();
        echo.await.unwrap();
        task.await.unwrap();
        let mut connected = false;
        let mut closed = false;
        let mut frames = Vec::new();
        while let Ok(event) = context.events.try_recv() {
            match event {
                ProxyEvent::WebSocketConnected { request, .. } => {
                    connected = true;
                    assert_eq!(request.uri().path(), "/chat");
                }
                ProxyEvent::WebSocketClosed { .. } => closed = true,
                ProxyEvent::WebSocketFrame { frame, .. } => frames.push(frame.payload.clone()),
                _ => {}
            }
        }
        assert!(connected && closed);
        assert!(frames.iter().any(|payload| payload.as_ref() == b"request"));
        assert!(frames.iter().any(|payload| payload.as_ref() == b"response"));
    })
    .await
    .unwrap();
}
