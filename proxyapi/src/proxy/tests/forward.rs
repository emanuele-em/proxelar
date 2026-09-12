use super::*;
use crate::proxy::test_support::{request, Context};
use tokio::io::AsyncWriteExt;

async fn inspect_certificate<I>(mut client: I, h2: bool)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if h2 {
        let client = proxelar_proto::http2::H2Client::handshake(client, Default::default())
            .await
            .unwrap();
        let response = client
            .send_request(request(Method::GET, "https://proxel.ar/"))
            .await
            .unwrap();
        assert_eq!(response.head.status, http::StatusCode::OK);
        assert!(!response.body.collect().await.unwrap().data.is_empty());
    } else {
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: proxel.ar\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        let _ = client.read_to_end(&mut response).await;
        assert!(response.starts_with(b"HTTP/1.1 200"));
        assert!(response.windows(5).any(|bytes| bytes == b"<html"));
    }
}

#[tokio::test]
async fn native_connect_and_captured_stream_inspect_each_tcp_http_protocol() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let context = Context::new();
        for captured in [false, true] {
            for tls in [false, true] {
                for h2 in [false, true] {
                    let (client, server) = tokio::io::duplex(65536);
                    let pool = context.pool();
                    let handler = context.handler.clone();
                    let ca = context.ca.clone();
                    let remote = "127.0.0.1:23456".parse().unwrap();
                    let listen = "127.0.0.1:8080".parse().unwrap();
                    let authority = "proxel.ar:443".parse().unwrap();
                    let task = tokio::spawn(async move {
                        if captured {
                            handle_captured_stream(
                                server, remote, handler, ca, pool, None, listen, authority,
                            )
                            .await;
                        } else {
                            handle_native_connect(
                                proxelar_proto::http1::UpgradedIo {
                                    io: Box::new(server) as BoxIo,
                                    read_ahead: Bytes::new(),
                                },
                                authority,
                                handler,
                                ca,
                                NativeUpstream::shared(pool, None),
                                remote,
                                listen,
                            )
                            .await;
                        }
                    });
                    if tls {
                        let mut config = context.tls.clone();
                        config.alpn_protocols = vec![if h2 {
                            b"h2".to_vec()
                        } else {
                            b"http/1.1".to_vec()
                        }];
                        let client = tokio_rustls::TlsConnector::from(Arc::new(config))
                            .connect("proxel.ar".try_into().unwrap(), client)
                            .await
                            .unwrap();
                        inspect_certificate(client, h2).await;
                    } else {
                        inspect_certificate(client, h2).await;
                    }
                    task.abort();
                }
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn captured_raw_stream_forwards_initial_bytes_and_records_close() {
    let mut context = Context::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = listener.local_addr().unwrap().to_string().parse().unwrap();
    let echo = tokio::spawn(async move {
        let (mut peer, _) = listener.accept().await.unwrap();
        let mut data = Vec::new();
        peer.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"\0opaque");
        peer.write_all(b"echo").await.unwrap();
    });
    let (mut client, server) = tokio::io::duplex(65536);
    let task = tokio::spawn(handle_captured_stream(
        server,
        "127.0.0.1:23456".parse().unwrap(),
        context.handler.clone(),
        context.ca.clone(),
        context.pool(),
        None,
        "127.0.0.1:8080".parse().unwrap(),
        authority,
    ));
    client.write_all(b"\0opaque").await.unwrap();
    client.shutdown().await.unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bytes, b"echo");
    echo.await.unwrap();
    task.await.unwrap();
    let mut closed = false;
    while let Ok(event) = context.events.try_recv() {
        closed |= matches!(event, ProxyEvent::TcpClosed { .. });
    }
    assert!(closed);
}

#[tokio::test]
async fn truncated_tls_handshakes_close_native_and_captured_streams() {
    let context = Context::new();
    for captured in [false, true] {
        let (mut client, server) = tokio::io::duplex(1024);
        let pool = context.pool();
        let ca = context.ca.clone();
        let handler = context.handler.clone();
        let task = tokio::spawn(async move {
            let remote = "127.0.0.1:23456".parse().unwrap();
            let listen = "127.0.0.1:8080".parse().unwrap();
            let authority = "proxel.ar:443".parse().unwrap();
            if captured {
                handle_captured_stream(server, remote, handler, ca, pool, None, listen, authority)
                    .await;
            } else {
                handle_native_connect(
                    proxelar_proto::http1::UpgradedIo {
                        io: Box::new(server) as BoxIo,
                        read_ahead: Bytes::new(),
                    },
                    authority,
                    handler,
                    ca,
                    NativeUpstream::shared(pool, None),
                    remote,
                    listen,
                )
                .await;
            }
        });
        client.write_all(b"\x16\x03\x03\x00\x10bad").await.unwrap();
        client.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }
}

#[test]
fn direct_certificate_routing_distinguishes_local_authorities() {
    for (listen, host, expected) in [
        ("127.0.0.1:8080", "localhost:8080", true),
        ("0.0.0.0:8080", "127.0.0.1:8080", true),
        ("192.0.2.1:8080", "localhost:8080", false),
        ("127.0.0.1:8080", "localhost:80", false),
        ("127.0.0.1:8080", "example.test:8080", false),
        ("127.0.0.1:8080", "invalid host", false),
    ] {
        let mut req = request(Method::GET, "/");
        req.head.headers.add("host", host).unwrap();
        assert_eq!(
            is_direct_cert_protocol_request(&req, listen.parse().unwrap()),
            expected,
            "{listen} {host}"
        );
    }
    let mut req = request(Method::GET, "/");
    req.head.headers.add("host", b"\xff").unwrap();
    assert!(!is_direct_cert_protocol_request(
        &req,
        "127.0.0.1:8080".parse().unwrap()
    ));
}

#[tokio::test]
async fn pinned_stream_preserves_destination_for_http1_and_http2() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let context = Context::new();
        for h2 in [false, true] {
            let (client, server) = tokio::io::duplex(65536);
            let (upstream, mut peer) = tokio::io::duplex(65536);
            let origin = tokio::spawn(async move {
                let mut bytes = Vec::new();
                while !bytes.ends_with(b"\r\n\r\n") {
                    bytes.push(peer.read_u8().await.unwrap());
                }
                let head = String::from_utf8(bytes).unwrap().to_ascii_lowercase();
                assert!(head.starts_with("get /pinned http/1.1"));
                assert!(head.contains("host: pinned.test:80"));
                assert!(!head.contains("wrong.test"));
                peer.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\npinned",
                )
                .await
                .unwrap();
            });
            let task = tokio::spawn(serve_pinned_stream(
                server,
                upstream,
                "pinned.test:80".parse().unwrap(),
                Scheme::HTTP,
                context.handler.clone(),
                context.ca.clone(),
                "127.0.0.1:2".parse().unwrap(),
                "127.0.0.1:8080".parse().unwrap(),
            ));
            if h2 {
                let client = proxelar_proto::http2::H2Client::handshake(client, Default::default())
                    .await
                    .unwrap();
                let response = client
                    .send_request(request(Method::GET, "http://wrong.test/pinned"))
                    .await
                    .unwrap();
                assert_eq!(response.body.collect().await.unwrap().data, "pinned");
            } else {
                let mut client = client;
                client
                    .write_all(
                        b"GET /pinned HTTP/1.1\r\nHost: wrong.test\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
                let mut bytes = Vec::new();
                client.read_to_end(&mut bytes).await.unwrap();
                assert!(bytes.ends_with(b"pinned"));
            }
            origin.await.unwrap();
            task.abort();
        }
    })
    .await
    .unwrap();
}

#[cfg(feature = "scripting")]
#[test]
fn websocket_lua_handles_control_frames_drop_and_errors() {
    let scripts = [
        ("function on_websocket_frame(f) return false end", None),
        (
            "function on_websocket_frame(f) return 'edited' end",
            Some("edited"),
        ),
        (
            "function on_websocket_frame(f) error('hook failed') end",
            Some("original"),
        ),
    ];
    for (script, expected) in scripts {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), script).unwrap();
        let engine = crate::scripting::ScriptEngine::new(file.path()).unwrap();
        for frame in [
            Message::Text("original".into()),
            Message::Binary(Bytes::from_static(b"original")),
            Message::Ping(Bytes::from_static(b"original")),
            Message::Pong(Bytes::from_static(b"original")),
        ] {
            for direction in [WsDirection::ClientToServer, WsDirection::ServerToClient] {
                let result = transform_ws_frame(frame.clone(), direction, Some(&engine));
                match expected {
                    Some(payload) => assert_eq!(result.unwrap().into_data(), payload.as_bytes()),
                    None => assert!(result.is_none()),
                }
            }
        }
        assert_eq!(
            transform_ws_frame(
                Message::Close(None),
                WsDirection::ClientToServer,
                Some(&engine)
            ),
            Some(Message::Close(None))
        );
    }
}
