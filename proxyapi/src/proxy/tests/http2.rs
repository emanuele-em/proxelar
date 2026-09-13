use super::*;
use crate::proxy::test_support::{request, Context};
use proxelar_proto::ProxyBody;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn service(context: &Context) -> ForwardH2Service {
    let pool = context.pool();
    ForwardH2Service {
        scheme: Scheme::HTTP,
        remote_addr: "127.0.0.1:12345".parse().unwrap(),
        handler: context.handler.clone(),
        ca: context.ca.clone(),
        native_pool: Some(pool.clone()),
        route: None,
        upstream: NativeUpstream::shared(pool, None),
        listen_addr: "127.0.0.1:8080".parse().unwrap(),
    }
}

#[tokio::test]
async fn forward_certificate_and_failed_upstream_responses() {
    let context = Context::new();
    for uri in ["http://proxel.ar/", "http://proxel.ar/cert/pem"] {
        let response = service(&context)
            .handle(request(Method::GET, uri))
            .await
            .unwrap();
        assert!(response.head.status.is_success());
        assert!(!response.body.collect().await.unwrap().data.is_empty());
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let response = service(&context)
        .handle(request(Method::GET, &format!("http://{addr}/")))
        .await
        .unwrap();
    assert_eq!(response.head.status, StatusCode::BAD_GATEWAY);
    assert_eq!(response.body.collect().await.unwrap().data, "Bad Gateway");
    let mut connect = request(Method::CONNECT, "/");
    connect.head.headers.add("host", "example.test").unwrap();
    assert!(service(&context).handle(connect).await.is_err());
}

#[tokio::test]
async fn extended_websocket_rejects_bad_version_and_unreachable_upstream() {
    let context = Context::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    for (version, expected) in [
        ("12", StatusCode::BAD_REQUEST),
        ("13", StatusCode::BAD_GATEWAY),
    ] {
        let mut req = request(Method::CONNECT, &format!("http://{addr}/ws"));
        req.head.headers.add(":protocol", "websocket").unwrap();
        req.head
            .headers
            .add("sec-websocket-version", version)
            .unwrap();
        let response = service(&context).handle(req).await.unwrap();
        assert_eq!(response.head.status, expected);
        assert!(!response.body.collect().await.unwrap().data.is_empty());
    }
}

#[tokio::test]
async fn reverse_reports_uri_rewrite_and_connection_failures() {
    let context = Context::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    for target in [
        "example.test:80".to_owned(),
        "/missing-authority".to_owned(),
        format!("http://{addr}/"),
    ] {
        for websocket in [false, true] {
            let mut service = ReverseH2Service {
                remote_addr: "127.0.0.1:12345".parse().unwrap(),
                handler: context.handler.clone(),
                target: target.parse().unwrap(),
                upstream: NativeUpstream::shared(context.pool(), None),
            };
            let mut req = request(
                if websocket {
                    Method::CONNECT
                } else {
                    Method::GET
                },
                "http://example.test/path",
            );
            if websocket {
                req.head.headers.add(":protocol", "websocket").unwrap();
                req.head.headers.add("sec-websocket-version", "13").unwrap();
            }
            let response = service.call(req).await.unwrap();
            assert_eq!(response.head.status, StatusCode::BAD_GATEWAY);
            assert!(response
                .body
                .collect()
                .await
                .unwrap()
                .data
                .starts_with(b"Bad Gateway"));
        }
    }
}

#[tokio::test]
async fn connect_carries_plain_http_tls_http1_and_tls_http2() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let context = Context::new();
        for protocol in [b"".as_slice(), b"http/1.1", b"h2"] {
            let (mut client, tunnel) = tokio::io::duplex(65536);
            let task = tokio::spawn(handle_connect_tunnel(tunnel, "proxel.ar:443".parse().unwrap(), service(&context)));
            if protocol.is_empty() {
                client.write_all(b"GET http://proxel.ar/ HTTP/1.1\r\nHost: proxel.ar\r\nConnection: close\r\n\r\n").await.unwrap();
                let mut response = Vec::new();
                client.read_to_end(&mut response).await.unwrap();
                assert!(response.starts_with(b"HTTP/1.1 200"));
            } else {
                let mut tls = context.tls.clone();
                tls.alpn_protocols = vec![protocol.to_vec()];
                let stream = tokio_rustls::TlsConnector::from(Arc::new(tls)).connect("proxel.ar".try_into().unwrap(), client).await.unwrap();
                if protocol == b"h2" {
                    let client = proxelar_proto::http2::H2Client::handshake(stream, ConnectionConfig::default()).await.unwrap();
                    let response = client.send_request(request(Method::GET, "https://proxel.ar/")).await.unwrap();
                    assert_eq!(response.head.status, StatusCode::OK);
                    assert!(!response.body.collect().await.unwrap().data.is_empty());
                } else {
                    let mut stream = stream;
                    stream.write_all(b"GET / HTTP/1.1\r\nHost: proxel.ar\r\nConnection: close\r\n\r\n").await.unwrap();
                    let mut response = Vec::new();
                    // HTTP closes without necessarily sending a TLS close_notify.
                    let _ = stream.read_to_end(&mut response).await;
                    assert!(response.starts_with(b"HTTP/1.1 200"));
                }
            }
            task.abort();
        }
    }).await.unwrap();
}

#[tokio::test]
async fn connect_raw_stream_preserves_bytes_and_eof() {
    let mut context = Context::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = listener.local_addr().unwrap().to_string().parse().unwrap();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = [0; 4];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"\x00raw");
        stream.write_all(b"reply").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let (mut client, tunnel) = tokio::io::duplex(65536);
    let task = tokio::spawn(handle_connect_tunnel(tunnel, authority, service(&context)));
    client.write_all(b"\x00raw").await.unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response, b"reply");
    echo.await.unwrap();
    task.await.unwrap();
    assert!(matches!(
        context.events.recv().await,
        Some(crate::ProxyEvent::TcpConnected { .. })
    ));
}

#[tokio::test]
async fn websocket_rejection_from_upstream_is_forwarded() {
    let context = Context::new();
    let (io, mut peer) = tokio::io::duplex(65536);
    let upstream = NativeUpstream::pinned(io, "example.test:80".parse().unwrap());
    let server = tokio::spawn(async move {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(peer.read_u8().await.unwrap());
        }
        let head = String::from_utf8(bytes).unwrap();
        assert!(head.starts_with("GET /ws HTTP/1.1"));
        assert!(head.to_ascii_lowercase().contains("upgrade: websocket"));
        peer.write_all(
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndenied",
        )
        .await
        .unwrap();
    });
    let mut req = request(Method::CONNECT, "http://example.test/ws");
    req.head.headers.add(":protocol", "websocket").unwrap();
    req.head.headers.add("sec-websocket-version", "13").unwrap();
    req.body = ProxyBody::empty();
    let response = handle_extended_websocket(
        req,
        context.handler,
        upstream,
        "127.0.0.1:1".parse().unwrap(),
        None,
    )
    .await
    .unwrap();
    assert_eq!(response.head.status, StatusCode::FORBIDDEN);
    assert_eq!(response.body.collect().await.unwrap().data, "denied");
    server.await.unwrap();
}

#[tokio::test]
async fn request_rules_short_circuit_forward_reverse_and_websocket_requests() {
    let mut context = Context::new();
    context.handler = context
        .handler
        .with_route_rules(Arc::new(crate::rules::RouteRules {
            rules: vec![crate::rules::RouteRule::Mock {
                url_prefix: "http://example.test/".to_owned(),
                method: None,
                status: 418,
                headers: Vec::new(),
                body: "local response".to_owned(),
            }],
        }));
    for reverse in [false, true] {
        for websocket in [false, true] {
            let mut req = request(
                if websocket {
                    Method::CONNECT
                } else {
                    Method::GET
                },
                "http://example.test/path",
            );
            if websocket {
                req.head.headers.add(":protocol", "websocket").unwrap();
                req.head.headers.add("sec-websocket-version", "13").unwrap();
            }
            let response = if reverse {
                let mut service = ReverseH2Service {
                    remote_addr: "127.0.0.1:1".parse().unwrap(),
                    handler: context.handler.clone(),
                    target: "http://unreachable.invalid/".parse().unwrap(),
                    upstream: NativeUpstream::shared(context.pool(), None),
                };
                service.call(req).await.unwrap()
            } else {
                service(&context).handle(req).await.unwrap()
            };
            assert_eq!(response.head.status, StatusCode::IM_A_TEAPOT);
            assert_eq!(
                response.body.collect().await.unwrap().data,
                "local response"
            );
        }
    }
}

#[tokio::test]
async fn failed_connect_handshakes_and_unavailable_nested_h2_close_cleanly() {
    let context = Context::new();
    let reserved = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = reserved
        .local_addr()
        .unwrap()
        .to_string()
        .parse::<Authority>()
        .unwrap();
    drop(reserved);
    for bytes in [
        b"\x16\x03\x03\x00\x10bad".as_slice(),
        b"\0raw",
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
    ] {
        let (mut client, tunnel) = tokio::io::duplex(1024);
        let mut service = service(&context);
        service.native_pool = None;
        let task = tokio::spawn(handle_connect_tunnel(tunnel, authority.clone(), service));
        client.write_all(bytes).await.unwrap();
        client.shutdown().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        let mut remaining = Vec::new();
        client.read_to_end(&mut remaining).await.unwrap();
    }
}
