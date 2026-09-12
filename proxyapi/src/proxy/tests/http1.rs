use super::*;
use crate::ca::CertificateAuthority;
use crate::proxy::test_support::{request, Context};
use bytes::Bytes;
use http::StatusCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn shared_https_connector_uses_http1_and_normalizes_wire_headers() {
    for address in ["127.0.0.1:0", "[::1]:0"] {
        for negotiated in [false, true] {
            https_connector_roundtrip(address, negotiated).await;
        }
    }
}

async fn https_connector_roundtrip(address: &str, negotiated: bool) {
    let context = Context::new();
    let listener = tokio::net::TcpListener::bind(address).await.unwrap();
    let authority: Authority = listener.local_addr().unwrap().to_string().parse().unwrap();
    let config = context.ca.gen_server_config(&authority).await.unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = tokio_rustls::TlsAcceptor::from(config)
            .accept(stream)
            .await
            .unwrap();
        assert_eq!(
            stream.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_slice())
        );
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(stream.read_u8().await.unwrap());
        }
        let head = String::from_utf8(bytes).unwrap().to_ascii_lowercase();
        assert!(head.starts_with("get /path?q=1 http/1.1"));
        assert!(head.contains("cookie: a=1; b=2"));
        assert!(!head.contains("proxy-authorization"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });
    let upstream = if negotiated {
        NativeUpstream::negotiated(
            OutboundConnector::new(None),
            context.tls.clone(),
            vec![b"http/1.1".to_vec()],
        )
    } else {
        NativeUpstream::shared(context.pool(), None)
    };
    let mut req = request(Method::GET, &format!("https://{authority}/path?q=1"));
    req.head.headers.add("cookie", "a=1").unwrap();
    req.head.headers.add("cookie", "b=2").unwrap();
    req.head
        .headers
        .add("proxy-authorization", "Basic secret")
        .unwrap();
    let response = upstream.send(req, false).await.unwrap().response;
    assert_eq!(response.head.status, StatusCode::OK);
    assert_eq!(response.body.collect().await.unwrap().data, "ok");
    server.await.unwrap();
}

#[tokio::test]
async fn negotiated_http1_websocket_reuses_connection_after_rejection() {
    let context = Context::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority: Authority = listener.local_addr().unwrap().to_string().parse().unwrap();
    let config = context.ca.gen_server_config(&authority).await.unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = tokio_rustls::TlsAcceptor::from(config)
            .accept(stream)
            .await
            .unwrap();
        for _ in 0..2 {
            let mut bytes = Vec::new();
            while !bytes.ends_with(b"\r\n\r\n") {
                bytes.push(stream.read_u8().await.unwrap());
            }
            let head = String::from_utf8(bytes).unwrap().to_ascii_lowercase();
            assert!(head.starts_with("get /ws http/1.1"));
            assert!(head.contains("sec-websocket-key:"));
            assert!(!head.contains(":protocol"));
            stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\n\r\ndenied")
                .await
                .unwrap();
        }
    });
    let upstream = NativeUpstream::negotiated(
        OutboundConnector::new(None),
        context.tls,
        vec![b"http/1.1".to_vec()],
    );
    for _ in 0..2 {
        let mut req = request(Method::CONNECT, &format!("https://{authority}/ws"));
        req.head.headers.add(":protocol", "websocket").unwrap();
        req.head.headers.add("sec-websocket-version", "13").unwrap();
        let NativeWebSocketResponse::Http1(result) = upstream.send_websocket(req).await.unwrap()
        else {
            panic!("expected an HTTP/1 upstream");
        };
        assert_eq!(result.response.head.status, StatusCode::FORBIDDEN);
        assert_eq!(result.response.body.collect().await.unwrap().data, "denied");
    }
    server.await.unwrap();
}

#[tokio::test]
async fn closed_negotiated_http1_client_is_evicted() {
    let context = Context::new();
    let (io, peer) = tokio::io::duplex(1024);
    drop(peer);
    let client = Arc::new(NegotiatedClient::Http1 {
        client: Http1Client::new(io, ConnectionConfig::default()),
        authority: "example.test:80".parse().unwrap(),
    });
    let upstream = NegotiatedUpstream {
        outbound: OutboundConnector::new(None),
        tls: Arc::new(context.tls),
        client: tokio::sync::Mutex::new(Some(client)),
    };
    assert!(upstream
        .send(
            request(Method::GET, "https://example.test/"),
            false,
            "example.test:443".parse().unwrap()
        )
        .await
        .is_err());
    assert!(upstream.client.lock().await.is_none());
}

#[tokio::test]
async fn negotiated_http1_reconnects_after_idle_peer_close() {
    let context = Context::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority: Authority = listener.local_addr().unwrap().to_string().parse().unwrap();
    let config = context.ca.gen_server_config(&authority).await.unwrap();
    let (close_tx, mut close_rx) = tokio::sync::mpsc::channel(1);
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = tokio_rustls::TlsAcceptor::from(config.clone())
                .accept(stream)
                .await
                .unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await.unwrap());
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            stream.flush().await.unwrap();
            close_rx.recv().await.unwrap();
        }
    });
    let upstream = NativeUpstream::negotiated(
        OutboundConnector::new(None),
        context.tls,
        vec![b"http/1.1".to_vec()],
    );
    for _ in 0..2 {
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            upstream.send(
                request(Method::GET, &format!("https://{authority}/")),
                false,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result.response.body.collect().await.unwrap().data, "ok");
        let NativeUpstream::Negotiated(state) = &upstream else {
            unreachable!()
        };
        let cached = state.client.lock().await.as_ref().unwrap().clone();
        close_tx.send(()).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !cached.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("idle close was not detected");
    }
    server.await.unwrap();
}

#[tokio::test]
async fn negotiated_http2_reconnects_after_goaway() {
    let context = Context::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority: Authority = listener.local_addr().unwrap().to_string().parse().unwrap();
    let config = context.ca.gen_server_config(&authority).await.unwrap();
    let (close_tx, mut close_rx) = tokio::sync::mpsc::channel(1);
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = tokio_rustls::TlsAcceptor::from(config.clone())
                .accept(stream)
                .await
                .unwrap();
            assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
            let service = hyper::service::service_fn(|_| async {
                Ok::<_, std::convert::Infallible>(http::Response::new(http_body_util::Full::new(
                    Bytes::from_static(b"ok"),
                )))
            });
            let builder =
                hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());
            let connection =
                builder.serve_connection(hyper_util::rt::TokioIo::new(stream), service);
            tokio::pin!(connection);
            tokio::select! {
                result = &mut connection => panic!("server closed before GOAWAY: {result:?}"),
                signal = close_rx.recv() => { signal.unwrap(); }
            }
            connection.as_mut().graceful_shutdown();
            connection.await.unwrap();
        }
    });
    let upstream = NativeUpstream::negotiated(
        OutboundConnector::new(None),
        context.tls,
        vec![b"h2".to_vec()],
    );
    for _ in 0..2 {
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            upstream.send(
                request(Method::GET, &format!("https://{authority}/")),
                false,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result.response.head.version, Version::HTTP_2);
        assert_eq!(result.response.body.collect().await.unwrap().data, "ok");
        let NativeUpstream::Negotiated(state) = &upstream else {
            unreachable!()
        };
        let cached = state.client.lock().await.as_ref().unwrap().clone();
        close_tx.send(()).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !cached.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("negotiated HTTP/2 cache did not retire the GOAWAY connection");
    }
    server.await.unwrap();
}

#[tokio::test]
async fn negotiated_http2_rejects_http1_upgrade_without_evicting_client() {
    let context = Context::new();
    let (io, peer) = tokio::io::duplex(65536);
    #[derive(Clone)]
    struct Reply;
    impl proxelar_proto::HttpService for Reply {
        fn call(&mut self, _: ProxyRequest) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
            Box::pin(async {
                Ok(ProxyResponse::new(
                    proxelar_proto::ResponseHead::new(
                        StatusCode::OK,
                        Version::HTTP_2,
                        proxyapi_models::HeaderBlock::new(),
                    ),
                    ProxyBody::full(Bytes::from_static(b"still usable")),
                ))
            })
        }
    }
    let server = tokio::spawn(proxelar_proto::http2::serve_connection(
        peer,
        Reply,
        H2ConnectionConfig::default(),
    ));
    let client = Arc::new(NegotiatedClient::Http2(
        H2Client::handshake(io, H2ConnectionConfig::default())
            .await
            .unwrap(),
    ));
    let upstream = NegotiatedUpstream {
        outbound: OutboundConnector::new(None),
        tls: Arc::new(context.tls),
        client: tokio::sync::Mutex::new(Some(client.clone())),
    };
    let error = upstream
        .send(
            request(Method::GET, "https://example.test/"),
            true,
            "example.test:443".parse().unwrap(),
        )
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), ErrorKind::Unsupported);
    assert!(upstream
        .client
        .lock()
        .await
        .as_ref()
        .is_some_and(|cached| Arc::ptr_eq(cached, &client)));
    let response = upstream
        .send(
            request(Method::GET, "https://example.test/"),
            false,
            "example.test:443".parse().unwrap(),
        )
        .await
        .unwrap()
        .response;
    assert_eq!(response.body.collect().await.unwrap().data, "still usable");
    server.abort();
}
