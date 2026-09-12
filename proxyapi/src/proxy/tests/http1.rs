use super::*;
use crate::ca::CertificateAuthority;
use crate::proxy::test_support::{request, Context};
use bytes::Bytes;
use http::StatusCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn shared_https_connector_uses_http1_and_normalizes_wire_headers() {
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
    let upstream = NativeUpstream::shared(context.pool(), None);
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
