use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, StatusCode, Uri, Version};
use proxelar_proto::http1::{
    serve_connection, serve_connection_with_upgrades, BoxIo, ConnectionConfig, Http1Client,
    Http1Connector, Http1Pool, PoolKey, ServerConnection,
};
use proxelar_proto::{
    BodyFrame, BoxFuture, ErrorKind, HttpService, ProtocolError, ProxyBody, ProxyRequest,
    ProxyResponse, RequestHead, ResponseHead,
};
use proxyapi_models::HeaderBlock;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};

fn request(method: Method, path: &'static str, body: ProxyBody) -> ProxyRequest {
    let mut headers = HeaderBlock::new();
    headers.add("Host", "example.test").unwrap();
    ProxyRequest::new(
        RequestHead::new(method, Uri::from_static(path), Version::HTTP_11, headers),
        body,
    )
}

#[derive(Clone)]
struct EchoService {
    calls: Arc<AtomicUsize>,
    trailers: bool,
}

impl HttpService for EchoService {
    fn call(
        &mut self,
        request: ProxyRequest,
    ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let trailers = self.trailers;
        Box::pin(async move {
            let path = request.head.uri.path().to_owned();
            let collected = request.body.collect().await?;
            let mut headers = HeaderBlock::new();
            headers.add("X-Path", path).unwrap();
            let body = if trailers {
                let mut trailer_block = HeaderBlock::new();
                trailer_block.add("X-Checksum", "ok").unwrap();
                ProxyBody::from_frames([
                    Ok(BodyFrame::Data(collected.data)),
                    Ok(BodyFrame::Trailers(trailer_block)),
                ])
            } else {
                ProxyBody::full(collected.data)
            };
            Ok(ProxyResponse::new(
                ResponseHead::new(StatusCode::OK, Version::HTTP_11, headers),
                body,
            ))
        })
    }
}

#[tokio::test]
async fn client_and_server_stream_bodies_trailers_and_keep_alive() {
    let (client_io, server_io) = tokio::io::duplex(256);
    let calls = Arc::new(AtomicUsize::new(0));
    let server = tokio::spawn(serve_connection(
        server_io,
        EchoService {
            calls: Arc::clone(&calls),
            trailers: true,
        },
        ConnectionConfig::default(),
    ));
    let client = Http1Client::new(client_io, ConnectionConfig::default());

    let response = client
        .send_request(request(
            Method::POST,
            "/first",
            ProxyBody::full(Bytes::from_static(b"payload")),
        ))
        .await
        .unwrap();
    assert_eq!(
        response.head.headers.get("x-path"),
        Some(b"/first".as_slice())
    );
    let collected = response.body.collect().await.unwrap();
    assert_eq!(collected.data, Bytes::from_static(b"payload"));
    assert_eq!(
        collected
            .trailers
            .as_ref()
            .and_then(|headers| headers.get("x-checksum")),
        Some(b"ok".as_slice())
    );

    let response = client
        .send_request(request(Method::GET, "/second", ProxyBody::empty()))
        .await
        .unwrap();
    assert_eq!(
        response.head.headers.get("x-path"),
        Some(b"/second".as_slice())
    );
    assert!(response.body.collect().await.unwrap().data.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    drop(client);
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn server_preserves_pipelined_response_order() {
    let (mut client_io, server_io) = tokio::io::duplex(4096);
    let server = tokio::spawn(serve_connection(
        server_io,
        EchoService {
            calls: Arc::new(AtomicUsize::new(0)),
            trailers: false,
        },
        ConnectionConfig::default(),
    ));
    client_io
        .write_all(
            b"GET /one HTTP/1.1\r\nHost: example.test\r\n\r\nGET /two HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut wire = Vec::new();
    client_io.read_to_end(&mut wire).await.unwrap();
    let text = String::from_utf8(wire).unwrap();
    let first = text.find("X-Path: /one").unwrap();
    let second = text.find("X-Path: /two").unwrap();
    assert!(first < second, "responses were reordered: {text}");
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn client_skips_informational_responses_before_the_final_head() {
    let (client_io, mut peer) = tokio::io::duplex(4096);
    let peer_task = tokio::spawn(async move {
        let mut request = Vec::new();
        let mut byte = [0_u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            peer.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
        }
        peer.write_all(
            b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        )
        .await
        .unwrap();
    });
    let client = Http1Client::new(client_io, ConnectionConfig::default());
    let response = client
        .send_request(request(Method::GET, "/", ProxyBody::empty()))
        .await
        .unwrap();
    assert_eq!(response.head.status, StatusCode::OK);
    assert_eq!(
        response.body.collect().await.unwrap().data,
        Bytes::from_static(b"hello")
    );
    peer_task.await.unwrap();
}

#[tokio::test]
async fn idle_read_timeout_is_reported() {
    let (_peer, server_io) = tokio::io::duplex(64);
    let config = ConnectionConfig {
        read_timeout: Duration::from_millis(10),
        ..ConnectionConfig::default()
    };
    let error = serve_connection(
        server_io,
        EchoService {
            calls: Arc::new(AtomicUsize::new(0)),
            trailers: false,
        },
        config,
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Timeout);
}

struct ConnectService;

impl HttpService for ConnectService {
    fn call(
        &mut self,
        _request: ProxyRequest,
    ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
        Box::pin(async {
            Ok(ProxyResponse::new(
                ResponseHead::new(StatusCode::OK, Version::HTTP_11, HeaderBlock::new()),
                ProxyBody::empty(),
            ))
        })
    }
}

#[tokio::test]
async fn accepted_connect_returns_raw_io_and_preserves_read_ahead() {
    let (mut peer, server_io) = tokio::io::duplex(1024);
    let server = tokio::spawn(serve_connection_with_upgrades(
        server_io,
        ConnectService,
        ConnectionConfig::default(),
    ));
    peer.write_all(b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\nPING")
        .await
        .unwrap();
    let mut response = [0_u8; 19];
    peer.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"HTTP/1.1 200 OK\r\n\r\n");

    let outcome = server.await.unwrap().unwrap();
    let ServerConnection::Upgraded(upgraded) = outcome else {
        panic!("CONNECT did not return the raw stream");
    };
    assert_eq!(upgraded.read_ahead, Bytes::from_static(b"PING"));
}

#[derive(Clone)]
struct DuplexConnector {
    connections: Arc<AtomicUsize>,
}

impl Http1Connector for DuplexConnector {
    fn connect(&self, _key: PoolKey) -> BoxFuture<'static, Result<BoxIo, ProtocolError>> {
        let connections = Arc::clone(&self.connections);
        Box::pin(async move {
            connections.fetch_add(1, Ordering::SeqCst);
            let (client_io, server_io): (DuplexStream, DuplexStream) = tokio::io::duplex(1024);
            tokio::spawn(async move {
                let _ = serve_connection(
                    server_io,
                    EchoService {
                        calls: Arc::new(AtomicUsize::new(0)),
                        trailers: false,
                    },
                    ConnectionConfig::default(),
                )
                .await;
            });
            Ok(Box::new(client_io) as BoxIo)
        })
    }
}

#[derive(Clone)]
struct CloseAfterResponseService;

impl HttpService for CloseAfterResponseService {
    fn call(
        &mut self,
        request: ProxyRequest,
    ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
        Box::pin(async move {
            let path = request.head.uri.path().to_owned();
            request.body.collect().await?;
            let mut headers = HeaderBlock::new();
            headers.add("Connection", "close").unwrap();
            Ok(ProxyResponse::new(
                ResponseHead::new(StatusCode::OK, Version::HTTP_11, headers),
                ProxyBody::full(Bytes::from(path)),
            ))
        })
    }
}

#[derive(Clone)]
struct ClosingConnector {
    connections: Arc<AtomicUsize>,
}

impl Http1Connector for ClosingConnector {
    fn connect(&self, _key: PoolKey) -> BoxFuture<'static, Result<BoxIo, ProtocolError>> {
        let connections = Arc::clone(&self.connections);
        Box::pin(async move {
            connections.fetch_add(1, Ordering::SeqCst);
            let (client_io, server_io): (DuplexStream, DuplexStream) = tokio::io::duplex(1024);
            tokio::spawn(async move {
                let _ = serve_connection(
                    server_io,
                    CloseAfterResponseService,
                    ConnectionConfig::default(),
                )
                .await;
            });
            Ok(Box::new(client_io) as BoxIo)
        })
    }
}

#[tokio::test]
async fn pool_reuses_connections_by_destination_tls_and_route() {
    let connections = Arc::new(AtomicUsize::new(0));
    let pool = Http1Pool::new(
        DuplexConnector {
            connections: Arc::clone(&connections),
        },
        ConnectionConfig::default(),
    );
    let key = PoolKey {
        destination: "example.test:443".to_owned(),
        tls: true,
        outbound_route: Some("direct".to_owned()),
    };
    for path in ["/one", "/two"] {
        let response = pool
            .send(key.clone(), request(Method::GET, path, ProxyBody::empty()))
            .await
            .unwrap();
        response.body.collect().await.unwrap();
    }
    assert_eq!(connections.load(Ordering::SeqCst), 1);
    assert_eq!(pool.len().await, 1);

    let mut other = key;
    other.outbound_route = Some("socks://127.0.0.1:1080".to_owned());
    let response = pool
        .send(other, request(Method::GET, "/three", ProxyBody::empty()))
        .await
        .unwrap();
    response.body.collect().await.unwrap();
    assert_eq!(connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn pool_retries_concurrent_requests_that_were_queued_but_never_written() {
    let connections = Arc::new(AtomicUsize::new(0));
    let pool = Arc::new(Http1Pool::new(
        ClosingConnector {
            connections: Arc::clone(&connections),
        },
        ConnectionConfig::default(),
    ));
    let key = PoolKey {
        destination: "example.test:80".to_owned(),
        tls: false,
        outbound_route: None,
    };

    let paths = [
        "/one", "/two", "/three", "/four", "/five", "/six", "/seven", "/eight",
    ];
    let mut requests = Vec::new();
    for path in paths {
        let pool = Arc::clone(&pool);
        let key = key.clone();
        requests.push(tokio::spawn(async move {
            pool.send(key, request(Method::GET, path, ProxyBody::empty()))
                .await
                .unwrap()
                .body
                .collect()
                .await
                .unwrap()
                .data
        }));
    }

    let mut bodies = Vec::new();
    for request in requests {
        bodies.push(request.await.unwrap());
    }
    bodies.sort();
    let mut expected = paths
        .map(|path| Bytes::from_static(path.as_bytes()))
        .to_vec();
    expected.sort();
    assert_eq!(bodies, expected);
    assert_eq!(connections.load(Ordering::SeqCst), paths.len());
}
