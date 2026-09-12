use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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

struct BodyHintsService {
    hints: Option<tokio::sync::oneshot::Sender<(Option<u64>, bool)>>,
}

impl HttpService for BodyHintsService {
    fn call(
        &mut self,
        request: ProxyRequest,
    ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
        if let Some(hints) = self.hints.take() {
            let _ = hints.send((
                request.body.exact_length(),
                request.body.may_have_trailers(),
            ));
        }
        Box::pin(async {
            Ok(ProxyResponse::new(
                ResponseHead::new(StatusCode::OK, Version::HTTP_11, HeaderBlock::new()),
                ProxyBody::empty(),
            ))
        })
    }
}

#[tokio::test]
async fn bodyless_request_has_zero_length_without_trailers() {
    let (mut peer, server_io) = tokio::io::duplex(1024);
    let (hints_tx, hints_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve_connection(
        server_io,
        BodyHintsService {
            hints: Some(hints_tx),
        },
        ConnectionConfig::default(),
    ));

    peer.write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(hints_rx.await.unwrap(), (Some(0), false));

    let mut response = Vec::new();
    peer.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    server.await.unwrap().unwrap();
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

struct ExpectService {
    saw_expect: Arc<AtomicBool>,
}

impl HttpService for ExpectService {
    fn call(
        &mut self,
        request: ProxyRequest,
    ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
        self.saw_expect.store(
            request.head.headers.get("expect").is_some(),
            Ordering::SeqCst,
        );
        Box::pin(async move {
            let body = request.body.collect().await?.data;
            Ok(ProxyResponse::new(
                ResponseHead::new(StatusCode::OK, Version::HTTP_11, HeaderBlock::new()),
                ProxyBody::full(body),
            ))
        })
    }
}

#[tokio::test]
async fn server_acknowledges_expect_continue_before_reading_the_body() {
    let (mut client, server_io) = tokio::io::duplex(4096);
    let saw_expect = Arc::new(AtomicBool::new(false));
    let server = tokio::spawn(serve_connection(
        server_io,
        ExpectService {
            saw_expect: Arc::clone(&saw_expect),
        },
        ConnectionConfig::default(),
    ));

    client
        .write_all(
            b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\nExpect: 100-Continue\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut interim = [0_u8; 25];
    tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut interim))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");

    client.write_all(b"body").await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with(b"body"));
    assert!(!saw_expect.load(Ordering::SeqCst));
    server.await.unwrap().unwrap();
}

#[derive(Clone)]
struct InformationalService;

impl HttpService for InformationalService {
    fn call(
        &mut self,
        _request: ProxyRequest,
    ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
        Box::pin(async {
            let mut headers = HeaderBlock::new();
            headers.add("Link", "</style.css>; rel=preload").unwrap();
            Ok(ProxyResponse::new(
                ResponseHead::new(StatusCode::OK, Version::HTTP_11, HeaderBlock::new()),
                ProxyBody::empty(),
            )
            .with_informational(vec![ResponseHead::new(
                StatusCode::EARLY_HINTS,
                Version::HTTP_11,
                headers,
            )]))
        })
    }
}

#[tokio::test]
async fn server_writes_informational_responses_before_the_final_head() {
    let (mut peer, server_io) = tokio::io::duplex(1024);
    let server = tokio::spawn(serve_connection(
        server_io,
        InformationalService,
        ConnectionConfig::default(),
    ));
    peer.write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut wire = Vec::new();
    peer.read_to_end(&mut wire).await.unwrap();
    let text = String::from_utf8(wire).unwrap();
    assert!(text.starts_with("HTTP/1.1 103 Early Hints\r\n"), "{text}");
    assert!(text.contains("\r\n\r\nHTTP/1.1 200 OK\r\n"), "{text}");
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn client_preserves_informational_responses_before_the_final_head() {
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
    assert_eq!(response.informational.len(), 1);
    assert_eq!(response.informational[0].status, StatusCode::EARLY_HINTS);
    assert_eq!(
        response.informational[0].headers.get("link"),
        Some(b"</a.css>; rel=preload".as_slice())
    );
    assert_eq!(
        response.body.collect().await.unwrap().data,
        Bytes::from_static(b"hello")
    );
    peer_task.await.unwrap();
}

#[tokio::test]
async fn client_delivers_an_early_response_while_the_upload_continues() {
    let (client_io, mut peer) = tokio::io::duplex(256);
    let release_upload = Arc::new(tokio::sync::Notify::new());
    let body = ProxyBody::new(futures_util::stream::once({
        let release_upload = Arc::clone(&release_upload);
        async move {
            release_upload.notified().await;
            Ok(BodyFrame::Data(Bytes::from_static(b"body")))
        }
    }))
    .with_exact_length(4)
    .with_trailer_hint(false);

    let peer_task = tokio::spawn(async move {
        let mut request_head = Vec::new();
        let mut byte = [0_u8; 1];
        while !request_head.ends_with(b"\r\n\r\n") {
            peer.read_exact(&mut byte).await.unwrap();
            request_head.push(byte[0]);
        }
        peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let mut body = [0_u8; 4];
        peer.read_exact(&mut body).await.unwrap();
        body
    });

    let client = Http1Client::new(client_io, ConnectionConfig::default());
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        client.send_request(request(Method::POST, "/", body)),
    )
    .await
    .expect("response head was blocked on the request body")
    .unwrap();
    assert_eq!(response.head.status, StatusCode::OK);
    let collected = tokio::time::timeout(Duration::from_secs(1), response.body.collect())
        .await
        .expect("response completion was blocked on the request body")
        .unwrap();
    assert!(collected.data.is_empty());

    release_upload.notify_one();
    assert_eq!(peer_task.await.unwrap(), *b"body");
}

#[tokio::test]
async fn client_stops_an_upload_after_an_early_closing_response() {
    const BODY_LEN: usize = 64 * 1024;
    let (client_io, mut peer) = tokio::io::duplex(128);
    let peer_task = tokio::spawn(async move {
        let mut request_head = Vec::new();
        let mut byte = [0_u8; 1];
        while !request_head.ends_with(b"\r\n\r\n") {
            peer.read_exact(&mut byte).await.unwrap();
            request_head.push(byte[0]);
        }
        peer.write_all(
            b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();

        let mut received = Vec::new();
        peer.read_to_end(&mut received).await.unwrap();
        received.len()
    });

    let client = Http1Client::new(client_io, ConnectionConfig::default());
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        client.send_request(request(
            Method::POST,
            "/",
            ProxyBody::full(vec![b'x'; BODY_LEN]),
        )),
    )
    .await
    .expect("early response was blocked on the request upload")
    .unwrap();
    assert_eq!(response.head.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(response.body.collect().await.unwrap().data.is_empty());
    assert!(peer_task.await.unwrap() < BODY_LEN);
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

#[tokio::test]
async fn explicitly_configured_service_timeout_is_reported() {
    struct PendingService;
    impl HttpService for PendingService {
        fn call(&mut self, _: ProxyRequest) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
            Box::pin(std::future::pending())
        }
    }
    let (mut peer, io) = tokio::io::duplex(1024);
    peer.write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
        .await
        .unwrap();
    let error = serve_connection(
        io,
        PendingService,
        ConnectionConfig {
            service_timeout: Some(Duration::from_millis(10)),
            ..ConnectionConfig::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Timeout);
    assert!(error.message().contains("service"));
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

#[tokio::test]
async fn declined_upgrade_keeps_the_connection_alive() {
    let (mut peer, server_io) = tokio::io::duplex(4096);
    let server = tokio::spawn(serve_connection(
        server_io,
        EchoService {
            calls: Arc::new(AtomicUsize::new(0)),
            trailers: false,
        },
        ConnectionConfig::default(),
    ));
    peer.write_all(
        b"GET /upgrade HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nGET /next HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();

    let mut wire = Vec::new();
    peer.read_to_end(&mut wire).await.unwrap();
    let text = String::from_utf8(wire).unwrap();
    assert_eq!(text.matches("HTTP/1.1 200 OK").count(), 2, "{text}");
    assert!(text.contains("X-Path: /upgrade"), "{text}");
    assert!(text.contains("X-Path: /next"), "{text}");
    server.await.unwrap().unwrap();
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
struct BlockingConnector {
    connections: Arc<AtomicUsize>,
    slow_connect_started: Arc<AtomicBool>,
    slow_connect_release: Arc<tokio::sync::Notify>,
}

impl Http1Connector for BlockingConnector {
    fn connect(&self, key: PoolKey) -> BoxFuture<'static, Result<BoxIo, ProtocolError>> {
        let connector = self.clone();
        Box::pin(async move {
            connector.connections.fetch_add(1, Ordering::SeqCst);
            if key.destination == "slow.test:80" {
                connector.slow_connect_started.store(true, Ordering::SeqCst);
                connector.slow_connect_release.notified().await;
            }
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
struct DelayedService {
    slow_started: Arc<AtomicBool>,
    slow_release: Arc<tokio::sync::Notify>,
}

impl HttpService for DelayedService {
    fn call(
        &mut self,
        request: ProxyRequest,
    ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
        let slow_started = Arc::clone(&self.slow_started);
        let slow_release = Arc::clone(&self.slow_release);
        Box::pin(async move {
            let path = request.head.uri.path().to_owned();
            request.body.collect().await?;
            if path == "/slow" {
                slow_started.store(true, Ordering::SeqCst);
                slow_release.notified().await;
            }
            Ok(ProxyResponse::new(
                ResponseHead::new(StatusCode::OK, Version::HTTP_11, HeaderBlock::new()),
                ProxyBody::full(Bytes::from(path)),
            ))
        })
    }
}

#[derive(Clone)]
struct DelayedConnector {
    connections: Arc<AtomicUsize>,
    service: DelayedService,
}

impl Http1Connector for DelayedConnector {
    fn connect(&self, _key: PoolKey) -> BoxFuture<'static, Result<BoxIo, ProtocolError>> {
        let connector = self.clone();
        Box::pin(async move {
            connector.connections.fetch_add(1, Ordering::SeqCst);
            let (client_io, server_io): (DuplexStream, DuplexStream) = tokio::io::duplex(1024);
            tokio::spawn(async move {
                let _ = serve_connection(server_io, connector.service, ConnectionConfig::default())
                    .await;
            });
            Ok(Box::new(client_io) as BoxIo)
        })
    }
}

async fn wait_for(flag: &AtomicBool) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while !flag.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
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

#[derive(Clone)]
struct Http10DefaultCloseConnector {
    connections: Arc<AtomicUsize>,
}

impl Http1Connector for Http10DefaultCloseConnector {
    fn connect(&self, _key: PoolKey) -> BoxFuture<'static, Result<BoxIo, ProtocolError>> {
        let connections = Arc::clone(&self.connections);
        Box::pin(async move {
            connections.fetch_add(1, Ordering::SeqCst);
            let (client_io, mut peer): (DuplexStream, DuplexStream) = tokio::io::duplex(1024);
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut byte = [0_u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    peer.read_exact(&mut byte).await.unwrap();
                    request.push(byte[0]);
                }
                peer.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await
                    .unwrap();

                // A conforming client closes after this default-close response.
                // If another request is incorrectly reused here, consume one byte
                // and drop the connection so that the request fails visibly.
                let _ = peer.read(&mut byte).await;
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

struct ControlledConnector {
    peers: tokio::sync::mpsc::UnboundedSender<DuplexStream>,
}

impl Http1Connector for ControlledConnector {
    fn connect(&self, _: PoolKey) -> BoxFuture<'static, Result<BoxIo, ProtocolError>> {
        let (client, peer) = tokio::io::duplex(4096);
        self.peers.send(peer).unwrap();
        Box::pin(async { Ok(Box::new(client) as BoxIo) })
    }
}

#[tokio::test]
async fn pool_reconnects_after_idle_eof_without_retrying_started_requests() {
    let (peers_tx, mut peers) = tokio::sync::mpsc::unbounded_channel();
    let pool = Arc::new(Http1Pool::new(
        ControlledConnector { peers: peers_tx },
        ConnectionConfig::default(),
    ));
    let key = PoolKey {
        destination: "example.test:80".into(),
        tls: false,
        outbound_route: None,
    };
    for (response_expected, read_request) in
        [(true, true), (true, true), (false, true), (false, false)]
    {
        let pool = pool.clone();
        let key = key.clone();
        let sending = tokio::spawn(async move {
            let response = pool
                .send(key, request(Method::POST, "/", ProxyBody::empty()))
                .await?;
            response.body.collect().await
        });
        let mut peer = tokio::time::timeout(Duration::from_secs(1), peers.recv())
            .await
            .expect("closed idle connection was reused")
            .unwrap();
        if read_request {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(peer.read_u8().await.unwrap());
            }
        }
        if response_expected {
            peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            assert_eq!(sending.await.unwrap().unwrap().data, "ok");
            // Close only after the response is consumed, without Connection: close.
            // The next command may race the idle driver's EOF notification.
            drop(peer);
        } else {
            // Neither a sent POST nor an immediately closed fresh connection
            // may trigger a retry.
            drop(peer);
            assert!(tokio::time::timeout(Duration::from_secs(1), sending)
                .await
                .unwrap()
                .unwrap()
                .is_err());
            assert!(peers.try_recv().is_err());
        }
    }
}

#[tokio::test]
async fn pool_does_not_reuse_an_http10_default_close_response() {
    let connections = Arc::new(AtomicUsize::new(0));
    let pool = Http1Pool::new(
        Http10DefaultCloseConnector {
            connections: Arc::clone(&connections),
        },
        ConnectionConfig::default(),
    );
    let key = PoolKey {
        destination: "example.test:80".to_owned(),
        tls: false,
        outbound_route: None,
    };

    for path in ["/one", "/two"] {
        let response = tokio::time::timeout(
            Duration::from_secs(1),
            pool.send(key.clone(), request(Method::GET, path, ProxyBody::empty())),
        )
        .await
        .expect("HTTP/1.0 request timed out")
        .unwrap();
        assert_eq!(
            response.body.collect().await.unwrap().data,
            Bytes::from_static(b"ok")
        );
    }

    assert_eq!(connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn slow_connect_does_not_block_an_unrelated_destination() {
    let slow_connect_started = Arc::new(AtomicBool::new(false));
    let slow_connect_release = Arc::new(tokio::sync::Notify::new());
    let pool = Arc::new(Http1Pool::new(
        BlockingConnector {
            connections: Arc::new(AtomicUsize::new(0)),
            slow_connect_started: Arc::clone(&slow_connect_started),
            slow_connect_release: Arc::clone(&slow_connect_release),
        },
        ConnectionConfig::default(),
    ));
    let slow_key = PoolKey {
        destination: "slow.test:80".to_owned(),
        tls: false,
        outbound_route: None,
    };
    let fast_key = PoolKey {
        destination: "fast.test:80".to_owned(),
        tls: false,
        outbound_route: None,
    };

    let slow_pool = Arc::clone(&pool);
    let slow = tokio::spawn(async move {
        let response = slow_pool
            .send(slow_key, request(Method::GET, "/slow", ProxyBody::empty()))
            .await
            .unwrap();
        response.body.collect().await.unwrap();
    });
    wait_for(&slow_connect_started).await;

    let fast = tokio::time::timeout(
        Duration::from_secs(1),
        pool.send(fast_key, request(Method::GET, "/fast", ProxyBody::empty())),
    )
    .await
    .expect("unrelated destination was blocked")
    .unwrap();
    assert_eq!(fast.body.collect().await.unwrap().data.as_ref(), b"");

    slow_connect_release.notify_one();
    slow.await.unwrap();
}

#[tokio::test]
async fn concurrent_origin_requests_use_separate_http1_connections() {
    let connections = Arc::new(AtomicUsize::new(0));
    let slow_started = Arc::new(AtomicBool::new(false));
    let slow_release = Arc::new(tokio::sync::Notify::new());
    let pool = Arc::new(Http1Pool::new(
        DelayedConnector {
            connections: Arc::clone(&connections),
            service: DelayedService {
                slow_started: Arc::clone(&slow_started),
                slow_release: Arc::clone(&slow_release),
            },
        },
        ConnectionConfig::default(),
    ));
    let key = PoolKey {
        destination: "example.test:80".to_owned(),
        tls: false,
        outbound_route: None,
    };

    let slow_pool = Arc::clone(&pool);
    let slow_key = key.clone();
    let slow = tokio::spawn(async move {
        let response = slow_pool
            .send(slow_key, request(Method::GET, "/slow", ProxyBody::empty()))
            .await
            .unwrap();
        response.body.collect().await.unwrap().data
    });
    wait_for(&slow_started).await;

    let fast = tokio::time::timeout(
        Duration::from_secs(1),
        pool.send(key, request(Method::GET, "/fast", ProxyBody::empty())),
    )
    .await
    .expect("same-origin request was head-of-line blocked")
    .unwrap();
    assert_eq!(fast.body.collect().await.unwrap().data.as_ref(), b"/fast");
    assert_eq!(connections.load(Ordering::SeqCst), 2);

    slow_release.notify_one();
    assert_eq!(slow.await.unwrap().as_ref(), b"/slow");
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
