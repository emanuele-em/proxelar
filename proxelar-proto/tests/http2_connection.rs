use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt as _;
use proxelar_proto::http2::{
    body_tunnel, serve_connection, ConnectionConfig, H2Client, H2Connector, H2Pool, H2PoolKey,
};
use proxelar_proto::{
    BodyFrame, BoxFuture, ErrorKind, HttpService, ProtocolError, ProxyBody, ProxyRequest,
    ProxyResponse, ResponseHead,
};
use proxyapi_models::{HeaderBlock, HeaderField};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};
use tokio::time::timeout;

#[tokio::test]
async fn tunnel_response_progresses_while_request_is_backpressured() {
    let (application, mut outbound) = body_tunnel(ProxyBody::full(vec![1; 32]), 16);
    let (mut reader, mut writer) = tokio::io::split(application);
    // This confirms the receive pump is writing a frame larger than its buffer.
    reader.read_u8().await.unwrap();
    writer.write_all(b"response").await.unwrap();
    let frame = timeout(Duration::from_secs(1), outbound.next())
        .await
        .expect("response stalled behind request backpressure")
        .unwrap()
        .unwrap();
    assert_eq!(frame, BodyFrame::Data(Bytes::from_static(b"response")));
}

#[tokio::test]
async fn tunnel_request_progresses_while_response_is_backpressured() {
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();
    let inbound = ProxyBody::new(futures_util::stream::once(async {
        request_rx.await.unwrap()
    }));
    let (application, _outbound) = body_tunnel(inbound, 16);
    let (mut reader, mut writer) = tokio::io::split(application);
    let writing = writer.write_all(&[2; 128]);
    tokio::pin!(writing);
    assert!(timeout(Duration::from_millis(20), &mut writing)
        .await
        .is_err());

    request_tx
        .send(Ok(BodyFrame::Data(Bytes::from_static(b"request"))))
        .unwrap();
    let mut request = [0; 7];
    timeout(Duration::from_secs(1), reader.read_exact(&mut request))
        .await
        .expect("request stalled behind response backpressure")
        .unwrap();
    assert_eq!(&request, b"request");
}

#[tokio::test]
async fn tunnel_request_eof_keeps_response_writable() {
    let (mut application, mut outbound) = body_tunnel(ProxyBody::empty(), 16);
    assert_eq!(application.read(&mut [0]).await.unwrap(), 0);
    application.write_all(b"response").await.unwrap();
    application.shutdown().await.unwrap();
    let body = timeout(Duration::from_secs(1), async {
        let mut data = Vec::new();
        while let Some(frame) = outbound.next().await {
            if let BodyFrame::Data(bytes) = frame.unwrap() {
                data.extend_from_slice(&bytes);
            }
        }
        data
    })
    .await
    .unwrap();
    assert_eq!(body, b"response");
}

#[tokio::test]
async fn tunnel_response_eof_keeps_request_readable() {
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();
    let inbound = ProxyBody::new(futures_util::stream::once(async {
        request_rx.await.unwrap()
    }));
    let (mut application, mut outbound) = body_tunnel(inbound, 16);
    application.shutdown().await.unwrap();
    assert!(timeout(Duration::from_secs(1), outbound.next())
        .await
        .unwrap()
        .is_none());

    request_tx
        .send(Ok(BodyFrame::Data(Bytes::from_static(b"request"))))
        .unwrap();
    let mut request = Vec::new();
    timeout(
        Duration::from_secs(1),
        application.read_to_end(&mut request),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(request, b"request");
}

#[tokio::test]
async fn dropping_tunnel_response_cancels_pending_request() {
    let (mut request_tx, request_rx) = tokio::sync::oneshot::channel();
    let inbound = ProxyBody::new(futures_util::stream::once(async {
        request_rx.await.unwrap()
    }));
    let (mut application, outbound) = body_tunnel(inbound, 16);
    drop(outbound);
    timeout(Duration::from_secs(1), request_tx.closed())
        .await
        .unwrap();
    assert_eq!(application.read(&mut [0]).await.unwrap(), 0);
}

#[tokio::test]
async fn tunnel_reports_inbound_errors_and_rejects_trailers() {
    for frame in [
        Err(ProtocolError::new(ErrorKind::Reset, "request reset")),
        Ok(BodyFrame::Trailers(HeaderBlock::new())),
    ] {
        let expected = match &frame {
            Err(error) => error.kind(),
            Ok(_) => ErrorKind::ProtocolViolation,
        };
        let (mut application, mut outbound) = body_tunnel(ProxyBody::from_frames([frame]), 16);
        let error = timeout(Duration::from_secs(1), outbound.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), expected);
        assert!(outbound.next().await.is_none());
        assert_eq!(application.read(&mut [0]).await.unwrap(), 0);
    }
}

#[derive(Clone)]
struct EchoService;

impl HttpService for EchoService {
    fn call(
        &mut self,
        request: ProxyRequest,
    ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
        Box::pin(async move {
            Ok(ProxyResponse::new(
                ResponseHead::new(
                    http::StatusCode::OK,
                    http::Version::HTTP_2,
                    HeaderBlock::from_fields([
                        HeaderField::new("x-echo", "one").unwrap(),
                        HeaderField::new("x-echo", "two").unwrap(),
                    ]),
                ),
                request.body,
            ))
        })
    }
}

fn request(path: &str, body: ProxyBody) -> ProxyRequest {
    ProxyRequest::new(
        proxelar_proto::RequestHead::new(
            http::Method::POST,
            format!("https://example.test{path}").parse().unwrap(),
            http::Version::HTTP_2,
            HeaderBlock::new(),
        ),
        body,
    )
}

#[tokio::test]
async fn client_and_server_stream_data_and_ordered_trailers() {
    let (client_io, server_io) = tokio::io::duplex(128);
    let server = tokio::spawn(serve_connection(
        server_io,
        EchoService,
        ConnectionConfig {
            initial_stream_window_size: 32,
            initial_connection_window_size: 64,
            ..ConnectionConfig::default()
        },
    ));
    let client = H2Client::handshake(client_io, ConnectionConfig::default())
        .await
        .unwrap();
    let trailers = HeaderBlock::from_fields([
        HeaderField::new("x-checksum", "one").unwrap(),
        HeaderField::new("x-checksum", "two").unwrap(),
    ]);
    let response = client
        .send_request(request(
            "/stream",
            ProxyBody::from_frames([
                Ok(BodyFrame::Data(Bytes::from(vec![b'a'; 256]))),
                Ok(BodyFrame::Trailers(trailers.clone())),
            ]),
        ))
        .await
        .unwrap();
    assert_eq!(
        response.head.headers.get_all("x-echo").collect::<Vec<_>>(),
        vec![b"one".as_slice(), b"two".as_slice()]
    );
    let collected = response.body.collect().await.unwrap();
    assert_eq!(collected.data, Bytes::from(vec![b'a'; 256]));
    assert_eq!(collected.trailers, Some(trailers));
    drop(client);
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn one_connection_multiplexes_concurrent_streams() {
    let (client_io, server_io) = tokio::io::duplex(1024);
    let server = tokio::spawn(serve_connection(
        server_io,
        EchoService,
        ConnectionConfig::default(),
    ));
    let client = H2Client::handshake(client_io, ConnectionConfig::default())
        .await
        .unwrap();
    let mut tasks = Vec::new();
    for index in 0..20 {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            let payload = Bytes::from(format!("stream-{index}"));
            let response = client
                .send_request(request(
                    &format!("/{index}"),
                    ProxyBody::full(payload.clone()),
                ))
                .await
                .unwrap();
            assert_eq!(response.body.collect().await.unwrap().data, payload);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    drop(client);
    server.await.unwrap().unwrap();
}

#[derive(Clone)]
struct ForbiddenBodyService;

impl HttpService for ForbiddenBodyService {
    fn call(
        &mut self,
        request: ProxyRequest,
    ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
        Box::pin(async move {
            let status = match request.head.uri.path() {
                "/head" => http::StatusCode::OK,
                "/no-content" => http::StatusCode::NO_CONTENT,
                "/reset-content" => http::StatusCode::RESET_CONTENT,
                "/not-modified" => http::StatusCode::NOT_MODIFIED,
                path => panic!("unexpected path {path}"),
            };
            Ok(ProxyResponse::new(
                ResponseHead::new(status, http::Version::HTTP_2, HeaderBlock::new()),
                ProxyBody::full(Bytes::from_static(b"forbidden response body")),
            ))
        })
    }
}

#[tokio::test]
async fn server_suppresses_semantically_forbidden_response_bodies() {
    let (client_io, server_io) = tokio::io::duplex(1024);
    let server = tokio::spawn(serve_connection(
        server_io,
        ForbiddenBodyService,
        ConnectionConfig::default(),
    ));
    let client = H2Client::handshake(client_io, ConnectionConfig::default())
        .await
        .unwrap();

    for (method, path, status) in [
        (http::Method::HEAD, "/head", http::StatusCode::OK),
        (
            http::Method::GET,
            "/no-content",
            http::StatusCode::NO_CONTENT,
        ),
        (
            http::Method::GET,
            "/reset-content",
            http::StatusCode::RESET_CONTENT,
        ),
        (
            http::Method::GET,
            "/not-modified",
            http::StatusCode::NOT_MODIFIED,
        ),
    ] {
        let response = client
            .send_request(ProxyRequest::new(
                proxelar_proto::RequestHead::new(
                    method,
                    format!("https://example.test{path}").parse().unwrap(),
                    http::Version::HTTP_2,
                    HeaderBlock::new(),
                ),
                ProxyBody::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(response.head.status, status);
        assert!(response.body.collect().await.unwrap().data.is_empty());
    }

    drop(client);
    server.await.unwrap().unwrap();
}

#[derive(Clone)]
struct FailingService;

impl HttpService for FailingService {
    fn call(
        &mut self,
        _request: ProxyRequest,
    ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
        Box::pin(async {
            Err(ProtocolError::new(
                ErrorKind::ProtocolViolation,
                "rejected stream",
            ))
        })
    }
}

#[derive(Clone)]
struct SelectiveFailureService;

impl HttpService for SelectiveFailureService {
    fn call(
        &mut self,
        request: ProxyRequest,
    ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
        Box::pin(async move {
            if request.head.uri.path() == "/reset" {
                return Err(ProtocolError::new(ErrorKind::Reset, "reset stream"));
            }
            Ok(ProxyResponse::new(
                ResponseHead::new(
                    http::StatusCode::OK,
                    http::Version::HTTP_2,
                    HeaderBlock::new(),
                ),
                request.body,
            ))
        })
    }
}

#[tokio::test]
async fn service_failures_reset_only_the_stream() {
    let (client_io, server_io) = tokio::io::duplex(1024);
    let server = tokio::spawn(serve_connection(
        server_io,
        FailingService,
        ConnectionConfig::default(),
    ));
    let client = H2Client::handshake(client_io, ConnectionConfig::default())
        .await
        .unwrap();
    let error = client
        .send_request(request("/reset", ProxyBody::empty()))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Reset);
    drop(client);
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn extended_connect_is_advertised_and_streams_bytes() {
    let (client_io, server_io) = tokio::io::duplex(1024);
    let server = tokio::spawn(serve_connection(
        server_io,
        EchoService,
        ConnectionConfig {
            enable_extended_connect: true,
            ..ConnectionConfig::default()
        },
    ));
    let client = H2Client::handshake(client_io, ConnectionConfig::default())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), client.ensure_extended_connect())
        .await
        .unwrap()
        .unwrap();

    let response = client
        .send_request(ProxyRequest::new(
            proxelar_proto::RequestHead::new(
                http::Method::CONNECT,
                "https://example.test/chat".parse().unwrap(),
                http::Version::HTTP_2,
                HeaderBlock::from_fields([
                    HeaderField::new(":protocol", "websocket").unwrap(),
                    HeaderField::new("sec-websocket-version", "13").unwrap(),
                ]),
            ),
            ProxyBody::full(Bytes::from_static(b"websocket bytes")),
        ))
        .await
        .unwrap();
    assert_eq!(
        response.body.collect().await.unwrap().data,
        Bytes::from_static(b"websocket bytes")
    );
    drop(client);
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn extended_connect_requires_the_peer_setting() {
    let (client_io, server_io) = tokio::io::duplex(1024);
    let server = tokio::spawn(serve_connection(
        server_io,
        EchoService,
        ConnectionConfig::default(),
    ));
    let client = H2Client::handshake(client_io, ConnectionConfig::default())
        .await
        .unwrap();

    let error = tokio::time::timeout(Duration::from_secs(2), client.ensure_extended_connect())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Unsupported);

    drop(client);
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
            Ok(ProxyResponse::new(
                ResponseHead::new(
                    http::StatusCode::OK,
                    http::Version::HTTP_2,
                    HeaderBlock::new(),
                ),
                ProxyBody::empty(),
            )
            .with_informational(vec![ResponseHead::new(
                http::StatusCode::EARLY_HINTS,
                http::Version::HTTP_2,
                HeaderBlock::from_fields([
                    HeaderField::new("link", "</style.css>; rel=preload").unwrap()
                ]),
            )]))
        })
    }
}

#[tokio::test]
async fn client_and_server_preserve_informational_responses() {
    let (client_io, server_io) = tokio::io::duplex(1024);
    let server = tokio::spawn(serve_connection(
        server_io,
        InformationalService,
        ConnectionConfig::default(),
    ));
    let client = H2Client::handshake(client_io, ConnectionConfig::default())
        .await
        .unwrap();

    let response = client
        .send_request(request("/hints", ProxyBody::empty()))
        .await
        .unwrap();
    assert_eq!(response.head.status, http::StatusCode::OK);
    assert_eq!(response.informational.len(), 1);
    assert_eq!(
        response.informational[0].status,
        http::StatusCode::EARLY_HINTS
    );
    assert_eq!(
        response.informational[0].headers.get("link"),
        Some(b"</style.css>; rel=preload".as_slice())
    );

    drop(response);
    drop(client);
    server.await.unwrap().unwrap();
}

#[derive(Clone)]
struct QueueConnector {
    streams: Arc<Mutex<VecDeque<DuplexStream>>>,
    connects: Arc<AtomicUsize>,
}

impl H2Connector for QueueConnector {
    fn connect(
        &self,
        _key: H2PoolKey,
    ) -> BoxFuture<'static, Result<proxelar_proto::http1::BoxIo, ProtocolError>> {
        let stream = self.streams.lock().unwrap().pop_front();
        self.connects.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            stream
                .map(|stream| Box::new(stream) as proxelar_proto::http1::BoxIo)
                .ok_or_else(|| ProtocolError::new(ErrorKind::Io, "no queued stream"))
        })
    }
}

#[tokio::test]
async fn pool_reuses_one_multiplexed_connection_per_route_key() {
    let (client_io, server_io) = tokio::io::duplex(1024);
    let server = tokio::spawn(serve_connection(
        server_io,
        EchoService,
        ConnectionConfig::default(),
    ));
    let connects = Arc::new(AtomicUsize::new(0));
    let pool = H2Pool::new(
        QueueConnector {
            streams: Arc::new(Mutex::new(VecDeque::from([client_io]))),
            connects: Arc::clone(&connects),
        },
        ConnectionConfig::default(),
    );
    let key = H2PoolKey {
        destination: "example.test:443".to_owned(),
        tls: true,
        outbound_route: Some("direct".to_owned()),
    };
    for path in ["/one", "/two"] {
        let response = tokio::time::timeout(
            Duration::from_secs(2),
            pool.send(key.clone(), request(path, ProxyBody::empty())),
        )
        .await
        .expect("pool send timed out")
        .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), response.body.collect())
                .await
                .expect("response body timed out")
                .unwrap()
                .data,
            Bytes::new()
        );
    }
    assert_eq!(connects.load(Ordering::SeqCst), 1);
    assert_eq!(pool.connection_count().await, 1);
    drop(pool);
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn pool_keeps_connection_after_stream_reset() {
    let (client_io, server_io) = tokio::io::duplex(1024);
    let server = tokio::spawn(serve_connection(
        server_io,
        SelectiveFailureService,
        ConnectionConfig::default(),
    ));
    let connects = Arc::new(AtomicUsize::new(0));
    let pool = H2Pool::new(
        QueueConnector {
            streams: Arc::new(Mutex::new(VecDeque::from([client_io]))),
            connects: Arc::clone(&connects),
        },
        ConnectionConfig::default(),
    );
    let key = H2PoolKey {
        destination: "example.test:443".to_owned(),
        tls: true,
        outbound_route: None,
    };

    let error = pool
        .send(key.clone(), request("/reset", ProxyBody::empty()))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Reset);

    let response = pool
        .send(key, request("/ok", ProxyBody::empty()))
        .await
        .unwrap();
    assert!(response.body.collect().await.unwrap().data.is_empty());
    assert_eq!(connects.load(Ordering::SeqCst), 1);
    assert_eq!(pool.connection_count().await, 1);

    drop(pool);
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn peer_reset_drops_pending_upload_and_keeps_other_streams_usable() {
    let (client_io, server_io) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        let mut conn = h2::server::handshake(server_io).await.unwrap();
        let (_request, mut respond) = conn.accept().await.unwrap().unwrap();
        respond.send_reset(h2::Reason::CANCEL);
        while let Some(accepted) = conn.accept().await {
            let (_, mut respond) = accepted.unwrap();
            respond
                .send_response(http::Response::new(()), true)
                .unwrap();
        }
    });
    let client = H2Client::handshake(client_io, ConnectionConfig::default())
        .await
        .unwrap();
    let (mut source, receiver) = tokio::sync::oneshot::channel::<Bytes>();
    let body = ProxyBody::new(futures_util::stream::once(async {
        Ok(BodyFrame::Data(receiver.await.unwrap()))
    }));
    let result = client.send_request(request("/reset", body)).await;
    assert!(result.is_err());
    timeout(Duration::from_secs(1), source.closed())
        .await
        .expect("reset stream retained its pending upload body");
    let response = timeout(
        Duration::from_secs(1),
        client.send_request(request("/next", ProxyBody::empty())),
    )
    .await
    .unwrap()
    .unwrap();
    response.body.collect().await.unwrap();
    server.abort();
}
