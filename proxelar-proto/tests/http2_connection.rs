use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use proxelar_proto::http2::{
    serve_connection, ConnectionConfig, H2Client, H2Connector, H2Pool, H2PoolKey,
};
use proxelar_proto::{
    BodyFrame, BoxFuture, ErrorKind, HttpService, ProtocolError, ProxyBody, ProxyRequest,
    ProxyResponse, ResponseHead,
};
use proxyapi_models::{HeaderBlock, HeaderField};
use tokio::io::DuplexStream;

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
