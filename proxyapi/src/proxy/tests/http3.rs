use super::*;
use proxelar_proto::ResponseHead;
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

#[tokio::test]
async fn informational_responses_precede_final_headers_and_body() {
    let response = ProxyResponse::new(
        ResponseHead::new(StatusCode::OK, Version::HTTP_3, HeaderBlock::new()),
        ProxyBody::full(Bytes::from_static(b"ok")),
    )
    .with_informational(vec![ResponseHead::new(
        StatusCode::EARLY_HINTS,
        Version::HTTP_3,
        HeaderBlock::new(),
    )]);
    let (send, mut recv) = mpsc::channel(4);
    send_response(PollSender::new(send), response, &Method::GET)
        .await
        .unwrap();
    for status in [b"103", b"200"] {
        assert!(
            matches!(recv.recv().await, Some(OutboundFrame::Headers(headers)) if headers[0].value() == status)
        );
    }
    assert!(
        matches!(recv.recv().await, Some(OutboundFrame::Body(data, false)) if data == b"ok".as_slice())
    );
    assert!(matches!(recv.recv().await, Some(OutboundFrame::Body(data, true)) if data.is_empty()));
}

#[tokio::test]
async fn response_sender_rejects_invalid_informationals_and_closed_channels() {
    for status in [StatusCode::SWITCHING_PROTOCOLS, StatusCode::OK] {
        let response = ProxyResponse::new(
            ResponseHead::new(StatusCode::OK, Version::HTTP_3, HeaderBlock::new()),
            ProxyBody::empty(),
        )
        .with_informational(vec![ResponseHead::new(
            status,
            Version::HTTP_3,
            HeaderBlock::new(),
        )]);
        let (send, _recv) = mpsc::channel(1);
        assert_eq!(
            send_response(PollSender::new(send), response, &Method::GET)
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::ProtocolViolation
        );
    }
    for body in [
        ProxyBody::empty(),
        ProxyBody::full(Bytes::from_static(b"data")),
    ] {
        let (send, recv) = mpsc::channel(1);
        drop(recv);
        assert_eq!(
            send_body(PollSender::new(send), body)
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::Io
        );
    }
    let (send, mut recv) = mpsc::channel(1);
    send_stream_error(PollSender::new(send)).await;
    assert!(matches!(
        recv.recv().await,
        Some(OutboundFrame::PeerStreamError)
    ));
}

#[tokio::test]
async fn invalid_requests_and_service_errors_reset_the_h3_stream() {
    struct Reject;
    impl HttpService for Reject {
        fn call(
            &mut self,
            request: ProxyRequest,
        ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
            assert_eq!(request.head.uri.path(), "/");
            Box::pin(async { Err(ProtocolError::new(ErrorKind::Reset, "rejected")) })
        }
    }
    for headers in [
        vec![Header::new(b":method", b"GET")],
        vec![
            Header::new(b":method", b"GET"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", b"example.test"),
            Header::new(b":path", b"/"),
        ],
    ] {
        let (send, mut sent) = mpsc::channel(1);
        let (_body, recv) = mpsc::channel(1);
        handle_server_request(
            Reject,
            IncomingH3Headers {
                headers,
                send: PollSender::new(send),
                recv,
            },
        )
        .await;
        assert!(matches!(
            sent.recv().await,
            Some(OutboundFrame::PeerStreamError)
        ));
        assert!(sent.recv().await.is_none());
    }
}

#[tokio::test]
async fn address_exhaustion_reports_the_final_connection_error() {
    let error = connect_h3_candidates(std::iter::empty(), |_| async { Ok::<_, ProtocolError>(()) })
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::MalformedMessage);
    let addresses = [
        "127.0.0.1:443".parse().unwrap(),
        "[::1]:443".parse().unwrap(),
    ];
    let error = connect_h3_candidates(addresses, |addr| async move {
        Err::<(), _>(protocol(ErrorKind::Io, format!("{addr}: refused")))
    })
    .await
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Io);
    assert!(error.message().contains("[::1]:443"));
}

#[derive(Clone)]
struct EchoService;

impl HttpService for EchoService {
    fn call(
        &mut self,
        request: ProxyRequest,
    ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
        Box::pin(async move {
            if request.head.uri.path() == "/reset" {
                return Err(protocol(ErrorKind::Reset, "test stream rejection"));
            }
            if request.head.uri.path() == "/pending" {
                return std::future::pending().await;
            }
            if request.head.uri.path() == "/invalid-response" {
                return Ok(ProxyResponse::new(
                    ResponseHead::new(StatusCode::OK, Version::HTTP_3, HeaderBlock::new()),
                    ProxyBody::empty(),
                )
                .with_informational(vec![ResponseHead::new(
                    StatusCode::OK,
                    Version::HTTP_3,
                    HeaderBlock::new(),
                )]));
            }
            let informational_count = if request.head.uri.path() == "/too-many-info" {
                17
            } else {
                1
            };
            let mut headers = HeaderBlock::new();
            headers.add("x-first", "1").unwrap();
            headers.add("x-repeat", [0x80, 0xff]).unwrap();
            headers.add("x-middle", "2").unwrap();
            headers.add("x-repeat", "last").unwrap();
            let body = if request.head.uri.path() == "/forbidden" {
                ProxyBody::full("must not be sent")
            } else {
                request.body
            };
            Ok(ProxyResponse::new(
                ResponseHead::new(StatusCode::OK, Version::HTTP_3, headers),
                body,
            )
            .with_informational(vec![
                ResponseHead::new(
                    StatusCode::EARLY_HINTS,
                    Version::HTTP_3,
                    HeaderBlock::new(),
                );
                informational_count
            ]))
        })
    }
}

struct TestEndpoint {
    address: SocketAddr,
    task: tokio::task::JoinHandle<()>,
    verifier: Arc<dyn ServerCertVerifier>,
}

impl TestEndpoint {
    async fn new() -> Self {
        Self::bind("127.0.0.1:0", "localhost:443").await
    }

    async fn bind(address: &str, authority: &str) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let ca = Arc::new(crate::ca::Ssl::load_or_generate(dir.path()).unwrap());
        let cert = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(cert.path(), ca.ca_cert_pem()).unwrap();
        let verifier = crate::proxy::tls::h3_server_verifier(
            &crate::UpstreamTlsConfig::CaFileOnly(cert.path().to_path_buf()),
        )
        .unwrap();
        let config = server_config(ca, authority.parse().unwrap(), false).unwrap();
        let listener = H3Listener::bind(address.parse().unwrap(), config)
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            listener.serve(|_| EchoService).await.unwrap();
        });
        Self {
            address,
            task,
            verifier,
        }
    }

    fn client(&self) -> ReverseH3Upstream {
        ReverseH3Upstream::new_with_remote(
            "https://localhost/".parse().unwrap(),
            self.verifier.clone(),
            self.address,
        )
    }
}

impl Drop for TestEndpoint {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn echo_request(path: &str, body: ProxyBody) -> ProxyRequest {
    ProxyRequest::new(
        proxelar_proto::RequestHead::new(
            Method::POST,
            format!("https://localhost{path}").parse().unwrap(),
            Version::HTTP_3,
            HeaderBlock::new(),
        ),
        body,
    )
}

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("HTTP/3 operation timed out")
}

#[tokio::test]
async fn direct_driver_preserves_informationals_headers_and_bidirectional_trailers() {
    let endpoint = TestEndpoint::new().await;
    let client = endpoint.client();
    let mut trailers = HeaderBlock::new();
    trailers.add("x-checksum", "first").unwrap();
    trailers.add("x-between", "middle").unwrap();
    trailers.add("x-checksum", "last").unwrap();
    let request = echo_request(
        "/echo",
        ProxyBody::from_frames([
            Ok(BodyFrame::Data(Bytes::from(vec![b'a'; 512 * 1024]))),
            Ok(BodyFrame::Trailers(trailers.clone())),
        ]),
    );
    let response = within(client.send(request)).await.unwrap();
    let (informationals, head, body) = response.into_parts();
    assert_eq!(informationals.len(), 1);
    assert_eq!(informationals[0].status, StatusCode::EARLY_HINTS);
    assert_eq!(
        head.headers
            .iter()
            .map(|field| field.name())
            .collect::<Vec<_>>(),
        [b"x-first".as_slice(), b"x-repeat", b"x-middle", b"x-repeat"]
    );
    assert_eq!(
        head.headers.get_all("x-repeat").collect::<Vec<_>>(),
        [b"\x80\xff".as_slice(), b"last"]
    );
    let body = within(body.collect()).await.unwrap();
    assert_eq!(body.data.len(), 512 * 1024);
    assert_eq!(body.trailers, Some(trailers));
}

#[tokio::test]
async fn direct_driver_backpressure_and_reset_do_not_block_other_streams() {
    let endpoint = TestEndpoint::new().await;
    let client = endpoint.client();
    // This exceeds both stream windows and all application queues.
    let stalled = within(client.send(echo_request(
        "/echo",
        ProxyBody::full(vec![b'x'; 2 * 1024 * 1024]),
    )))
    .await
    .unwrap();
    let connection = client.inner.client.lock().await.as_ref().unwrap().clone();
    let reset = within(client.send(echo_request("/reset", ProxyBody::empty())))
        .await
        .err()
        .unwrap();
    assert_eq!(reset.kind(), ErrorKind::Reset);
    let response = within(client.send(echo_request("/echo", ProxyBody::full("independent"))))
        .await
        .unwrap();
    assert_eq!(
        within(response.body.collect()).await.unwrap().data,
        "independent"
    );
    assert!(Arc::ptr_eq(
        &connection,
        client.inner.client.lock().await.as_ref().unwrap()
    ));
    assert_eq!(
        within(stalled.body.collect()).await.unwrap().data.len(),
        2 * 1024 * 1024
    );
}

#[tokio::test]
async fn direct_driver_suppresses_head_response_body() {
    let endpoint = TestEndpoint::new().await;
    let mut request = echo_request("/forbidden", ProxyBody::empty());
    request.head.method = Method::HEAD;
    let response = within(endpoint.client().send(request)).await.unwrap();
    assert!(within(response.body.collect())
        .await
        .unwrap()
        .data
        .is_empty());
}

#[tokio::test]
async fn direct_driver_listener_shutdown_fails_pending_requests() {
    let endpoint = TestEndpoint::new().await;
    let client = endpoint.client();
    let initial = within(client.send(echo_request("/echo", ProxyBody::empty())))
        .await
        .unwrap();
    within(initial.body.collect()).await.unwrap();
    let pending = tokio::spawn(async move {
        client
            .send(echo_request("/pending", ProxyBody::empty()))
            .await
    });
    tokio::task::yield_now().await;
    endpoint.task.abort();
    assert!(within(pending).await.unwrap().is_err());
}

#[tokio::test]
async fn direct_driver_verifies_hostname_and_trust_chain() {
    let endpoint = TestEndpoint::new().await;
    for (hostname, verifier) in [
        ("wrong.test", endpoint.verifier.clone()),
        (
            "localhost",
            crate::proxy::tls::h3_server_verifier(&crate::UpstreamTlsConfig::default()).unwrap(),
        ),
    ] {
        assert!(
            within(connect_h3_candidate(endpoint.address, hostname, verifier))
                .await
                .is_err()
        );
    }
    let response = within(
        endpoint
            .client()
            .send(echo_request("/echo", ProxyBody::full("trusted"))),
    )
    .await
    .unwrap();
    assert_eq!(
        within(response.body.collect()).await.unwrap().data,
        "trusted"
    );
}

struct PendingUpload(Option<oneshot::Sender<()>>);
impl Stream for PendingUpload {
    type Item = Result<BodyFrame, ProtocolError>;
    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Pending
    }
}
impl Drop for PendingUpload {
    fn drop(&mut self) {
        if let Some(dropped) = self.0.take() {
            let _ = dropped.send(());
        }
    }
}

#[tokio::test]
async fn direct_driver_dropping_response_cancels_pending_upload_and_keeps_connection() {
    let endpoint = TestEndpoint::new().await;
    let client = endpoint.client();
    let (dropped, received) = oneshot::channel();
    let response = within(client.send(echo_request(
        "/echo",
        ProxyBody::new(PendingUpload(Some(dropped))),
    )))
    .await
    .unwrap();
    drop(response);
    within(received).await.unwrap();
    let response = within(client.send(echo_request("/echo", ProxyBody::full("still open"))))
        .await
        .unwrap();
    assert_eq!(
        within(response.body.collect()).await.unwrap().data,
        "still open"
    );
}

#[tokio::test]
async fn direct_driver_connects_to_ipv6_literal_with_verified_certificate() {
    let endpoint = TestEndpoint::bind("[::1]:0", "[::1]:443").await;
    let target = format!("https://{}/", endpoint.address).parse().unwrap();
    let client = ReverseH3Upstream::new(target, endpoint.verifier.clone());
    let response = within(client.send(echo_request("/echo", ProxyBody::full("ipv6"))))
        .await
        .unwrap();
    assert_eq!(within(response.body.collect()).await.unwrap().data, "ipv6");
}

#[tokio::test(start_paused = true)]
async fn direct_driver_handshake_timeout_is_bounded() {
    let silent_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let verifier =
        crate::proxy::tls::h3_server_verifier(&crate::UpstreamTlsConfig::Insecure).unwrap();
    let error = connect_h3_candidate(silent_peer.local_addr().unwrap(), "localhost", verifier)
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), ErrorKind::Timeout);
}

#[tokio::test]
async fn direct_driver_rejects_excessive_informationals_without_losing_connection() {
    let endpoint = TestEndpoint::new().await;
    let client = endpoint.client();
    let error = within(client.send(echo_request("/too-many-info", ProxyBody::empty())))
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), ErrorKind::Reset);
    let connection = client.inner.client.lock().await.as_ref().unwrap().clone();
    let response = within(client.send(echo_request("/echo", ProxyBody::full("after reset"))))
        .await
        .unwrap();
    assert_eq!(
        within(response.body.collect()).await.unwrap().data,
        "after reset"
    );
    assert!(Arc::ptr_eq(
        &connection,
        client.inner.client.lock().await.as_ref().unwrap()
    ));
}

#[tokio::test]
async fn direct_driver_replaces_draining_connection_after_request_limit() {
    let endpoint = TestEndpoint::new().await;
    let client = endpoint.client();
    for _ in 0..DEFAULT_MAX_REQUESTS_PER_CONNECTION {
        let response = within(client.send(echo_request("/echo", ProxyBody::empty())))
            .await
            .unwrap();
        within(response.body.collect()).await.unwrap();
    }
    let previous = client.inner.client.lock().await.as_ref().unwrap().clone();
    let response = within(client.send(echo_request("/echo", ProxyBody::full("new connection"))))
        .await
        .unwrap();
    assert_eq!(
        within(response.body.collect()).await.unwrap().data,
        "new connection"
    );
    assert!(!Arc::ptr_eq(
        &previous,
        client.inner.client.lock().await.as_ref().unwrap()
    ));
}

#[tokio::test]
async fn direct_driver_listener_ignores_malformed_packets_and_negotiates_versions() {
    let endpoint = TestEndpoint::new().await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(b"not QUIC", endpoint.address).await.unwrap();
    socket
        .send_to(&[0x40; 1200], endpoint.address)
        .await
        .unwrap();
    let mut initial = vec![0; 1200];
    initial[..7].copy_from_slice(&[0xc0, 0xfa, 0xfa, 0xfa, 0xfa, 0, 0]);
    socket.send_to(&initial, endpoint.address).await.unwrap();
    let mut buffer = [0; 1500];
    let (length, source) = within(socket.recv_from(&mut buffer)).await.unwrap();
    assert_eq!(source, endpoint.address);
    let header = quiche::Header::from_slice(&mut buffer[..length], 0).unwrap();
    assert_eq!(header.ty, quiche::Type::VersionNegotiation);
    let response = within(
        endpoint
            .client()
            .send(echo_request("/echo", ProxyBody::full("still serving"))),
    )
    .await
    .unwrap();
    assert_eq!(
        within(response.body.collect()).await.unwrap().data,
        "still serving"
    );
}

#[tokio::test]
async fn direct_driver_propagates_body_failures_without_evicting_connection() {
    let endpoint = TestEndpoint::new().await;
    let client = endpoint.client();
    let body = ProxyBody::from_frames([
        Ok(BodyFrame::Data(Bytes::from_static(b"partial"))),
        Err(protocol(ErrorKind::Io, "upload failed")),
    ]);
    let result = within(client.send(echo_request("/echo", body))).await;
    match result {
        Ok(response) => {
            assert!(within(response.body.collect()).await.is_err());
        }
        Err(error) => assert_eq!(error.kind(), ErrorKind::Reset),
    }
    let connection = client.inner.client.lock().await.as_ref().unwrap().clone();
    let response = within(client.send(echo_request("/echo", ProxyBody::full("recovered"))))
        .await
        .unwrap();
    assert_eq!(
        within(response.body.collect()).await.unwrap().data,
        "recovered"
    );
    assert!(Arc::ptr_eq(
        &connection,
        client.inner.client.lock().await.as_ref().unwrap()
    ));
}

#[tokio::test]
async fn direct_driver_rejects_invalid_request_before_opening_stream() {
    let endpoint = TestEndpoint::new().await;
    let client = endpoint.client();
    let mut invalid = echo_request("/echo", ProxyBody::empty());
    invalid.head.uri = "/no-authority".parse().unwrap();
    assert_eq!(
        within(client.send(invalid)).await.err().unwrap().kind(),
        ErrorKind::MalformedMessage
    );
    let response = within(client.send(echo_request("/echo", ProxyBody::full("valid"))))
        .await
        .unwrap();
    assert_eq!(within(response.body.collect()).await.unwrap().data, "valid");
}

#[tokio::test]
async fn direct_driver_invalid_service_response_resets_only_that_stream() {
    let endpoint = TestEndpoint::new().await;
    let client = endpoint.client();
    assert_eq!(
        within(client.send(echo_request("/invalid-response", ProxyBody::empty())))
            .await
            .err()
            .unwrap()
            .kind(),
        ErrorKind::Reset
    );
    let response = within(client.send(echo_request("/echo", ProxyBody::full("valid response"))))
        .await
        .unwrap();
    assert_eq!(
        within(response.body.collect()).await.unwrap().data,
        "valid response"
    );
}

struct ObservedUpload {
    polled: Option<oneshot::Sender<()>>,
    dropped: Option<oneshot::Sender<()>>,
}
impl Stream for ObservedUpload {
    type Item = Result<BodyFrame, ProtocolError>;
    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(polled) = self.polled.take() {
            let _ = polled.send(());
        }
        Poll::Pending
    }
}
impl Drop for ObservedUpload {
    fn drop(&mut self) {
        if let Some(dropped) = self.dropped.take() {
            let _ = dropped.send(());
        }
    }
}

#[tokio::test]
async fn direct_driver_cancelling_request_before_headers_releases_upload() {
    let endpoint = TestEndpoint::new().await;
    let client = endpoint.client();
    let (polled, started) = oneshot::channel();
    let (dropped, stopped) = oneshot::channel();
    let request_client = client.clone();
    let request = tokio::spawn(async move {
        request_client
            .send(echo_request(
                "/pending",
                ProxyBody::new(ObservedUpload {
                    polled: Some(polled),
                    dropped: Some(dropped),
                }),
            ))
            .await
    });
    within(started).await.unwrap();
    request.abort();
    within(stopped).await.unwrap();
    let response =
        within(client.send(echo_request("/echo", ProxyBody::full("after cancellation"))))
            .await
            .unwrap();
    assert_eq!(
        within(response.body.collect()).await.unwrap().data,
        "after cancellation"
    );
}

#[tokio::test]
async fn websocket_rejections_preserve_http_error_responses() {
    for scenario in 0..4 {
        let context = super::super::test_support::Context::new();
        let mut request = echo_request("/socket", ProxyBody::empty());
        request.head.method = Method::CONNECT;
        request.head.headers.add(":protocol", "websocket").unwrap();
        request
            .head
            .headers
            .add(
                "sec-websocket-version",
                if scenario == 0 { "12" } else { "13" },
            )
            .unwrap();
        let target = (scenario == 1).then(|| "example.test:80".parse().unwrap());
        let response = handle_extended_websocket(
            request,
            context.handler,
            "127.0.0.1:12345".parse().unwrap(),
            target,
            move |_| async move {
                assert!(
                    scenario >= 2,
                    "invalid handshakes must not reach the upstream"
                );
                if scenario == 2 {
                    return Err(protocol(ErrorKind::Io, "upstream unavailable"));
                }
                Ok(ProxyResponse::new(
                    ResponseHead::new(StatusCode::FORBIDDEN, Version::HTTP_3, HeaderBlock::new()),
                    ProxyBody::full("denied by upstream"),
                ))
            },
        )
        .await
        .unwrap();
        assert_eq!(
            response.head.status,
            match scenario {
                0 => StatusCode::BAD_REQUEST,
                1 | 2 => StatusCode::BAD_GATEWAY,
                _ => StatusCode::FORBIDDEN,
            }
        );
        let body = within(response.body.collect()).await.unwrap().data;
        assert!(!body.is_empty());
        if scenario == 3 {
            assert_eq!(body, "denied by upstream");
        }
    }
}

#[tokio::test]
async fn inbound_body_surfaces_explicit_driver_error_once() {
    let (send, recv) = mpsc::channel(2);
    let error = protocol(ErrorKind::Reset, "peer reset while reading DATA");
    send.send(InboundFrame::Error(error.clone())).await.unwrap();
    send.send(InboundFrame::Body(Bytes::from_static(b"after error"), true))
        .await
        .unwrap();
    let mut body = inbound_body(recv);
    assert_eq!(body.next().await.unwrap().unwrap_err(), error);
    assert!(body.next().await.is_none());
}
