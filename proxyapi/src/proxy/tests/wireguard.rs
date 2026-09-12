use super::*;

#[tokio::test(start_paused = true)]
async fn idle_h3_flow_closes_its_queue_and_reports_its_generation() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let ca = Arc::new(Ssl::load_or_generate(dir.path()).unwrap());
    let (events, _events) = mpsc::channel(4);
    let (responses, mut response_rx) = mpsc::channel(4);
    let (completed, mut completed_rx) = mpsc::channel(4);
    let key = UdpFlowKey {
        source: "10.0.0.2:12345".parse().unwrap(),
        destination: "127.0.0.1:443".parse().unwrap(),
    };
    let flow = start_h3_flow(
        key,
        7,
        H3FlowContext {
            handler: CapturingHandler::new(events),
            ca,
            verifier: super::super::tls::h3_server_verifier(&crate::UpstreamTlsConfig::Insecure)
                .unwrap(),
            response_tx: responses,
            completed_tx: completed,
            cancel: CancellationToken::new(),
        },
    )
    .await
    .unwrap();
    // Tokio's paused clock advances to the idle deadline while the flow waits.
    assert_eq!(completed_rx.recv().await, Some((key, 7)));
    assert!(flow.datagrams.is_closed());
    assert!(response_rx.recv().await.is_none());
}

#[derive(Clone)]
struct RejectService;
impl HttpService for RejectService {
    fn call(&mut self, _: ProxyRequest) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
        Box::pin(async {
            Err(ProtocolError::new(
                proxelar_proto::ErrorKind::Reset,
                "unexpected request",
            ))
        })
    }
}

#[tokio::test]
async fn h3_service_reports_missing_authority_and_untrusted_upstream() {
    let context = super::super::test_support::Context::new();
    let config = super::super::http3::server_config(
        context.ca.clone(),
        "upstream.test:443".parse().unwrap(),
        false,
    )
    .unwrap();
    let listener = super::super::http3::H3Listener::bind("127.0.0.1:0".parse().unwrap(), config)
        .await
        .unwrap();
    let destination = listener.local_addr().unwrap();
    let server = tokio::spawn(listener.serve(|_| RejectService));
    let mut service = WireGuardH3Service {
        remote_addr: "10.0.0.2:12345".parse().unwrap(),
        destination,
        handler: context.handler,
        verifier: super::super::tls::h3_server_verifier(&crate::UpstreamTlsConfig::default())
            .unwrap(),
        upstreams: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
    };
    for (uri, websocket, expected) in [
        ("/no-authority", false, http::StatusCode::BAD_REQUEST),
        (
            "https://upstream.test/",
            false,
            http::StatusCode::BAD_GATEWAY,
        ),
        (
            "https://upstream.test/socket",
            true,
            http::StatusCode::BAD_GATEWAY,
        ),
    ] {
        let mut request = super::super::test_support::request(
            if websocket {
                http::Method::CONNECT
            } else {
                http::Method::GET
            },
            uri,
        );
        if websocket {
            request.head.headers.add(":protocol", "websocket").unwrap();
            request
                .head
                .headers
                .add("sec-websocket-version", "13")
                .unwrap();
        }
        let response = tokio::time::timeout(Duration::from_secs(5), service.call(request))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.head.status, expected);
        assert!(!response.body.collect().await.unwrap().data.is_empty());
    }
    server.abort();
}
