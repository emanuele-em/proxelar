use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use proxyapi::{
    InterceptConfig, InterceptDecision, Proxy, ProxyConfig, ProxyEvent, ProxyMode,
    UpstreamTlsConfig, DEFAULT_BODY_CAPTURE_LIMIT,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::{protocol::Role, Message};
use tokio_tungstenite::WebSocketStream;

const EVENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[tokio::test]
async fn test_reverse_proxy_starts_and_shuts_down() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let addr = reserve_loopback_addr().await;

    let ca_dir = tempfile::tempdir().unwrap();

    let (event_tx, _event_rx) = mpsc::channel::<ProxyEvent>(100);
    let config = ProxyConfig {
        addr,
        mode: ProxyMode::Reverse {
            target: "http://127.0.0.1:9999".parse().unwrap(),
        },
        event_tx,
        ca_dir: ca_dir.path().to_path_buf(),
        upstream_tls: UpstreamTlsConfig::Default,
        intercept: None,
        body_capture_limit: DEFAULT_BODY_CAPTURE_LIMIT,
        #[cfg(feature = "scripting")]
        script_path: None,
        replay_rx: None,
    };

    let proxy = Proxy::new(config);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let handle = tokio::spawn(async move {
        proxy
            .start(async {
                shutdown_rx.await.ok();
            })
            .await
    });

    wait_for_tcp(addr).await;

    let _ = shutdown_tx.send(());

    let result = handle.await.unwrap();
    assert!(result.is_ok());
}

#[tokio::test]
async fn reverse_proxy_forwards_http_and_emits_request_complete() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (upstream_addr, upstream_shutdown) = start_upstream_server().await;
    let proxy_addr = reserve_loopback_addr().await;
    let ca_dir = tempfile::tempdir().unwrap();

    let (event_tx, mut event_rx) = mpsc::channel::<ProxyEvent>(100);
    let config = ProxyConfig {
        addr: proxy_addr,
        mode: ProxyMode::Reverse {
            target: format!("http://{upstream_addr}").parse().unwrap(),
        },
        event_tx,
        ca_dir: ca_dir.path().to_path_buf(),
        upstream_tls: UpstreamTlsConfig::Default,
        intercept: None,
        body_capture_limit: DEFAULT_BODY_CAPTURE_LIMIT,
        #[cfg(feature = "scripting")]
        script_path: None,
        replay_rx: None,
    };

    let proxy = Proxy::new(config);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        proxy
            .start(async {
                shutdown_rx.await.ok();
            })
            .await
    });

    wait_for_tcp(proxy_addr).await;

    let response = reqwest::Client::new()
        .get(format!("http://{proxy_addr}/hello?name=proxelar"))
        .header("x-client-test", "roundtrip")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::CREATED);
    assert_eq!(response.headers()["x-upstream-path"], "/hello");
    assert_eq!(response.text().await.unwrap(), "upstream response");

    let event = tokio::time::timeout(EVENT_TIMEOUT, event_rx.recv())
        .await
        .unwrap()
        .unwrap();

    match event {
        ProxyEvent::RequestComplete {
            request, response, ..
        } => {
            assert_eq!(request.uri().path(), "/hello");
            assert_eq!(request.uri().query(), Some("name=proxelar"));
            assert_eq!(
                request.headers().get("x-client-test"),
                Some(b"roundtrip".as_slice())
            );
            assert_eq!(response.status(), http::StatusCode::CREATED);
            assert_eq!(
                response.headers().get("x-upstream-path"),
                Some(b"/hello".as_slice())
            );
            assert_eq!(response.body().as_ref(), b"upstream response");
        }
        other => panic!("expected RequestComplete event, got {other:?}"),
    }

    let _ = shutdown_tx.send(());
    let _ = upstream_shutdown.send(());

    assert!(handle.await.unwrap().is_ok());
}

#[tokio::test]
async fn reverse_proxy_forwards_h2c_post_and_emits_http2_capture() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (upstream_addr, upstream_shutdown) = start_echo_request_body_server().await;
    let proxy_addr = reserve_loopback_addr().await;
    let ca_dir = tempfile::tempdir().unwrap();

    let (event_tx, mut event_rx) = mpsc::channel::<ProxyEvent>(100);
    let config = ProxyConfig {
        addr: proxy_addr,
        mode: ProxyMode::Reverse {
            target: format!("http://{upstream_addr}").parse().unwrap(),
        },
        event_tx,
        ca_dir: ca_dir.path().to_path_buf(),
        upstream_tls: UpstreamTlsConfig::Default,
        intercept: None,
        body_capture_limit: DEFAULT_BODY_CAPTURE_LIMIT,
        #[cfg(feature = "scripting")]
        script_path: None,
        replay_rx: None,
    };

    let proxy = Proxy::new(config);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        proxy
            .start(async {
                shutdown_rx.await.ok();
            })
            .await
    });

    wait_for_tcp(proxy_addr).await;

    let mut sender = connect_h2(proxy_addr).await;
    let request = Request::builder()
        .method(http::Method::POST)
        .version(http::Version::HTTP_2)
        .uri(format!("http://{proxy_addr}/echo?via=h2c"))
        .header("x-client-test", "reverse-h2c")
        .body(Full::new(Bytes::from_static(b"reverse h2 body")))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();

    assert_eq!(response.version(), http::Version::HTTP_2);
    assert_eq!(response.status(), http::StatusCode::CREATED);
    assert_eq!(response.headers()["x-upstream-version"], "HTTP/1.1");
    assert_eq!(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .as_ref(),
        b"reverse h2 body"
    );

    let event = tokio::time::timeout(EVENT_TIMEOUT, event_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match event {
        ProxyEvent::RequestComplete {
            request, response, ..
        } => {
            assert_eq!(request.version(), http::Version::HTTP_2);
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri().path(), "/echo");
            assert_eq!(request.uri().query(), Some("via=h2c"));
            assert_eq!(
                request.headers().get("x-client-test"),
                Some(b"reverse-h2c".as_slice())
            );
            assert_eq!(request.body().as_ref(), b"reverse h2 body");
            assert_eq!(response.status(), http::StatusCode::CREATED);
            assert_eq!(response.body().as_ref(), b"reverse h2 body");
        }
        other => panic!("expected RequestComplete event, got {other:?}"),
    }

    let _ = shutdown_tx.send(());
    let _ = upstream_shutdown.send(());
    assert!(handle.await.unwrap().is_ok());
}

#[tokio::test]
async fn reverse_proxy_returns_502_when_target_is_unreachable() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let unused_upstream = reserve_loopback_addr().await;
    let proxy_addr = reserve_loopback_addr().await;
    let ca_dir = tempfile::tempdir().unwrap();

    let (event_tx, mut event_rx) = mpsc::channel::<ProxyEvent>(100);
    let config = ProxyConfig {
        addr: proxy_addr,
        mode: ProxyMode::Reverse {
            target: format!("http://{unused_upstream}").parse().unwrap(),
        },
        event_tx,
        ca_dir: ca_dir.path().to_path_buf(),
        upstream_tls: UpstreamTlsConfig::Default,
        intercept: None,
        body_capture_limit: DEFAULT_BODY_CAPTURE_LIMIT,
        #[cfg(feature = "scripting")]
        script_path: None,
        replay_rx: None,
    };

    let proxy = Proxy::new(config);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        proxy
            .start(async {
                shutdown_rx.await.ok();
            })
            .await
    });

    wait_for_tcp(proxy_addr).await;

    let response = reqwest::Client::new()
        .get(format!("http://{proxy_addr}/missing"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
    assert_eq!(response.text().await.unwrap(), "Bad Gateway");
    let event = tokio::time::timeout(EVENT_TIMEOUT, event_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match event {
        ProxyEvent::RequestComplete {
            request, response, ..
        } => {
            assert_eq!(request.uri().path(), "/missing");
            assert_eq!(response.status(), http::StatusCode::BAD_GATEWAY);
            assert_eq!(response.body().as_ref(), b"Bad Gateway");
        }
        other => panic!("expected RequestComplete event, got {other:?}"),
    }

    let _ = shutdown_tx.send(());
    assert!(handle.await.unwrap().is_ok());
}

#[tokio::test]
async fn reverse_proxy_default_upstream_tls_rejects_private_ca() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (upstream_addr, upstream_shutdown, _ca_pem, _) =
        start_private_ca_https_upstream(false).await;

    let (status, body) =
        request_private_ca_https_upstream(upstream_addr, UpstreamTlsConfig::Default).await;

    assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY);
    assert_eq!(body, "Bad Gateway");

    let _ = upstream_shutdown.send(());
}

#[tokio::test]
async fn reverse_proxy_default_with_ca_file_trusts_private_ca() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (upstream_addr, upstream_shutdown, ca_pem, _) =
        start_private_ca_https_upstream(false).await;
    let ca_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(ca_file.path(), ca_pem).unwrap();

    let (status, body) = request_private_ca_https_upstream(
        upstream_addr,
        UpstreamTlsConfig::DefaultWithCaFile(ca_file.path().to_path_buf()),
    )
    .await;

    assert_eq!(status, reqwest::StatusCode::CREATED);
    assert_eq!(body, "upstream response");

    let _ = upstream_shutdown.send(());
}

#[tokio::test]
async fn reverse_proxy_ca_file_only_trusts_private_ca() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (upstream_addr, upstream_shutdown, ca_pem, _) =
        start_private_ca_https_upstream(false).await;
    let ca_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(ca_file.path(), ca_pem).unwrap();

    let (status, body) = request_private_ca_https_upstream(
        upstream_addr,
        UpstreamTlsConfig::CaFileOnly(ca_file.path().to_path_buf()),
    )
    .await;

    assert_eq!(status, reqwest::StatusCode::CREATED);
    assert_eq!(body, "upstream response");

    let _ = upstream_shutdown.send(());
}

#[tokio::test]
async fn reverse_proxy_insecure_upstream_tls_accepts_private_ca() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (upstream_addr, upstream_shutdown, _ca_pem, _) =
        start_private_ca_https_upstream(false).await;

    let (status, body) =
        request_private_ca_https_upstream(upstream_addr, UpstreamTlsConfig::Insecure).await;

    assert_eq!(status, reqwest::StatusCode::CREATED);
    assert_eq!(body, "upstream response");

    let _ = upstream_shutdown.send(());
}

#[tokio::test]
async fn reverse_https_propagates_client_alpn_offers_upstream_in_order() {
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, ServerName};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio_rustls::TlsConnector;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let (upstream_addr, upstream_shutdown, _ca_pem, upstream_offers) =
        start_private_ca_https_upstream(false).await;
    let proxy_addr = reserve_loopback_addr().await;
    let ca_dir = tempfile::tempdir().unwrap();
    let (event_tx, _event_rx) = mpsc::channel::<ProxyEvent>(16);
    let proxy = Proxy::new(ProxyConfig {
        addr: proxy_addr,
        mode: ProxyMode::Reverse {
            target: format!("https://{upstream_addr}").parse().unwrap(),
        },
        event_tx,
        ca_dir: ca_dir.path().to_path_buf(),
        upstream_tls: UpstreamTlsConfig::Insecure,
        intercept: None,
        body_capture_limit: DEFAULT_BODY_CAPTURE_LIMIT,
        #[cfg(feature = "scripting")]
        script_path: None,
        replay_rx: None,
    });
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let proxy_task = tokio::spawn(async move {
        proxy
            .start(async {
                shutdown_rx.await.ok();
            })
            .await
    });
    wait_for_tcp(proxy_addr).await;

    let proxy_ca = std::fs::read(ca_dir.path().join("proxelar-ca.pem")).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(&proxy_ca).unwrap())
        .unwrap();
    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let expected_offers = vec![b"x-proxelar-test".to_vec(), b"http/1.1".to_vec()];
    client_config.alpn_protocols = expected_offers.clone();
    let tcp = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let mut tls = TlsConnector::from(Arc::new(client_config))
        .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
        .await
        .unwrap();
    tls.write_all(
        format!("GET /alpn HTTP/1.1\r\nHost: {proxy_addr}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut response = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        match tls.read(&mut buffer).await {
            Ok(0) => break,
            Ok(length) => response.extend_from_slice(&buffer[..length]),
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(error) => panic!("failed to read reverse TLS response: {error}"),
        }
    }

    assert!(response.starts_with(b"HTTP/1.1 201"));
    assert_eq!(
        *upstream_offers
            .lock()
            .unwrap_or_else(|error| error.into_inner()),
        expected_offers
    );

    let _ = shutdown_tx.send(());
    let _ = upstream_shutdown.send(());
    assert!(proxy_task.await.unwrap().is_ok());
}

#[tokio::test]
async fn reverse_https_negotiates_h2_with_the_upstream() {
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, ServerName};
    use tokio_rustls::TlsConnector;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let (upstream_addr, upstream_shutdown, _ca_pem, upstream_offers) =
        start_private_ca_https_upstream(true).await;
    let proxy_addr = reserve_loopback_addr().await;
    let ca_dir = tempfile::tempdir().unwrap();
    let (event_tx, _event_rx) = mpsc::channel::<ProxyEvent>(16);
    let proxy = Proxy::new(ProxyConfig {
        addr: proxy_addr,
        mode: ProxyMode::Reverse {
            target: format!("https://{upstream_addr}").parse().unwrap(),
        },
        event_tx,
        ca_dir: ca_dir.path().to_path_buf(),
        upstream_tls: UpstreamTlsConfig::Insecure,
        intercept: None,
        body_capture_limit: DEFAULT_BODY_CAPTURE_LIMIT,
        #[cfg(feature = "scripting")]
        script_path: None,
        replay_rx: None,
    });
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let proxy_task = tokio::spawn(async move {
        proxy
            .start(async {
                shutdown_rx.await.ok();
            })
            .await
    });
    wait_for_tcp(proxy_addr).await;

    let proxy_ca = std::fs::read(ca_dir.path().join("proxelar-ca.pem")).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(&proxy_ca).unwrap())
        .unwrap();
    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let expected_offers = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    client_config.alpn_protocols = expected_offers.clone();
    let tcp = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let tls = TlsConnector::from(Arc::new(client_config))
        .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(TokioIo::new(tls))
        .await
        .unwrap();
    let connection_task = tokio::spawn(connection);
    let request = Request::builder()
        .uri(format!("https://{proxy_addr}/h2"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), http::StatusCode::CREATED);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "upstream response"
    );
    assert_eq!(
        *upstream_offers
            .lock()
            .unwrap_or_else(|error| error.into_inner()),
        expected_offers
    );

    drop(sender);
    let _ = shutdown_tx.send(());
    let _ = upstream_shutdown.send(());
    assert!(proxy_task.await.unwrap().is_ok());
    connection_task.abort();
}

#[tokio::test]
async fn reverse_https_proxies_rfc8441_to_an_h2_upstream() {
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, ServerName};
    use tokio_rustls::TlsConnector;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let (upstream_addr, upstream_shutdown, _ca_pem, _upstream_offers) =
        start_private_ca_https_upstream(true).await;
    let proxy_addr = reserve_loopback_addr().await;
    let ca_dir = tempfile::tempdir().unwrap();
    let (event_tx, mut event_rx) = mpsc::channel::<ProxyEvent>(32);
    let proxy = Proxy::new(ProxyConfig {
        addr: proxy_addr,
        mode: ProxyMode::Reverse {
            target: format!("https://{upstream_addr}").parse().unwrap(),
        },
        event_tx,
        ca_dir: ca_dir.path().to_path_buf(),
        upstream_tls: UpstreamTlsConfig::Insecure,
        intercept: None,
        body_capture_limit: DEFAULT_BODY_CAPTURE_LIMIT,
        #[cfg(feature = "scripting")]
        script_path: None,
        replay_rx: None,
    });
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let proxy_task = tokio::spawn(async move {
        proxy
            .start(async {
                shutdown_rx.await.ok();
            })
            .await
    });
    wait_for_tcp(proxy_addr).await;

    let proxy_ca = std::fs::read(ca_dir.path().join("proxelar-ca.pem")).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(&proxy_ca).unwrap())
        .unwrap();
    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tcp = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let tls = TlsConnector::from(Arc::new(client_config))
        .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
        .await
        .unwrap();
    let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(TokioIo::new(tls))
        .await
        .unwrap();
    let connection_task = tokio::spawn(connection);

    let ordinary = Request::builder()
        .uri(format!("https://{proxy_addr}/ready"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    assert_eq!(
        sender.send_request(ordinary).await.unwrap().status(),
        http::StatusCode::CREATED
    );

    let mut request = Request::builder()
        .method(http::Method::CONNECT)
        .version(http::Version::HTTP_2)
        .uri(format!("https://{proxy_addr}/chat"))
        .header("sec-websocket-version", "13")
        .header("sec-websocket-protocol", "chat")
        .body(Full::new(Bytes::new()))
        .unwrap();
    request
        .extensions_mut()
        .insert(hyper::ext::Protocol::from_static("websocket"));
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(response.headers()["sec-websocket-protocol"], "chat");

    let upgraded = hyper::upgrade::on(response).await.unwrap();
    let mut websocket =
        WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Client, None).await;
    websocket
        .send(Message::Text("through-h2".into()))
        .await
        .unwrap();
    assert_eq!(
        websocket.next().await.unwrap().unwrap(),
        Message::Text("through-h2".into())
    );
    websocket.close(None).await.unwrap();

    let mut connected = false;
    let mut client_frame = false;
    let mut server_frame = false;
    tokio::time::timeout(EVENT_TIMEOUT, async {
        while !(connected && client_frame && server_frame) {
            match event_rx.recv().await.unwrap() {
                ProxyEvent::WebSocketConnected {
                    request, response, ..
                } => {
                    connected = true;
                    assert_eq!(request.uri().path(), "/chat");
                    assert_eq!(response.version(), http::Version::HTTP_2);
                }
                ProxyEvent::WebSocketFrame { frame, .. } => match frame.direction {
                    proxyapi_models::WsDirection::ClientToServer => {
                        client_frame |= frame.payload.as_ref() == b"through-h2";
                    }
                    proxyapi_models::WsDirection::ServerToClient => {
                        server_frame |= frame.payload.as_ref() == b"through-h2";
                    }
                },
                _ => {}
            }
        }
    })
    .await
    .unwrap();

    drop(sender);
    let _ = shutdown_tx.send(());
    let _ = upstream_shutdown.send(());
    assert!(proxy_task.await.unwrap().is_ok());
    connection_task.abort();
}

#[tokio::test]
async fn reverse_proxy_intercepts_oversized_request_before_streaming_original() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (upstream_addr, upstream_shutdown) = start_echo_request_body_server().await;
    let proxy_addr = reserve_loopback_addr().await;
    let ca_dir = tempfile::tempdir().unwrap();
    let intercept = InterceptConfig::new();
    intercept.set_enabled(true);

    let (event_tx, mut event_rx) = mpsc::channel::<ProxyEvent>(100);
    let config = ProxyConfig {
        addr: proxy_addr,
        mode: ProxyMode::Reverse {
            target: format!("http://{upstream_addr}").parse().unwrap(),
        },
        event_tx,
        ca_dir: ca_dir.path().to_path_buf(),
        upstream_tls: UpstreamTlsConfig::Default,
        intercept: Some(Arc::clone(&intercept)),
        body_capture_limit: Some(4),
        #[cfg(feature = "scripting")]
        script_path: None,
        replay_rx: None,
    };

    let proxy = Proxy::new(config);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        proxy
            .start(async {
                shutdown_rx.await.ok();
            })
            .await
    });

    wait_for_tcp(proxy_addr).await;

    let response_task = tokio::spawn(async move {
        reqwest::Client::new()
            .post(format!("http://{proxy_addr}/upload"))
            .body("abcdef")
            .send()
            .await
            .unwrap()
    });

    let intercepted = tokio::time::timeout(EVENT_TIMEOUT, event_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let (id, method, uri, mut headers, body) = match intercepted {
        ProxyEvent::RequestIntercepted { id, request } => {
            assert_eq!(request.uri().path(), "/upload");
            assert_eq!(request.body().as_ref(), b"abcd");
            (
                id,
                request.method().to_string(),
                request.uri().to_string(),
                request.headers().clone(),
                request.body().clone(),
            )
        }
        other => panic!("expected RequestIntercepted event, got {other:?}"),
    };
    headers.add("x-intercept", "yes").unwrap();
    assert!(intercept.resolve(
        id,
        InterceptDecision::Modified {
            method,
            uri,
            headers,
            body,
        },
    ));

    let response = response_task.await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::CREATED);
    assert_eq!(response.headers()["x-seen-intercept"], "yes");
    assert_eq!(response.text().await.unwrap(), "abcdef");

    let _ = shutdown_tx.send(());
    let _ = upstream_shutdown.send(());
    assert!(handle.await.unwrap().is_ok());
}

#[tokio::test]
async fn reverse_proxy_intercept_drop_emits_request_complete() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (upstream_addr, upstream_shutdown) = start_upstream_server().await;
    let proxy_addr = reserve_loopback_addr().await;
    let ca_dir = tempfile::tempdir().unwrap();
    let intercept = InterceptConfig::new();
    intercept.set_enabled(true);

    let (event_tx, mut event_rx) = mpsc::channel::<ProxyEvent>(100);
    let config = ProxyConfig {
        addr: proxy_addr,
        mode: ProxyMode::Reverse {
            target: format!("http://{upstream_addr}").parse().unwrap(),
        },
        event_tx,
        ca_dir: ca_dir.path().to_path_buf(),
        upstream_tls: UpstreamTlsConfig::Default,
        intercept: Some(Arc::clone(&intercept)),
        body_capture_limit: DEFAULT_BODY_CAPTURE_LIMIT,
        #[cfg(feature = "scripting")]
        script_path: None,
        replay_rx: None,
    };

    let proxy = Proxy::new(config);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        proxy
            .start(async {
                shutdown_rx.await.ok();
            })
            .await
    });

    wait_for_tcp(proxy_addr).await;

    let response_task = tokio::spawn(async move {
        reqwest::Client::new()
            .get(format!("http://{proxy_addr}/blocked"))
            .send()
            .await
            .unwrap()
    });

    let id = match tokio::time::timeout(EVENT_TIMEOUT, event_rx.recv())
        .await
        .unwrap()
        .unwrap()
    {
        ProxyEvent::RequestIntercepted { id, request } => {
            assert_eq!(request.uri().path(), "/blocked");
            id
        }
        other => panic!("expected RequestIntercepted event, got {other:?}"),
    };

    assert!(intercept.resolve(
        id,
        InterceptDecision::Block {
            status: 451,
            body: Bytes::from_static(b"blocked by test"),
        },
    ));

    let response = response_task.await.unwrap();
    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
    );
    assert_eq!(response.text().await.unwrap(), "blocked by test");

    match tokio::time::timeout(EVENT_TIMEOUT, event_rx.recv())
        .await
        .unwrap()
        .unwrap()
    {
        ProxyEvent::RequestComplete {
            id: complete_id,
            request,
            response,
        } => {
            assert_eq!(complete_id, id);
            assert_eq!(request.uri().path(), "/blocked");
            assert_eq!(
                response.status(),
                http::StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
            );
            assert_eq!(response.body().as_ref(), b"blocked by test");
        }
        other => panic!("expected RequestComplete event, got {other:?}"),
    }

    let _ = shutdown_tx.send(());
    let _ = upstream_shutdown.send(());
    assert!(handle.await.unwrap().is_ok());
}

#[cfg(feature = "scripting")]
#[tokio::test]
async fn reverse_proxy_runs_scripts_for_oversized_request_and_response() {
    use std::io::Write;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let (upstream_addr, upstream_shutdown) = start_echo_request_body_server().await;
    let proxy_addr = reserve_loopback_addr().await;
    let ca_dir = tempfile::tempdir().unwrap();
    let mut script = tempfile::NamedTempFile::new().unwrap();
    script
        .write_all(
            br#"
            function on_request(req)
                req.headers:set("x-script", "yes")
                return req
            end

            function on_response(req, res)
                res.headers:set("x-response-script", "yes")
                return res
            end
            "#,
        )
        .unwrap();
    script.flush().unwrap();

    let (event_tx, _event_rx) = mpsc::channel::<ProxyEvent>(100);
    let config = ProxyConfig {
        addr: proxy_addr,
        mode: ProxyMode::Reverse {
            target: format!("http://{upstream_addr}").parse().unwrap(),
        },
        event_tx,
        ca_dir: ca_dir.path().to_path_buf(),
        upstream_tls: UpstreamTlsConfig::Default,
        intercept: None,
        body_capture_limit: Some(4),
        script_path: Some(script.path().to_path_buf()),
        replay_rx: None,
    };

    let proxy = Proxy::new(config);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        proxy
            .start(async {
                shutdown_rx.await.ok();
            })
            .await
    });

    wait_for_tcp(proxy_addr).await;

    let response = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/scripted"))
        .body("abcdef")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::CREATED);
    assert_eq!(response.headers()["x-seen-script"], "yes");
    assert_eq!(response.headers()["x-response-script"], "yes");
    assert_eq!(response.text().await.unwrap(), "abcdef");

    let _ = shutdown_tx.send(());
    let _ = upstream_shutdown.send(());
    assert!(handle.await.unwrap().is_ok());
}

#[cfg(feature = "scripting")]
#[tokio::test]
async fn reverse_proxy_lua_short_circuit_emits_request_complete() {
    use std::io::Write;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let unused_upstream = reserve_loopback_addr().await;
    let proxy_addr = reserve_loopback_addr().await;
    let ca_dir = tempfile::tempdir().unwrap();
    let mut script = tempfile::NamedTempFile::new().unwrap();
    script
        .write_all(
            br#"
            function on_request(req)
                return {
                    status = 202,
                    headers = { ["x-script"] = "short" },
                    body = "short-circuited"
                }
            end
            "#,
        )
        .unwrap();
    script.flush().unwrap();

    let (event_tx, mut event_rx) = mpsc::channel::<ProxyEvent>(100);
    let config = ProxyConfig {
        addr: proxy_addr,
        mode: ProxyMode::Reverse {
            target: format!("http://{unused_upstream}").parse().unwrap(),
        },
        event_tx,
        ca_dir: ca_dir.path().to_path_buf(),
        upstream_tls: UpstreamTlsConfig::Default,
        intercept: None,
        body_capture_limit: DEFAULT_BODY_CAPTURE_LIMIT,
        script_path: Some(script.path().to_path_buf()),
        replay_rx: None,
    };

    let proxy = Proxy::new(config);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        proxy
            .start(async {
                shutdown_rx.await.ok();
            })
            .await
    });

    wait_for_tcp(proxy_addr).await;

    let response = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/script-short"))
        .body("request body")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::ACCEPTED);
    assert_eq!(response.headers()["x-script"], "short");
    assert_eq!(response.text().await.unwrap(), "short-circuited");

    match tokio::time::timeout(EVENT_TIMEOUT, event_rx.recv())
        .await
        .unwrap()
        .unwrap()
    {
        ProxyEvent::RequestComplete {
            request, response, ..
        } => {
            assert_eq!(request.uri().path(), "/script-short");
            assert_eq!(request.body().as_ref(), b"request body");
            assert_eq!(response.status(), http::StatusCode::ACCEPTED);
            assert_eq!(
                response.headers().get("x-script"),
                Some(b"short".as_slice())
            );
            assert_eq!(response.body().as_ref(), b"short-circuited");
        }
        other => panic!("expected RequestComplete event, got {other:?}"),
    }

    let _ = shutdown_tx.send(());
    assert!(handle.await.unwrap().is_ok());
}

async fn reserve_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

async fn wait_for_tcp(addr: SocketAddr) {
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(10);
    loop {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(_) => break,
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            }
            Err(e) => panic!("Server failed to start within timeout: {e}"),
        }
    }
}

async fn connect_h2(addr: SocketAddr) -> hyper::client::conn::http2::SendRequest<Full<Bytes>> {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender
}

async fn request_private_ca_https_upstream(
    upstream_addr: SocketAddr,
    upstream_tls: UpstreamTlsConfig,
) -> (reqwest::StatusCode, String) {
    let proxy_addr = reserve_loopback_addr().await;
    let ca_dir = tempfile::tempdir().unwrap();
    let (event_tx, _event_rx) = mpsc::channel::<ProxyEvent>(100);
    let config = ProxyConfig {
        addr: proxy_addr,
        mode: ProxyMode::Reverse {
            target: format!("https://{upstream_addr}").parse().unwrap(),
        },
        event_tx,
        ca_dir: ca_dir.path().to_path_buf(),
        upstream_tls,
        intercept: None,
        body_capture_limit: DEFAULT_BODY_CAPTURE_LIMIT,
        #[cfg(feature = "scripting")]
        script_path: None,
        replay_rx: None,
    };

    let proxy = Proxy::new(config);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        proxy
            .start(async {
                shutdown_rx.await.ok();
            })
            .await
    });

    wait_for_tcp(proxy_addr).await;

    let proxy_ca = std::fs::read(ca_dir.path().join("proxelar-ca.pem")).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&proxy_ca).unwrap())
        .build()
        .unwrap();
    let response = client
        .get(format!("https://{proxy_addr}/hello"))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();

    let _ = shutdown_tx.send(());
    assert!(handle.await.unwrap().is_ok());

    (status, body)
}

async fn start_upstream_server() -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    let Ok((stream, _)) = result else {
                        break;
                    };
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let service = service_fn(upstream_response);
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, service)
                            .await;
                    });
                }
                _ = &mut shutdown_rx => break,
            }
        }
    });

    (addr, shutdown_tx)
}

async fn start_private_ca_https_upstream(
    h2: bool,
) -> (
    SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    Vec<u8>,
    Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
) {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose,
    };
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use time::{Duration, OffsetDateTime};
    use tokio_rustls::TlsAcceptor;

    fn set_validity(params: &mut CertificateParams) {
        params.not_before = OffsetDateTime::now_utc() - Duration::seconds(60);
        params.not_after = params.not_before + Duration::days(1);
    }

    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Proxelar Upstream Test CA");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    set_validity(&mut ca_params);
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem().into_bytes();
    let issuer = Issuer::new(ca_params, ca_key);

    let mut server_params = CertificateParams::new(vec!["127.0.0.1".to_owned()]).unwrap();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "127.0.0.1");
    server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    set_validity(&mut server_params);
    let server_key = KeyPair::generate().unwrap();
    let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();
    let certs = vec![server_cert.der().clone()];
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der()));

    let mut server_config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .unwrap();
    if h2 {
        server_config.alpn_protocols = vec![b"h2".to_vec()];
    }
    let offered_alpn = Arc::new(std::sync::Mutex::new(Vec::new()));
    server_config.cert_resolver = Arc::new(RecordingCertResolver {
        inner: Arc::clone(&server_config.cert_resolver),
        offered: Arc::clone(&offered_alpn),
    });
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    let Ok((stream, _)) = result else {
                        break;
                    };
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let Ok(stream) = acceptor.accept(stream).await else {
                            return;
                        };
                        if h2 {
                            let _ = proxelar_proto::http2::serve_connection(
                                stream,
                                ReverseH2Upstream,
                                proxelar_proto::http2::ConnectionConfig {
                                    enable_extended_connect: true,
                                    ..proxelar_proto::http2::ConnectionConfig::default()
                                },
                            )
                            .await;
                        } else {
                            let io = TokioIo::new(stream);
                            let service = service_fn(upstream_response);
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, service)
                                .await;
                        }
                    });
                }
                _ = &mut shutdown_rx => break,
            }
        }
    });

    (addr, shutdown_tx, ca_pem, offered_alpn)
}

#[derive(Clone)]
struct ReverseH2Upstream;

impl proxelar_proto::HttpService for ReverseH2Upstream {
    fn call(
        &mut self,
        request: proxyapi::ProxyRequest,
    ) -> proxelar_proto::BoxFuture<'_, Result<proxyapi::ProxyResponse, proxyapi::ProtocolError>>
    {
        Box::pin(async move {
            if request.head.method == http::Method::CONNECT
                && request.head.headers.get(":protocol") == Some(b"websocket".as_slice())
            {
                let (tunnel, body) = proxelar_proto::http2::body_tunnel(request.body, 64 * 1024);
                tokio::spawn(async move {
                    let mut websocket =
                        WebSocketStream::from_raw_socket(tunnel, Role::Server, None).await;
                    while let Some(Ok(message)) = websocket.next().await {
                        let close = message.is_close();
                        if websocket.send(message).await.is_err() || close {
                            break;
                        }
                    }
                });
                let mut headers = proxyapi_models::HeaderBlock::new();
                if let Some(protocol) = request.head.headers.get("sec-websocket-protocol") {
                    headers.add("sec-websocket-protocol", protocol).unwrap();
                }
                return Ok(proxyapi::ProxyResponse::new(
                    proxyapi::ResponseHead::new(
                        http::StatusCode::OK,
                        http::Version::HTTP_2,
                        headers,
                    ),
                    body,
                ));
            }

            let mut headers = proxyapi_models::HeaderBlock::new();
            headers
                .add("x-upstream-path", request.head.uri.path())
                .unwrap();
            Ok(proxyapi::ProxyResponse::new(
                proxyapi::ResponseHead::new(
                    http::StatusCode::CREATED,
                    http::Version::HTTP_2,
                    headers,
                ),
                proxyapi::ProxyBody::full(Bytes::from_static(b"upstream response")),
            ))
        })
    }
}

#[derive(Debug)]
struct RecordingCertResolver {
    inner: Arc<dyn rustls::server::ResolvesServerCert>,
    offered: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
}

impl rustls::server::ResolvesServerCert for RecordingCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        *self
            .offered
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = client_hello
            .alpn()
            .into_iter()
            .flatten()
            .map(<[u8]>::to_vec)
            .collect();
        self.inner.resolve(client_hello)
    }
}

async fn start_echo_request_body_server() -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    let Ok((stream, _)) = result else {
                        break;
                    };
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let service = service_fn(echo_request_body_response);
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, service)
                            .await;
                    });
                }
                _ = &mut shutdown_rx => break,
            }
        }
    });

    (addr, shutdown_tx)
}

async fn upstream_response(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path().to_owned();
    Ok(Response::builder()
        .status(http::StatusCode::CREATED)
        .header("x-upstream-path", path)
        .body(Full::new(Bytes::from_static(b"upstream response")))
        .unwrap())
}

async fn echo_request_body_response(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let script_header = req.headers().get("x-script").cloned();
    let intercept_header = req.headers().get("x-intercept").cloned();
    let upstream_version = format!("{:?}", req.version());
    let body = req.into_body().collect().await?.to_bytes();

    let mut builder = Response::builder()
        .status(http::StatusCode::CREATED)
        .header("x-upstream-version", upstream_version);
    if let Some(value) = script_header {
        builder = builder.header("x-seen-script", value);
    }
    if let Some(value) = intercept_header {
        builder = builder.header("x-seen-intercept", value);
    }

    Ok(builder.body(Full::new(body)).unwrap())
}
