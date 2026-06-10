use bytes::Bytes;
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
        #[cfg(feature = "scripting")]
        allow_c_modules: false,
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
        #[cfg(feature = "scripting")]
        allow_c_modules: false,
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
            assert_eq!(request.headers()["x-client-test"], "roundtrip");
            assert_eq!(response.status(), http::StatusCode::CREATED);
            assert_eq!(response.headers()["x-upstream-path"], "/hello");
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
        #[cfg(feature = "scripting")]
        allow_c_modules: false,
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
            assert_eq!(request.headers()["x-client-test"], "reverse-h2c");
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
        #[cfg(feature = "scripting")]
        allow_c_modules: false,
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
    let (upstream_addr, upstream_shutdown, _ca_pem) = start_private_ca_https_upstream().await;

    let (status, body) =
        request_private_ca_https_upstream(upstream_addr, UpstreamTlsConfig::Default).await;

    assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY);
    assert_eq!(body, "Bad Gateway");

    let _ = upstream_shutdown.send(());
}

#[tokio::test]
async fn reverse_proxy_default_with_ca_file_trusts_private_ca() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (upstream_addr, upstream_shutdown, ca_pem) = start_private_ca_https_upstream().await;
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
    let (upstream_addr, upstream_shutdown, ca_pem) = start_private_ca_https_upstream().await;
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
    let (upstream_addr, upstream_shutdown, _ca_pem) = start_private_ca_https_upstream().await;

    let (status, body) =
        request_private_ca_https_upstream(upstream_addr, UpstreamTlsConfig::Insecure).await;

    assert_eq!(status, reqwest::StatusCode::CREATED);
    assert_eq!(body, "upstream response");

    let _ = upstream_shutdown.send(());
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
        #[cfg(feature = "scripting")]
        allow_c_modules: false,
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
    headers.insert("x-intercept", "yes".parse().unwrap());
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
        #[cfg(feature = "scripting")]
        allow_c_modules: false,
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
                req.headers["x-script"] = "yes"
                return req
            end

            function on_response(req, res)
                res.headers["x-response-script"] = "yes"
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
        allow_c_modules: false,
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
        allow_c_modules: false,
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
            assert_eq!(response.headers()["x-script"], "short");
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
        #[cfg(feature = "scripting")]
        allow_c_modules: false,
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
        .get(format!("http://{proxy_addr}/hello"))
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

async fn start_private_ca_https_upstream() -> (SocketAddr, tokio::sync::oneshot::Sender<()>, Vec<u8>)
{
    use openssl::{
        asn1::{Asn1Integer, Asn1Time},
        bn::BigNum,
        hash::MessageDigest,
        pkey::{PKey, Private},
        rsa::Rsa,
        x509::{
            extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
            X509Builder, X509NameBuilder, X509,
        },
    };
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer};
    use tokio_rustls::TlsAcceptor;

    fn random_serial_number() -> Asn1Integer {
        let mut serial = [0; 16];
        openssl::rand::rand_bytes(&mut serial).unwrap();
        Asn1Integer::from_bn(&BigNum::from_slice(&serial).unwrap()).unwrap()
    }

    fn set_validity(builder: &mut openssl::x509::X509Builder) {
        let not_before = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - 60;
        builder
            .set_not_before(Asn1Time::from_unix(not_before).unwrap().as_ref())
            .unwrap();
        builder
            .set_not_after(Asn1Time::from_unix(not_before + 86_400).unwrap().as_ref())
            .unwrap();
    }

    fn generate_ca() -> (PKey<Private>, X509) {
        let ca_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder
            .append_entry_by_text("CN", "Proxelar Upstream Test CA")
            .unwrap();
        let name = name_builder.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(random_serial_number().as_ref())
            .unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&ca_key).unwrap();
        set_validity(&mut builder);
        builder
            .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
        (ca_key, builder.build())
    }

    fn generate_server_cert(ca_key: &PKey<Private>, ca_cert: &X509) -> (PKey<Private>, X509) {
        let server_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder
            .append_entry_by_text("CN", "127.0.0.1")
            .unwrap();
        let name = name_builder.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(random_serial_number().as_ref())
            .unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(ca_cert.subject_name()).unwrap();
        builder.set_pubkey(&server_key).unwrap();
        set_validity(&mut builder);
        builder
            .append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .digital_signature()
                    .key_encipherment()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        builder
            .append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
            .unwrap();
        let subject_alt_name = SubjectAlternativeName::new()
            .ip("127.0.0.1")
            .build(&builder.x509v3_context(Some(ca_cert), None))
            .unwrap();
        builder.append_extension(subject_alt_name).unwrap();
        builder.sign(ca_key, MessageDigest::sha256()).unwrap();
        (server_key, builder.build())
    }

    let (ca_key, ca_cert) = generate_ca();
    let (server_key, server_cert) = generate_server_cert(&ca_key, &ca_cert);
    let ca_pem = ca_cert.to_pem().unwrap();
    let certs = vec![CertificateDer::from(server_cert.to_der().unwrap())];
    let private_key = PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(
        server_key.rsa().unwrap().private_key_to_der().unwrap(),
    ));

    let server_config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .unwrap();
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

    (addr, shutdown_tx, ca_pem)
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
