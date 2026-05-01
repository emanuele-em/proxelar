use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use proxyapi::{
    InterceptConfig, InterceptDecision, Proxy, ProxyConfig, ProxyEvent, ProxyMode,
    DEFAULT_BODY_CAPTURE_LIMIT,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

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

    let event = tokio::time::timeout(std::time::Duration::from_secs(2), event_rx.recv())
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
    assert!(event_rx.try_recv().is_err());

    let _ = shutdown_tx.send(());
    assert!(handle.await.unwrap().is_ok());
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
        intercept: Some(Arc::clone(&intercept)),
        body_capture_limit: 4,
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

    let intercepted = tokio::time::timeout(std::time::Duration::from_secs(2), event_rx.recv())
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
        intercept: None,
        body_capture_limit: 4,
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
    let body = req.into_body().collect().await?.to_bytes();

    let mut builder = Response::builder().status(http::StatusCode::CREATED);
    if let Some(value) = script_header {
        builder = builder.header("x-seen-script", value);
    }
    if let Some(value) = intercept_header {
        builder = builder.header("x-seen-intercept", value);
    }

    Ok(builder.body(Full::new(body)).unwrap())
}
