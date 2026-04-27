use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use proxyapi::{Proxy, ProxyConfig, ProxyEvent, ProxyMode};
use std::net::SocketAddr;
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

async fn upstream_response(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path().to_owned();
    Ok(Response::builder()
        .status(http::StatusCode::CREATED)
        .header("x-upstream-path", path)
        .body(Full::new(Bytes::from_static(b"upstream response")))
        .unwrap())
}
