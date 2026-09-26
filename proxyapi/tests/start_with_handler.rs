//! Integration tests for [`Proxy::start_with_handler`].
//!
//! These tests start a real forward proxy with a custom [`HttpHandler`] and
//! assert behavior through a local upstream server and raw HTTP clients.

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use proxyapi::{
    HttpContext, HttpHandler, Proxy, ProxyConfig, ProxyMode, ProxyRequest, ProxyResponse,
    RequestOrResponse, UpstreamTlsConfig,
};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

#[tokio::test]
async fn test_start_with_handler_starts_and_shuts_down() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let addr = reserve_loopback_addr().await;
    let ca_dir = tempfile::tempdir().unwrap();

    let (event_tx, _event_rx) = mpsc::channel(64);
    let config = ProxyConfig {
        addr,
        mode: ProxyMode::Forward,
        event_tx,
        ca_dir: ca_dir.path().to_path_buf(),
        upstream_tls: UpstreamTlsConfig::Default,
        intercept: None,
        body_capture_limit: None,
        #[cfg(feature = "scripting")]
        script_path: None,
        replay_rx: None,
    };

    let proxy = Proxy::new(config);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let handle = tokio::spawn(async move {
        proxy
            .start_with_handler(PassThroughHandler, async {
                shutdown_rx.await.ok();
            })
            .await
    });

    wait_for_tcp(addr).await.unwrap();

    let _ = shutdown_tx.send(());
    assert!(handle.await.unwrap().is_ok());
}

#[tokio::test]
async fn test_start_with_handler_forwards_http_through_custom_handler() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (upstream_addr, upstream_shutdown) = start_upstream_server().await;
    let (proxy_addr, shutdown_tx, handle) = start_proxy_with_handler(PassThroughHandler).await;

    let raw_response = send_raw_request(
        proxy_addr,
        format!(
            "GET http://{upstream_addr}/forward HTTP/1.1\r\n\
             Host: {upstream_addr}\r\n\
             Connection: close\r\n\
             \r\n"
        ),
    )
    .await;

    assert!(
        raw_response.starts_with("HTTP/1.1 200 OK"),
        "unexpected response:\n{raw_response}"
    );
    assert_response_header(&raw_response, "x-upstream-path-query", "/forward");
    assert!(raw_response.ends_with("forward response"));

    let _ = shutdown_tx.send(());
    let _ = upstream_shutdown.send(());
    assert!(handle.await.unwrap().is_ok());
}

#[tokio::test]
async fn test_start_with_handler_short_circuits_blocked_host() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (upstream_addr, upstream_shutdown) = start_upstream_server().await;
    let (proxy_addr, shutdown_tx, handle) = start_proxy_with_handler(BlockHostHandler {
        blocked_host: upstream_addr.to_string(),
    })
    .await;

    let raw_response = send_raw_request(
        proxy_addr,
        format!(
            "GET http://{upstream_addr}/blocked HTTP/1.1\r\n\
             Host: {upstream_addr}\r\n\
             Connection: close\r\n\
             \r\n"
        ),
    )
    .await;

    assert!(
        raw_response.starts_with("HTTP/1.1 403 Forbidden"),
        "unexpected response:\n{raw_response}"
    );
    assert!(raw_response.ends_with("blocked by custom handler"));

    let _ = shutdown_tx.send(());
    let _ = upstream_shutdown.send(());
    assert!(handle.await.unwrap().is_ok());
}

#[tokio::test]
async fn test_start_with_handler_request_mutation_reaches_upstream() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (upstream_addr, upstream_shutdown) = start_upstream_server().await;
    let (proxy_addr, shutdown_tx, handle) = start_proxy_with_handler(AddHeaderHandler {
        header_name: "x-injected",
        header_value: "custom-handler-test",
    })
    .await;

    let raw_response = send_raw_request(
        proxy_addr,
        format!(
            "GET http://{upstream_addr}/mutated HTTP/1.1\r\n\
             Host: {upstream_addr}\r\n\
             Connection: close\r\n\
             \r\n"
        ),
    )
    .await;

    assert!(
        raw_response.starts_with("HTTP/1.1 200 OK"),
        "unexpected response:\n{raw_response}"
    );
    assert_response_header(&raw_response, "x-upstream-injected", "custom-handler-test");
    assert!(raw_response.ends_with("forward response"));

    let _ = shutdown_tx.send(());
    let _ = upstream_shutdown.send(());
    assert!(handle.await.unwrap().is_ok());
}

#[tokio::test]
async fn test_start_with_handler_rejects_reverse_mode() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let addr = reserve_loopback_addr().await;
    let ca_dir = tempfile::tempdir().unwrap();
    let (event_tx, _event_rx) = mpsc::channel(64);
    let config = ProxyConfig {
        addr,
        mode: ProxyMode::Reverse {
            target: "http://127.0.0.1:1".parse().unwrap(),
        },
        event_tx,
        ca_dir: ca_dir.path().to_path_buf(),
        upstream_tls: UpstreamTlsConfig::Default,
        intercept: None,
        body_capture_limit: None,
        #[cfg(feature = "scripting")]
        script_path: None,
        replay_rx: None,
    };

    let proxy = Proxy::new(config);
    let result = proxy.start_with_handler(PassThroughHandler, async {}).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_start_with_handler_rejects_route_rules() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let addr = reserve_loopback_addr().await;
    let ca_dir = tempfile::tempdir().unwrap();
    let (event_tx, _event_rx) = mpsc::channel(64);
    let config = ProxyConfig {
        addr,
        mode: ProxyMode::Forward,
        event_tx,
        ca_dir: ca_dir.path().to_path_buf(),
        upstream_tls: UpstreamTlsConfig::Default,
        intercept: None,
        body_capture_limit: None,
        #[cfg(feature = "scripting")]
        script_path: None,
        replay_rx: None,
    };

    let rules = std::sync::Arc::new(proxyapi::RouteRules::default());
    let proxy = Proxy::new(config).with_route_rules(rules);
    let result = proxy.start_with_handler(PassThroughHandler, async {}).await;
    assert!(result.is_err());
}

/// Forwards every request and response unchanged.
#[derive(Clone)]
struct PassThroughHandler;

#[async_trait::async_trait]
impl HttpHandler for PassThroughHandler {
    async fn handle_request(&mut self, _ctx: &HttpContext, req: ProxyRequest) -> RequestOrResponse {
        RequestOrResponse::Request(req)
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: ProxyResponse) -> ProxyResponse {
        res
    }
}

/// Returns 403 for a specific host, forwards everything else.
#[derive(Clone)]
struct BlockHostHandler {
    blocked_host: String,
}

#[async_trait::async_trait]
impl HttpHandler for BlockHostHandler {
    async fn handle_request(&mut self, _ctx: &HttpContext, req: ProxyRequest) -> RequestOrResponse {
        if req
            .head
            .uri
            .authority()
            .is_some_and(|a| a.as_str() == self.blocked_host)
        {
            return RequestOrResponse::Response(self.synthetic_protocol_response(
                http::StatusCode::FORBIDDEN,
                http::HeaderMap::new(),
                Bytes::from_static(b"blocked by custom handler"),
            ));
        }
        RequestOrResponse::Request(req)
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: ProxyResponse) -> ProxyResponse {
        res
    }
}

/// Injects a custom header on every request before forwarding.
#[derive(Clone)]
struct AddHeaderHandler {
    header_name: &'static str,
    header_value: &'static str,
}

#[async_trait::async_trait]
impl HttpHandler for AddHeaderHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        mut req: ProxyRequest,
    ) -> RequestOrResponse {
        req.head
            .headers
            .set(self.header_name, self.header_value.as_bytes())
            .expect("static header name is valid");
        RequestOrResponse::Request(req)
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: ProxyResponse) -> ProxyResponse {
        res
    }
}

async fn start_proxy_with_handler<H: HttpHandler>(
    handler: H,
) -> (
    SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), proxyapi::Error>>,
) {
    let proxy_addr = reserve_loopback_addr().await;
    let ca_dir = tempfile::tempdir().unwrap();
    let (event_tx, _event_rx) = mpsc::channel::<proxyapi::ProxyEvent>(100);
    let config = ProxyConfig {
        addr: proxy_addr,
        mode: ProxyMode::Forward,
        event_tx,
        ca_dir: ca_dir.path().to_path_buf(),
        upstream_tls: UpstreamTlsConfig::Default,
        intercept: None,
        body_capture_limit: None,
        #[cfg(feature = "scripting")]
        script_path: None,
        replay_rx: None,
    };

    let proxy = Proxy::new(config);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        proxy
            .start_with_handler(handler, async {
                shutdown_rx.await.ok();
            })
            .await
    });

    wait_for_tcp(proxy_addr).await.unwrap();

    (proxy_addr, shutdown_tx, handle)
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
    let path_query = req
        .uri()
        .path_and_query()
        .map(http::uri::PathAndQuery::as_str)
        .unwrap_or("/");
    let host = req
        .headers()
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let injected = req
        .headers()
        .get("x-injected")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    Ok(Response::builder()
        .status(http::StatusCode::OK)
        .header("x-upstream-path-query", path_query)
        .header("x-upstream-host", host)
        .header("x-upstream-injected", injected)
        .body(Full::new(Bytes::from_static(b"forward response")))
        .unwrap())
}

async fn reserve_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

async fn wait_for_tcp(addr: SocketAddr) -> Result<(), std::io::Error> {
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(10);
    loop {
        match TcpStream::connect(addr).await {
            Ok(_) => return Ok(()),
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

async fn send_raw_request(addr: SocketAddr, request: String) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    read_to_string_until_eof(&mut stream).await
}

async fn read_to_string_until_eof(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut bytes),
    )
    .await
    .unwrap()
    .unwrap();
    String::from_utf8(bytes).unwrap()
}

fn assert_response_header(response: &str, name: &str, value: &str) {
    let headers = response
        .split("\r\n\r\n")
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let needle = format!(
        "{}: {}",
        name.to_ascii_lowercase(),
        value.to_ascii_lowercase()
    );
    assert!(
        headers.contains(&needle),
        "missing response header `{needle}` in:\n{response}"
    );
}
