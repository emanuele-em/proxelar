use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use proxyapi::{Proxy, ProxyConfig, ProxyEvent, ProxyMode, DEFAULT_BODY_CAPTURE_LIMIT};
use proxyapi_models::ProxiedRequest;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

const EVENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[tokio::test]
async fn test_forward_proxy_starts_and_shuts_down() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let addr = reserve_loopback_addr().await;
    let ca_dir = tempfile::tempdir().unwrap();

    let (event_tx, _event_rx) = mpsc::channel::<ProxyEvent>(100);
    let config = ProxyConfig {
        addr,
        mode: ProxyMode::Forward,
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

    wait_for_tcp(addr).await.unwrap();

    let _ = shutdown_tx.send(());

    let result = handle.await.unwrap();
    assert!(result.is_ok());
}

#[tokio::test]
async fn forward_proxy_forwards_absolute_http_and_emits_request_complete() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (upstream_addr, upstream_shutdown) = start_upstream_server().await;
    let (proxy_addr, shutdown_tx, handle, mut event_rx, _ca_dir) = start_forward_proxy().await;

    let raw_response = send_raw_request(
        proxy_addr,
        format!(
            "GET http://{upstream_addr}/absolute?via=proxy HTTP/1.1\r\n\
             Host: wrong-host.example\r\n\
             x-client-test: absolute-roundtrip\r\n\
             Connection: close\r\n\
             \r\n"
        ),
    )
    .await;

    assert!(
        raw_response.starts_with("HTTP/1.1 200 OK"),
        "unexpected response:\n{raw_response}"
    );
    assert_response_header(
        &raw_response,
        "x-upstream-path-query",
        "/absolute?via=proxy",
    );
    assert_response_header(&raw_response, "x-upstream-host", &upstream_addr.to_string());
    assert!(raw_response.ends_with("forward response"));

    match recv_request_complete(&mut event_rx).await {
        ProxyEvent::RequestComplete {
            request, response, ..
        } => {
            assert_eq!(request.method(), http::Method::GET);
            assert_eq!(request.uri().scheme_str(), Some("http"));
            assert_eq!(
                request.uri().authority().unwrap().as_str(),
                upstream_addr.to_string()
            );
            assert_eq!(request.uri().path(), "/absolute");
            assert_eq!(request.uri().query(), Some("via=proxy"));
            assert_eq!(request.headers()["x-client-test"], "absolute-roundtrip");
            assert_eq!(response.status(), http::StatusCode::OK);
            assert_eq!(response.body().as_ref(), b"forward response");
        }
        other => panic!("expected RequestComplete event, got {other:?}"),
    }

    let _ = shutdown_tx.send(());
    let _ = upstream_shutdown.send(());
    assert!(handle.await.unwrap().is_ok());
}

#[tokio::test]
async fn forward_proxy_connect_plain_http_reconstructs_uri_and_emits_request_complete() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (upstream_addr, upstream_shutdown) = start_upstream_server().await;
    let (proxy_addr, shutdown_tx, handle, mut event_rx, _ca_dir) = start_forward_proxy().await;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream
        .write_all(
            format!(
                "CONNECT {upstream_addr} HTTP/1.1\r\n\
                 Host: {upstream_addr}\r\n\
                 \r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let connect_response = read_headers(&mut stream).await;
    assert!(connect_response.starts_with("HTTP/1.1 200 OK"));

    stream
        .write_all(
            format!(
                "GET /tunneled?via=connect HTTP/1.1\r\n\
                 Host: {upstream_addr}\r\n\
                 x-client-test: connect-roundtrip\r\n\
                 Connection: close\r\n\
                 \r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let raw_response = read_to_string_until_eof(&mut stream).await;
    assert!(
        raw_response.starts_with("HTTP/1.1 200 OK"),
        "unexpected tunneled response:\n{raw_response}"
    );
    assert_response_header(
        &raw_response,
        "x-upstream-path-query",
        "/tunneled?via=connect",
    );
    assert_response_header(&raw_response, "x-upstream-host", &upstream_addr.to_string());
    assert!(raw_response.ends_with("forward response"));

    match recv_request_complete(&mut event_rx).await {
        ProxyEvent::RequestComplete {
            request, response, ..
        } => {
            assert_eq!(request.method(), http::Method::GET);
            assert_eq!(request.uri().scheme_str(), Some("http"));
            assert_eq!(
                request.uri().authority().unwrap().as_str(),
                upstream_addr.to_string()
            );
            assert_eq!(request.uri().path(), "/tunneled");
            assert_eq!(request.uri().query(), Some("via=connect"));
            assert_eq!(request.headers()["x-client-test"], "connect-roundtrip");
            assert_eq!(response.status(), http::StatusCode::OK);
            assert_eq!(response.body().as_ref(), b"forward response");
        }
        other => panic!("expected RequestComplete event, got {other:?}"),
    }

    let _ = shutdown_tx.send(());
    let _ = upstream_shutdown.send(());
    assert!(handle.await.unwrap().is_ok());
}

#[tokio::test]
async fn forward_proxy_serves_certificate_page_for_direct_and_proxelar_requests() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (proxy_addr, shutdown_tx, handle, _event_rx, _ca_dir) = start_forward_proxy().await;

    let direct = send_raw_request(
        proxy_addr,
        format!(
            "GET / HTTP/1.1\r\n\
             Host: {proxy_addr}\r\n\
             Connection: close\r\n\
             \r\n"
        ),
    )
    .await;
    assert!(direct.starts_with("HTTP/1.1 200 OK"));
    assert_response_header(&direct, "content-type", "text/html; charset=utf-8");
    assert!(direct.contains("Certificate Installation"));

    let proxelar = send_raw_request(
        proxy_addr,
        "GET http://proxel.ar/ HTTP/1.1\r\n\
         Host: proxel.ar\r\n\
         Connection: close\r\n\
         \r\n"
            .to_owned(),
    )
    .await;
    assert!(proxelar.starts_with("HTTP/1.1 200 OK"));
    assert!(proxelar.contains(&format!("http://{proxy_addr}/cert/pem")));

    let _ = shutdown_tx.send(());
    assert!(handle.await.unwrap().is_ok());
}

#[tokio::test]
async fn forward_proxy_returns_502_when_upstream_connection_fails() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let unused_upstream = reserve_loopback_addr().await;
    let (proxy_addr, shutdown_tx, handle, mut event_rx, _ca_dir) = start_forward_proxy().await;

    let raw_response = send_raw_request(
        proxy_addr,
        format!(
            "GET http://{unused_upstream}/missing HTTP/1.1\r\n\
             Host: {unused_upstream}\r\n\
             Connection: close\r\n\
             \r\n"
        ),
    )
    .await;

    assert!(raw_response.starts_with("HTTP/1.1 502 Bad Gateway"));
    assert!(raw_response.ends_with("Bad Gateway"));
    assert!(event_rx.try_recv().is_err());

    let _ = shutdown_tx.send(());
    assert!(handle.await.unwrap().is_ok());
}

#[tokio::test]
async fn forward_proxy_connect_plain_http_requires_host_header() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (proxy_addr, shutdown_tx, handle, _event_rx, _ca_dir) = start_forward_proxy().await;
    let unused_upstream = reserve_loopback_addr().await;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream
        .write_all(
            format!(
                "CONNECT {unused_upstream} HTTP/1.1\r\n\
                 Host: {unused_upstream}\r\n\
                 \r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let connect_response = read_headers(&mut stream).await;
    assert!(connect_response.starts_with("HTTP/1.1 200 OK"));

    stream
        .write_all(
            b"GET /no-host HTTP/1.1\r\n\
              Connection: close\r\n\
              \r\n",
        )
        .await
        .unwrap();

    let raw_response = read_to_string_until_eof(&mut stream).await;
    assert!(raw_response.starts_with("HTTP/1.1 400 Bad Request"));
    assert!(raw_response.ends_with("Bad Request: missing Host header"));

    let _ = shutdown_tx.send(());
    assert!(handle.await.unwrap().is_ok());
}

#[tokio::test]
async fn forward_proxy_connect_unknown_protocol_tunnels_raw_bytes() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (echo_addr, echo_shutdown) = start_raw_echo_server().await;
    let (proxy_addr, shutdown_tx, handle, _event_rx, _ca_dir) = start_forward_proxy().await;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream
        .write_all(
            format!(
                "CONNECT {echo_addr} HTTP/1.1\r\n\
                 Host: {echo_addr}\r\n\
                 \r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let connect_response = read_headers(&mut stream).await;
    assert!(connect_response.starts_with("HTTP/1.1 200 OK"));

    stream.write_all(b"PING").await.unwrap();
    let mut pong = [0; 4];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_exact(&mut pong),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&pong, b"PONG");

    let _ = shutdown_tx.send(());
    let _ = echo_shutdown.send(());
    assert!(handle.await.unwrap().is_ok());
}

#[tokio::test]
async fn forward_proxy_connect_plain_http_serves_cert_page_inside_tunnel() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let unused_upstream = reserve_loopback_addr().await;
    let (proxy_addr, shutdown_tx, handle, _event_rx, _ca_dir) = start_forward_proxy().await;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    write_connect(&mut stream, unused_upstream).await;
    assert!(read_headers(&mut stream)
        .await
        .starts_with("HTTP/1.1 200 OK"));

    stream
        .write_all(
            b"GET / HTTP/1.1\r\n\
              Host: proxel.ar\r\n\
              Connection: close\r\n\
              \r\n",
        )
        .await
        .unwrap();

    let raw_response = read_to_string_until_eof(&mut stream).await;
    assert!(raw_response.starts_with("HTTP/1.1 200 OK"));
    assert!(raw_response.contains("Certificate Installation"));
    assert!(raw_response.contains(&format!("http://{proxy_addr}/cert/pem")));

    let _ = shutdown_tx.send(());
    assert!(handle.await.unwrap().is_ok());
}

#[tokio::test]
async fn forward_proxy_connect_plain_http_returns_502_when_upstream_fails() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let unused_upstream = reserve_loopback_addr().await;
    let (proxy_addr, shutdown_tx, handle, _event_rx, _ca_dir) = start_forward_proxy().await;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    write_connect(&mut stream, unused_upstream).await;
    assert!(read_headers(&mut stream)
        .await
        .starts_with("HTTP/1.1 200 OK"));

    stream
        .write_all(
            format!(
                "GET /fail HTTP/1.1\r\n\
                 Host: {unused_upstream}\r\n\
                 Connection: close\r\n\
                 \r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let raw_response = read_to_string_until_eof(&mut stream).await;
    assert!(raw_response.starts_with("HTTP/1.1 502 Bad Gateway"));
    assert!(raw_response.ends_with("Bad Gateway"));

    let _ = shutdown_tx.send(());
    assert!(handle.await.unwrap().is_ok());
}

#[tokio::test]
async fn forward_proxy_replays_captured_request_through_proxy_loop() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (upstream_addr, upstream_shutdown) = start_upstream_server().await;
    let (_proxy_addr, shutdown_tx, handle, mut event_rx, replay_tx, _ca_dir) =
        start_forward_proxy_with_replay().await;

    let mut headers = http::HeaderMap::new();
    headers.insert("x-replay", "yes".parse().unwrap());
    let req = ProxiedRequest::new(
        http::Method::GET,
        format!("http://{upstream_addr}/replayed?from=ui")
            .parse()
            .unwrap(),
        http::Version::HTTP_11,
        headers,
        Bytes::new(),
        10,
    );
    replay_tx.send(req).await.unwrap();

    match recv_request_complete(&mut event_rx).await {
        ProxyEvent::RequestComplete {
            request, response, ..
        } => {
            assert_eq!(request.uri().path(), "/replayed");
            assert_eq!(request.uri().query(), Some("from=ui"));
            assert_eq!(request.headers()["x-replay"], "yes");
            assert_eq!(response.status(), http::StatusCode::OK);
            assert_eq!(response.body().as_ref(), b"forward response");
        }
        other => panic!("expected RequestComplete event, got {other:?}"),
    }

    let _ = shutdown_tx.send(());
    let _ = upstream_shutdown.send(());
    assert!(handle.await.unwrap().is_ok());
}

#[tokio::test]
async fn forward_proxy_websocket_upgrade_emits_connection_frames_and_close() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (upstream_addr, upstream_shutdown) = start_websocket_upstream_server().await;
    let (proxy_addr, shutdown_tx, handle, mut event_rx, _ca_dir) = start_forward_proxy().await;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream
        .write_all(
            format!(
                "GET http://{upstream_addr}/ws HTTP/1.1\r\n\
                 Host: {upstream_addr}\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Version: 13\r\n\
                 Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                 \r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let handshake = read_headers(&mut stream).await;
    assert!(handshake.starts_with("HTTP/1.1 101 Switching Protocols"));

    let mut ws = WebSocketStream::from_raw_socket(stream, Role::Client, None).await;
    ws.send(Message::Text("hello".into())).await.unwrap();
    let reply = ws.next().await.unwrap().unwrap();
    assert_eq!(reply, Message::Text("echo:hello".into()));
    ws.close(None).await.unwrap();

    let mut saw_connected = false;
    let mut saw_client_frame = false;
    let mut saw_server_frame = false;
    let mut saw_closed = false;

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !(saw_connected && saw_client_frame && saw_server_frame && saw_closed) {
            match event_rx.recv().await.unwrap() {
                ProxyEvent::WebSocketConnected {
                    request, response, ..
                } => {
                    saw_connected = true;
                    assert_eq!(request.uri().path(), "/ws");
                    assert_eq!(response.status(), http::StatusCode::SWITCHING_PROTOCOLS);
                }
                ProxyEvent::WebSocketFrame { frame, .. } => match frame.direction {
                    proxyapi_models::WsDirection::ClientToServer => {
                        if frame.payload.as_ref() == b"hello" {
                            saw_client_frame = true;
                        }
                    }
                    proxyapi_models::WsDirection::ServerToClient => {
                        if frame.payload.as_ref() == b"echo:hello" {
                            saw_server_frame = true;
                        }
                    }
                },
                ProxyEvent::WebSocketClosed { .. } => saw_closed = true,
                _ => {}
            }
        }
    })
    .await
    .unwrap();

    let _ = shutdown_tx.send(());
    let _ = upstream_shutdown.send(());
    assert!(handle.await.unwrap().is_ok());
}

async fn start_forward_proxy() -> (
    SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), proxyapi::Error>>,
    mpsc::Receiver<ProxyEvent>,
    tempfile::TempDir,
) {
    let proxy_addr = reserve_loopback_addr().await;
    let ca_dir = tempfile::tempdir().unwrap();
    let (event_tx, event_rx) = mpsc::channel::<ProxyEvent>(100);
    let config = ProxyConfig {
        addr: proxy_addr,
        mode: ProxyMode::Forward,
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

    wait_for_tcp(proxy_addr).await.unwrap();

    (proxy_addr, shutdown_tx, handle, event_rx, ca_dir)
}

async fn start_forward_proxy_with_replay() -> (
    SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), proxyapi::Error>>,
    mpsc::Receiver<ProxyEvent>,
    mpsc::Sender<ProxiedRequest>,
    tempfile::TempDir,
) {
    let proxy_addr = reserve_loopback_addr().await;
    let ca_dir = tempfile::tempdir().unwrap();
    let (event_tx, event_rx) = mpsc::channel::<ProxyEvent>(100);
    let (replay_tx, replay_rx) = mpsc::channel::<ProxiedRequest>(4);
    let config = ProxyConfig {
        addr: proxy_addr,
        mode: ProxyMode::Forward,
        event_tx,
        ca_dir: ca_dir.path().to_path_buf(),
        intercept: None,
        body_capture_limit: DEFAULT_BODY_CAPTURE_LIMIT,
        #[cfg(feature = "scripting")]
        script_path: None,
        replay_rx: Some(replay_rx),
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

    wait_for_tcp(proxy_addr).await.unwrap();

    (proxy_addr, shutdown_tx, handle, event_rx, replay_tx, ca_dir)
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

async fn write_connect(stream: &mut TcpStream, authority: SocketAddr) {
    stream
        .write_all(
            format!(
                "CONNECT {authority} HTTP/1.1\r\n\
                 Host: {authority}\r\n\
                 \r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
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

async fn start_raw_echo_server() -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        tokio::select! {
            result = listener.accept() => {
                let Ok((mut stream, _)) = result else {
                    return;
                };
                let mut ping = [0; 4];
                if stream.read_exact(&mut ping).await.is_ok() && &ping == b"PING" {
                    let _ = stream.write_all(b"PONG").await;
                }
            }
            _ = &mut shutdown_rx => {}
        }
    });

    (addr, shutdown_tx)
}

async fn start_websocket_upstream_server() -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
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
                        let service = service_fn(websocket_upstream_response);
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, service)
                            .with_upgrades()
                            .await;
                    });
                }
                _ = &mut shutdown_rx => break,
            }
        }
    });

    (addr, shutdown_tx)
}

async fn websocket_upstream_response(
    mut req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    tokio::spawn(async move {
        let Ok(upgraded) = hyper::upgrade::on(&mut req).await else {
            return;
        };
        let mut ws =
            WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, None).await;
        if let Some(Ok(Message::Text(text))) = ws.next().await {
            let _ = ws.send(Message::Text(format!("echo:{text}").into())).await;
        }
        let _ = ws.close(None).await;
    });

    Ok(Response::builder()
        .status(http::StatusCode::SWITCHING_PROTOCOLS)
        .header(hyper::header::CONNECTION, "Upgrade")
        .header(hyper::header::UPGRADE, "websocket")
        .header("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
        .body(Full::new(Bytes::new()))
        .unwrap())
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

    Ok(Response::builder()
        .status(http::StatusCode::OK)
        .header("x-upstream-path-query", path_query)
        .header("x-upstream-host", host)
        .body(Full::new(Bytes::from_static(b"forward response")))
        .unwrap())
}

async fn send_raw_request(addr: SocketAddr, request: String) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    read_to_string_until_eof(&mut stream).await
}

async fn read_headers(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut buf = [0; 1];

    loop {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_exact(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        bytes.push(buf[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    String::from_utf8(bytes).unwrap()
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

async fn recv_request_complete(event_rx: &mut mpsc::Receiver<ProxyEvent>) -> ProxyEvent {
    tokio::time::timeout(EVENT_TIMEOUT, async {
        loop {
            let event = event_rx.recv().await.unwrap();
            if matches!(event, ProxyEvent::RequestComplete { .. }) {
                return event;
            }
        }
    })
    .await
    .unwrap()
}
