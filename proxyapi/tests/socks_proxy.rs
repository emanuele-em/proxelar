use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};

use proxyapi::{
    Proxy, ProxyConfig, ProxyEvent, ProxyMode, UpstreamHttpVersion, UpstreamTlsConfig,
    DEFAULT_BODY_CAPTURE_LIMIT,
};
use proxyapi_models::StreamDirection;
use rama::bytes::Bytes;
use rama::http::server::HttpServer;
use rama::http::{Body, Request, Response, StatusCode};
use rama::rt::Executor;
use rama::service::service_fn;
use rama::tcp::server::TcpListener as RamaTcpListener;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

#[tokio::test]
async fn socks_reports_connect_failure_before_success() {
    let unavailable = reserve_loopback_addr().await;
    let (proxy_addr, shutdown, proxy_task, _events, _ca_dir) = start_socks_proxy(None).await;
    let mut stream = socks_handshake(proxy_addr).await;

    let reply = socks_connect(&mut stream, unavailable).await;

    assert_ne!(
        reply, 0,
        "unreachable target must not receive a success reply"
    );
    let _ = shutdown.send(());
    assert!(proxy_task.await.unwrap().is_ok());
}

#[tokio::test]
async fn socks_http_inspection_reuses_eager_egress() {
    let (upstream_addr, upstream_shutdown) = start_http_server().await;
    let (proxy_addr, shutdown, proxy_task, mut events, _ca_dir) = start_socks_proxy(None).await;
    let mut stream = socks_handshake(proxy_addr).await;
    assert_eq!(socks_connect(&mut stream, upstream_addr).await, 0);

    stream
        .write_all(
            format!(
                "GET /through-socks HTTP/1.1\r\nHost: {upstream_addr}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.ends_with("inspected through socks"), "{response}");

    let event = tokio::time::timeout(std::time::Duration::from_secs(5), events.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(event, ProxyEvent::RequestComplete { .. }));

    let _ = shutdown.send(());
    let _ = upstream_shutdown.send(());
    assert!(proxy_task.await.unwrap().is_ok());
}

#[tokio::test]
async fn socks_raw_fallback_uses_configured_http_proxy() {
    let (target_addr, target_shutdown) = start_raw_echo_server().await;
    let (chain_addr, observed_target, chain_shutdown) = start_http_connect_proxy().await;
    let upstream_proxy = format!("http://{chain_addr}").parse().unwrap();
    let (proxy_addr, shutdown, proxy_task, mut events, _ca_dir) =
        start_socks_proxy(Some(upstream_proxy)).await;
    let mut stream = socks_handshake(proxy_addr).await;

    assert_eq!(
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            socks_connect(&mut stream, target_addr),
        )
        .await
        .expect("SOCKS CONNECT through upstream proxy timed out"),
        0
    );
    let payload = b"PING raw-through-chain";
    stream.write_all(payload).await.unwrap();
    let connected = tokio::time::timeout(std::time::Duration::from_secs(5), events.recv())
        .await
        .expect("raw tunnel did not emit a connection event")
        .unwrap();
    assert!(matches!(connected, ProxyEvent::TcpConnected { .. }));
    let mut forwarded = Vec::new();
    while forwarded.len() < payload.len() {
        let event = tokio::time::timeout(std::time::Duration::from_secs(5), events.recv())
            .await
            .expect("raw tunnel did not forward client bytes")
            .unwrap();
        if let ProxyEvent::TcpData { chunk, .. } = event {
            if chunk.direction == StreamDirection::ClientToServer {
                forwarded.extend_from_slice(&chunk.payload);
            }
        }
    }
    assert_eq!(forwarded, payload);
    let mut echoed = vec![0; payload.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_exact(&mut echoed),
    )
    .await
    .expect("raw echo through upstream proxy timed out")
    .unwrap();

    assert_eq!(echoed, payload);
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(5), observed_target)
            .await
            .expect("upstream proxy did not observe CONNECT")
            .unwrap(),
        target_addr.to_string()
    );

    let _ = shutdown.send(());
    let _ = chain_shutdown.send(());
    let _ = target_shutdown.send(());
    assert!(proxy_task.await.unwrap().is_ok());
}

async fn start_socks_proxy(
    upstream_proxy: Option<proxyapi::UpstreamProxyConfig>,
) -> (
    SocketAddr,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), proxyapi::Error>>,
    mpsc::Receiver<ProxyEvent>,
    tempfile::TempDir,
) {
    let addr = reserve_loopback_addr().await;
    let ca_dir = tempfile::tempdir().unwrap();
    let (event_tx, event_rx) = mpsc::channel(100);
    let config = ProxyConfig {
        addr,
        mode: ProxyMode::Socks5,
        event_tx,
        ca_dir: ca_dir.path().to_path_buf(),
        upstream_tls: UpstreamTlsConfig::Default,
        upstream_http_version: UpstreamHttpVersion::default(),
        intercept: None,
        body_capture_limit: DEFAULT_BODY_CAPTURE_LIMIT,
        #[cfg(feature = "scripting")]
        script_path: None,
        replay_rx: None,
    };
    let proxy = match upstream_proxy {
        Some(upstream) => Proxy::new(config).with_upstream_proxy(upstream),
        None => Proxy::new(config),
    };
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        proxy
            .start(async {
                shutdown_rx.await.ok();
            })
            .await
    });
    wait_for_tcp(addr).await;
    (addr, shutdown_tx, task, event_rx, ca_dir)
}

async fn socks_handshake(proxy_addr: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0; 2];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 0]);
    stream
}

async fn socks_connect(stream: &mut TcpStream, target: SocketAddr) -> u8 {
    let SocketAddr::V4(target) = target else {
        panic!("test helper only supports IPv4")
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();

    let mut header = [0; 4];
    stream.read_exact(&mut header).await.unwrap();
    let address_len = match header[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut len = [0];
            stream.read_exact(&mut len).await.unwrap();
            usize::from(len[0])
        }
        atyp => panic!("unexpected SOCKS address type {atyp}"),
    };
    let mut address_and_port = vec![0; address_len + 2];
    stream.read_exact(&mut address_and_port).await.unwrap();
    header[1]
}

async fn start_http_server() -> (SocketAddr, oneshot::Sender<()>) {
    let exec = Executor::default();
    let listener = RamaTcpListener::bind_address("127.0.0.1:0", exec.clone())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let service = HttpServer::auto(exec).service(service_fn(|request: Request| async move {
        assert_eq!(request.uri().path_or_root(), "/through-socks");
        Ok::<_, Infallible>(
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(Bytes::from_static(b"inspected through socks")))
                .unwrap(),
        )
    }));
    tokio::spawn(async move {
        tokio::select! {
            () = listener.serve(service) => {}
            _ = shutdown_rx => {}
        }
    });
    (addr, shutdown_tx)
}

async fn start_raw_echo_server() -> (SocketAddr, oneshot::Sender<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    tokio::spawn(async move {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted.unwrap();
                let (mut reader, mut writer) = tokio::io::split(stream);
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            }
            _ = &mut shutdown_rx => {}
        }
    });
    (addr, shutdown_tx)
}

async fn start_http_connect_proxy() -> (SocketAddr, oneshot::Receiver<String>, oneshot::Sender<()>)
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (target_tx, target_rx) = oneshot::channel();
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    tokio::spawn(async move {
        tokio::select! {
            accepted = listener.accept() => {
                let (mut ingress, _) = accepted.unwrap();
                let request = read_http_head(&mut ingress).await;
                let target = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap()
                    .to_owned();
                let mut egress = TcpStream::connect(&target).await.unwrap();
                ingress
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .unwrap();
                let _ = target_tx.send(target);
                let _ = tokio::io::copy_bidirectional(&mut ingress, &mut egress).await;
            }
            _ = &mut shutdown_rx => {}
        }
    });
    (addr, target_rx, shutdown_tx)
}

async fn read_http_head(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).await.unwrap();
        bytes.push(byte[0]);
    }
    String::from_utf8(bytes).unwrap()
}

async fn reserve_loopback_addr() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

async fn wait_for_tcp(addr: SocketAddr) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match TcpStream::connect(addr).await {
            Ok(_) => return,
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
            Err(error) => panic!("proxy did not start: {error}"),
        }
    }
}
