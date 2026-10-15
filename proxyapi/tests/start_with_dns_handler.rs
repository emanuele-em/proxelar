//! Integration tests for [`Proxy::start_with_dns_handler`].
//!
//! These tests start a real DNS proxy with a custom [`DnsHandler`] and
//! assert behavior through a local upstream resolver and a UDP client.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use proxyapi::{
    DnsConfig, DnsDecision, DnsHandler, DnsName, Proxy, ProxyConfig, ProxyEvent, ProxyMode,
    UpstreamTlsConfig,
};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_start_with_dns_handler_filters_queries() {
    let upstream = start_upstream_resolver().await;
    let addr = reserve_loopback_addr().await;
    let (event_tx, mut event_rx) = mpsc::channel(64);
    let proxy = Proxy::new(dns_config(addr, upstream, event_tx));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        proxy
            .start_with_dns_handler(
                AllowNameHandler("allowed.example.test".parse().unwrap()),
                async {
                    shutdown_rx.await.ok();
                },
            )
            .await
    });

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(addr).await.unwrap();

    let response = exchange(&client, &query(1, "Allowed.Example.Test")).await;
    assert_eq!(response[3] & 0x0f, 0, "allowed query should be NOERROR");
    assert_eq!(&response[6..8], &[0, 1], "upstream answer expected");

    let response = exchange(&client, &query(2, "blocked.example.test")).await;
    assert_eq!(response[3] & 0x0f, 3, "blocked query should be NXDOMAIN");
    assert_eq!(&response[6..8], &[0, 0], "no answer expected");

    // Literal dots inside a label must not create an allowlisted suffix.
    for (id, labels) in [
        (3, vec![b"evil.allowed".as_slice(), b"example", b"test"]),
        (4, vec![b"allowed.example.test".as_slice()]),
    ] {
        let response = exchange(&client, &query_labels(id, &labels)).await;
        assert_eq!(
            response[3] & 0x0f,
            3,
            "label-boundary bypass must be blocked"
        );
    }
    // Arbitrary bytes in a subdomain are preserved, not rejected as invalid UTF-8.
    let binary_labels = [b"\xff.\\".as_slice(), b"Allowed", b"Example", b"Test"];
    let binary_packet = query_labels(5, &binary_labels);
    let response = exchange(&client, &binary_packet).await;
    assert_eq!(response[3] & 0x0f, 0);
    assert_eq!(&response[12..binary_packet.len()], &binary_packet[12..]);

    let _ = shutdown_tx.send(());
    assert!(handle.await.unwrap().is_ok());

    let mut names = HashMap::new();
    let mut responses = Vec::new();
    while let Ok(event) = event_rx.try_recv() {
        match event {
            ProxyEvent::DnsQuery { id, name, .. } => {
                names.insert(id, name);
            }
            ProxyEvent::DnsResponse {
                id,
                answers,
                overridden,
            } => responses.push((names[&id].clone(), answers, overridden)),
            _ => {}
        }
    }
    assert!(responses.contains(&(
        "Allowed.Example.Test".parse().unwrap(),
        vec!["127.0.0.1".to_owned()],
        false
    )));
    assert!(responses.contains(&("blocked.example.test".parse().unwrap(), vec![], true)));
    let binary_name = DnsName::from_labels(binary_labels).unwrap();
    assert!(responses.contains(&(binary_name.clone(), vec!["127.0.0.1".to_owned()], false)));
    assert!(names
        .values()
        .any(|name| name.labels() == binary_name.labels()));
}

#[tokio::test]
async fn test_start_with_dns_handler_rejects_non_dns_mode() {
    let (event_tx, _event_rx) = mpsc::channel(1);
    let mut config = dns_config(
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:9".parse().unwrap(),
        event_tx,
    );
    config.mode = ProxyMode::Forward;

    let error = Proxy::new(config)
        .start_with_dns_handler(AllowNameHandler(".".parse().unwrap()), async {})
        .await
        .expect_err("non-DNS mode should fail before startup");
    assert!(
        error.to_string().contains("DNS mode"),
        "unexpected error: {error}"
    );
}

/// Allows a domain and its subdomains, case-insensitively.
#[derive(Clone)]
struct AllowNameHandler(DnsName);

#[async_trait::async_trait]
impl DnsHandler for AllowNameHandler {
    async fn handle_query(&self, name: &DnsName, _query_type: u16) -> DnsDecision {
        if name.is_subdomain_of(&self.0) {
            DnsDecision::Forward
        } else {
            DnsDecision::NxDomain
        }
    }
}

fn dns_config(
    addr: SocketAddr,
    upstream: SocketAddr,
    event_tx: mpsc::Sender<ProxyEvent>,
) -> ProxyConfig {
    ProxyConfig {
        addr,
        mode: ProxyMode::Dns {
            config: DnsConfig::new(upstream),
        },
        event_tx,
        // DNS mode does not load a CA.
        ca_dir: std::env::temp_dir(),
        upstream_tls: UpstreamTlsConfig::Default,
        intercept: None,
        body_capture_limit: None,
        #[cfg(feature = "scripting")]
        script_path: None,
        replay_rx: None,
    }
}

/// Build an A query with the given transaction ID.
fn query(id: u16, name: &str) -> Vec<u8> {
    query_labels(id, &name.split('.').map(str::as_bytes).collect::<Vec<_>>())
}

fn query_labels(id: u16, labels: &[&[u8]]) -> Vec<u8> {
    let mut packet = id.to_be_bytes().to_vec();
    packet.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in labels {
        packet.push(u8::try_from(label.len()).unwrap());
        packet.extend_from_slice(label);
    }
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    packet
}

/// Answer every query with a single `A 127.0.0.1` record.
async fn start_upstream_resolver() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        while let Ok((length, client)) = socket.recv_from(&mut buffer).await {
            let mut response = buffer[..length].to_vec();
            response[2] |= 0x80; // QR
            response[3] |= 0x80; // RA
            response[7] = 1; // ANCOUNT
            response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1]);
            let _ = socket.send_to(&response, client).await;
        }
    });
    addr
}

async fn reserve_loopback_addr() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.local_addr().unwrap()
}

/// Send `packet` until a response with the same transaction ID arrives.
/// Early sends can race the proxy binding its socket.
async fn exchange(client: &UdpSocket, packet: &[u8]) -> Vec<u8> {
    let mut buffer = [0_u8; 512];
    for _ in 0..50 {
        client.send(packet).await.unwrap();
        let received = tokio::time::timeout(Duration::from_millis(100), client.recv(&mut buffer));
        if let Ok(Ok(length)) = received.await {
            if buffer[..2] == packet[..2] {
                return buffer[..length].to_vec();
            }
        }
    }
    panic!("no DNS response from proxy");
}
