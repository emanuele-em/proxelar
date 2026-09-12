use proxyapi::{DnsConfig, Proxy, ProxyConfig, ProxyMode, UpstreamTlsConfig};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

#[tokio::test]
async fn datagram_modes_report_bind_conflicts_and_release_ports_on_shutdown() {
    let directory = tempfile::tempdir().unwrap();
    let reserved = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = reserved.local_addr().unwrap();
    for mode in [
        ProxyMode::Udp {
            target: "127.0.0.1:53".parse().unwrap(),
        },
        ProxyMode::Dns {
            config: DnsConfig::new("127.0.0.1:53".parse().unwrap()),
        },
    ] {
        let (event_tx, _) = mpsc::channel(10);
        let proxy = Proxy::new(ProxyConfig {
            addr,
            mode: mode.clone(),
            event_tx,
            ca_dir: directory.path().to_path_buf(),
            upstream_tls: UpstreamTlsConfig::Default,
            intercept: None,
            body_capture_limit: None,
            #[cfg(feature = "scripting")]
            script_path: None,
            replay_rx: None,
        });
        assert!(proxy.start(std::future::ready(())).await.is_err());
    }
    drop(reserved);
    for mode in [
        ProxyMode::Udp {
            target: "127.0.0.1:53".parse().unwrap(),
        },
        ProxyMode::Dns {
            config: DnsConfig::new("127.0.0.1:53".parse().unwrap()),
        },
    ] {
        let (event_tx, _) = mpsc::channel(10);
        let proxy = Proxy::new(ProxyConfig {
            addr,
            mode,
            event_tx,
            ca_dir: directory.path().to_path_buf(),
            upstream_tls: UpstreamTlsConfig::Default,
            intercept: None,
            body_capture_limit: None,
            #[cfg(feature = "scripting")]
            script_path: None,
            replay_rx: None,
        });
        proxy.start(std::future::ready(())).await.unwrap();
        let rebound = UdpSocket::bind(addr).await.unwrap();
        drop(rebound);
    }
    // DNS and raw UDP startup should not generate an unused TLS CA.
    assert!(!directory.path().join("proxelar-ca.pem").exists());
}
