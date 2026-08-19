//! Privilege-free WireGuard capture backed by a userspace TCP/IP stack.

use rama::telemetry::tracing;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use netstack_smoltcp::{StackBuilder, TcpListener, UdpSocket as VirtualUdpSocket};
use proxyapi_models::ProxiedRequest;
use rama::futures::{SinkExt, StreamExt};
use rama::net::address::HostWithPort;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::ca::Ssl;
use crate::event::ProxyEvent;
use crate::handler::CapturingHandler;

use super::{dns, forward, udp, DnsConfig, PeekTimeoutPolicy, UpstreamClient};

const MAX_PACKET_SIZE: usize = 65_535;
const WIREGUARD_OVERHEAD: usize = 80;
const CLIENT_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const SERVER_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const SERVER_KEY_FILE: &str = "wireguard-server.key";
const CLIENT_KEY_FILE: &str = "wireguard-client.key";
// Android derives the tunnel/interface name from this stem and enforces the
// WireGuard 15-character interface-name limit.
const CLIENT_CONFIG_FILE: &str = "proxelar-wg.conf";

/// Key material and DNS policy for a single-peer WireGuard capture endpoint.
///
/// Proxelar deliberately starts with one generated client identity. A single
/// peer keeps address ownership unambiguous and makes deleting the generated
/// key files an effective credential rotation operation.
#[derive(Clone)]
pub struct WireGuardConfig {
    server_private_key: [u8; 32],
    peer_public_key: [u8; 32],
    dns: DnsConfig,
}

impl std::fmt::Debug for WireGuardConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WireGuardConfig")
            .field("server_private_key", &"[REDACTED]")
            .field("peer_public_key", &"[REDACTED]")
            .field("dns", &self.dns)
            .finish()
    }
}

impl WireGuardConfig {
    /// Build a WireGuard configuration from base64-encoded X25519 keys.
    pub fn from_base64(
        server_private_key: &str,
        peer_public_key: &str,
        dns: DnsConfig,
    ) -> io::Result<Self> {
        Ok(Self {
            server_private_key: decode_key(server_private_key)?,
            peer_public_key: decode_key(peer_public_key)?,
            dns,
        })
    }

    /// Return the server public key as standard padded base64.
    #[must_use]
    pub fn server_public_key(&self) -> String {
        let private = StaticSecret::from(self.server_private_key);
        encode_key(PublicKey::from(&private).as_bytes())
    }

    /// Load or generate a private server key and one client identity.
    ///
    /// Secret-bearing files are written with owner-only permissions on Unix.
    /// The returned path points to an importable WireGuard client config.
    pub fn load_or_generate(
        directory: &Path,
        endpoint: &str,
        dns: DnsConfig,
    ) -> io::Result<(Self, PathBuf)> {
        validate_endpoint(endpoint)?;
        std::fs::create_dir_all(directory)?;
        let server_private_key = load_or_generate_key(&directory.join(SERVER_KEY_FILE))?;
        let client_private_key = load_or_generate_key(&directory.join(CLIENT_KEY_FILE))?;
        let server_private = StaticSecret::from(server_private_key);
        let client_private = StaticSecret::from(client_private_key);
        let server_public = PublicKey::from(&server_private);
        let client_public = PublicKey::from(&client_private);
        let client_config_path = directory.join(CLIENT_CONFIG_FILE);
        let client_config = format!(
            "[Interface]\nPrivateKey = {}\nAddress = {CLIENT_ADDRESS}/32, fd00::2/128\nDNS = {SERVER_ADDRESS}\n\n[Peer]\nPublicKey = {}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {endpoint}\nPersistentKeepalive = 25\n",
            encode_key(&client_private_key),
            encode_key(server_public.as_bytes()),
        );
        crate::session::write_private(&client_config_path, client_config.as_bytes())?;
        Ok((
            Self {
                server_private_key,
                peer_public_key: *client_public.as_bytes(),
                dns,
            },
            client_config_path,
        ))
    }
}

fn validate_endpoint(endpoint: &str) -> io::Result<()> {
    HostWithPort::try_from(endpoint)
        .map_err(|_| invalid_input("WireGuard endpoint must be HOST:PORT"))?;
    Ok(())
}

fn load_or_generate_key(path: &Path) -> io::Result<[u8; 32]> {
    match std::fs::read_to_string(path) {
        Ok(value) => decode_key(value.trim()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut key = [0_u8; 32];
            rama::crypto::dep::boring::rand::rand_bytes(&mut key).map_err(io::Error::other)?;
            let encoded = format!("{}\n", encode_key(&key));
            crate::session::write_private(path, encoded.as_bytes())?;
            Ok(key)
        }
        Err(error) => Err(error),
    }
}

fn decode_key(value: &str) -> io::Result<[u8; 32]> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|_| invalid_input("WireGuard keys must be base64"))?;
    bytes
        .try_into()
        .map_err(|_| invalid_input("WireGuard keys must decode to 32 bytes"))
}

fn encode_key(value: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(value)
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

struct Peer {
    tunnel: Tunn,
    endpoint: Option<SocketAddr>,
}

impl Peer {
    fn new(config: &WireGuardConfig) -> Self {
        Self {
            tunnel: Tunn::new(
                StaticSecret::from(config.server_private_key),
                PublicKey::from(config.peer_public_key),
                None,
                Some(25),
                0,
                None,
            ),
            endpoint: None,
        }
    }
}

/// Run a WireGuard endpoint until shutdown, inspecting TCP and UDP traffic.
#[allow(clippy::too_many_arguments)]
pub async fn serve(
    address: SocketAddr,
    config: WireGuardConfig,
    handler: CapturingHandler,
    ca: Arc<Ssl>,
    client: Arc<UpstreamClient>,
    peek_timeout_policy: PeekTimeoutPolicy,
    event_tx: mpsc::Sender<ProxyEvent>,
    replay_rx: Option<mpsc::Receiver<ProxiedRequest>>,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    let socket = UdpSocket::bind(address).await?;
    let local_address = socket.local_addr()?;
    tracing::info!(
        "WireGuard proxy listening on {local_address}; client tunnel address {CLIENT_ADDRESS}"
    );

    let (stack, runner, virtual_udp, tcp_listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(true)
        .mtu(65_000)
        .build()?;
    let virtual_udp = virtual_udp.ok_or_else(|| io::Error::other("UDP stack unavailable"))?;
    let tcp_listener = tcp_listener.ok_or_else(|| io::Error::other("TCP stack unavailable"))?;
    let runner = runner.ok_or_else(|| io::Error::other("network stack runner unavailable"))?;
    let (decrypted_tx, decrypted_rx) = mpsc::channel(1_024);
    let (encrypted_tx, encrypted_rx) = mpsc::channel(1_024);
    let cancel = CancellationToken::new();
    let mut tasks = JoinSet::new();

    tasks.spawn(runner);
    tasks.spawn(stack_bridge(
        stack,
        decrypted_rx,
        encrypted_tx,
        cancel.clone(),
    ));
    tasks.spawn(wireguard_loop(
        socket,
        Peer::new(&config),
        decrypted_tx,
        encrypted_rx,
        cancel.clone(),
    ));
    tasks.spawn(tcp_loop(
        tcp_listener,
        handler.clone(),
        ca,
        Arc::clone(&client),
        peek_timeout_policy,
        cancel.clone(),
    ));
    tasks.spawn(udp_loop(virtual_udp, config.dns, event_tx, cancel.clone()));
    tasks.spawn(replay_loop(handler, client, replay_rx, cancel.clone()));

    tokio::pin!(shutdown);
    let result = tokio::select! {
        () = &mut shutdown => Ok(()),
        task = tasks.join_next() => match task {
            Some(Ok(result)) => result.and_then(|()| Err(io::Error::other("WireGuard task stopped unexpectedly"))),
            Some(Err(error)) => Err(io::Error::other(format!("WireGuard task panicked: {error}"))),
            None => Err(io::Error::other("WireGuard tasks stopped unexpectedly")),
        },
    };
    cancel.cancel();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}

async fn replay_loop(
    handler: CapturingHandler,
    client: Arc<UpstreamClient>,
    mut replay_rx: Option<mpsc::Receiver<ProxiedRequest>>,
    cancel: CancellationToken,
) -> io::Result<()> {
    loop {
        tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            request = receive_replay(&mut replay_rx) => {
                if let Some(request) = request {
                    tokio::spawn(forward::handle_replay(
                        request,
                        handler.clone(),
                        Arc::clone(&client),
                    ));
                }
            }
        }
    }
}

async fn receive_replay(
    replay_rx: &mut Option<mpsc::Receiver<ProxiedRequest>>,
) -> Option<ProxiedRequest> {
    match replay_rx {
        Some(receiver) => match receiver.recv().await {
            Some(request) => Some(request),
            None => std::future::pending().await,
        },
        None => std::future::pending().await,
    }
}

async fn stack_bridge(
    stack: netstack_smoltcp::Stack,
    mut decrypted_rx: mpsc::Receiver<Vec<u8>>,
    encrypted_tx: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
) -> io::Result<()> {
    let (mut sink, mut stream) = stack.split();
    loop {
        tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            packet = decrypted_rx.recv() => {
                let Some(packet) = packet else { return Ok(()); };
                if let Err(error) = sink.send(packet).await {
                    tracing::debug!("Discarding invalid WireGuard IP packet: {error}");
                }
            }
            packet = stream.next() => {
                let Some(packet) = packet else { return Ok(()); };
                encrypted_tx.send(packet?).await.map_err(|_| io::Error::other("WireGuard encryptor stopped"))?;
            }
        }
    }
}

async fn wireguard_loop(
    socket: UdpSocket,
    mut peer: Peer,
    decrypted_tx: mpsc::Sender<Vec<u8>>,
    mut encrypted_rx: mpsc::Receiver<Vec<u8>>,
    cancel: CancellationToken,
) -> io::Result<()> {
    let mut datagram = vec![0_u8; MAX_PACKET_SIZE];
    let mut output = vec![0_u8; MAX_PACKET_SIZE];
    let mut timers = tokio::time::interval(Duration::from_millis(250));
    timers.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            received = socket.recv_from(&mut datagram) => {
                let (length, source) = received?;
                process_incoming(
                    &socket,
                    &mut peer,
                    source,
                    &datagram[..length],
                    &mut output,
                    &decrypted_tx,
                ).await?;
            }
            packet = encrypted_rx.recv() => {
                let Some(packet) = packet else { return Ok(()); };
                process_outgoing(&socket, &mut peer, &packet, &mut output).await?;
            }
            _ = timers.tick() => {
                process_timer(&socket, &mut peer, &mut output).await?;
            }
        }
    }
}

async fn process_incoming(
    socket: &UdpSocket,
    peer: &mut Peer,
    source: SocketAddr,
    datagram: &[u8],
    output: &mut [u8],
    decrypted_tx: &mpsc::Sender<Vec<u8>>,
) -> io::Result<()> {
    let mut first = true;
    loop {
        let result = peer.tunnel.decapsulate(
            first.then_some(source.ip()),
            if first { datagram } else { &[] },
            output,
        );
        first = false;
        match result {
            TunnResult::Done => return Ok(()),
            TunnResult::Err(error) => {
                tracing::debug!("Rejected WireGuard packet from {source}: {error:?}");
                return Ok(());
            }
            TunnResult::WriteToNetwork(response) => {
                peer.endpoint = Some(source);
                socket.send_to(response, source).await?;
            }
            TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                peer.endpoint = Some(source);
                decrypted_tx
                    .send(packet.to_vec())
                    .await
                    .map_err(|_| io::Error::other("WireGuard network stack stopped"))?;
                return Ok(());
            }
        }
    }
}

async fn process_outgoing(
    socket: &UdpSocket,
    peer: &mut Peer,
    packet: &[u8],
    output: &mut [u8],
) -> io::Result<()> {
    if packet.len() > MAX_PACKET_SIZE - WIREGUARD_OVERHEAD {
        tracing::warn!(
            "Dropping oversized WireGuard IP packet ({} bytes)",
            packet.len()
        );
        return Ok(());
    }
    let Some(endpoint) = peer.endpoint else {
        tracing::debug!("Dropping WireGuard response before the peer has completed a handshake");
        return Ok(());
    };
    match peer.tunnel.encapsulate(packet, output) {
        TunnResult::WriteToNetwork(datagram) => {
            socket.send_to(datagram, endpoint).await?;
        }
        TunnResult::Done => {}
        TunnResult::Err(error) => tracing::debug!("WireGuard encryption failed: {error:?}"),
        TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
            tracing::warn!("WireGuard returned an unexpected tunnel packet while encrypting");
        }
    }
    Ok(())
}

async fn process_timer(socket: &UdpSocket, peer: &mut Peer, output: &mut [u8]) -> io::Result<()> {
    let Some(endpoint) = peer.endpoint else {
        return Ok(());
    };
    match peer.tunnel.update_timers(output) {
        TunnResult::WriteToNetwork(datagram) => {
            socket.send_to(datagram, endpoint).await?;
        }
        TunnResult::Done | TunnResult::Err(_) => {}
        TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
            tracing::warn!("WireGuard timer returned an unexpected tunnel packet");
        }
    }
    Ok(())
}

async fn tcp_loop(
    mut listener: TcpListener,
    handler: CapturingHandler,
    ca: Arc<Ssl>,
    client: Arc<UpstreamClient>,
    peek_timeout_policy: PeekTimeoutPolicy,
    cancel: CancellationToken,
) -> io::Result<()> {
    loop {
        tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            connection = listener.next() => {
                let Some((stream, _source, destination)) = connection else { return Ok(()); };
                let authority = HostWithPort::from(destination);
                // The netstack stream is a bare tokio duplex; wrap it so it
                // satisfies rama's `Io + ExtensionsRef` bound.
                let stream = rama::ServiceInput::new(stream);
                tokio::spawn(forward::handle_captured_stream(
                    stream,
                    handler.clone(),
                    Arc::clone(&ca),
                    Arc::clone(&client),
                    SocketAddr::new(IpAddr::V4(SERVER_ADDRESS), 80),
                    authority,
                    peek_timeout_policy,
                ));
            }
        }
    }
}

async fn udp_loop(
    socket: VirtualUdpSocket,
    dns_config: DnsConfig,
    event_tx: mpsc::Sender<ProxyEvent>,
    cancel: CancellationToken,
) -> io::Result<()> {
    let (mut reader, mut writer) = socket.split();
    let (response_tx, mut response_rx) = mpsc::channel(1_024);
    loop {
        tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            response = response_rx.recv() => {
                let Some(response) = response else { return Ok(()); };
                writer.send(response).await?;
            }
            datagram = reader.next() => {
                let Some((request, source, destination)) = datagram else { return Ok(()); };
                let response_tx = response_tx.clone();
                let dns_config = dns_config.clone();
                let event_tx = event_tx.clone();
                tokio::spawn(async move {
                    let response = if destination.port() == 53 {
                        dns::resolve_packet(request, dns_config, event_tx).await
                    } else {
                        udp::exchange(source, destination, request, event_tx).await
                    };
                    match response {
                        Ok(response) => {
                            let _ = response_tx.send((response, destination, source)).await;
                        }
                        Err(error) => tracing::debug!(
                            "WireGuard UDP exchange {source} -> {destination} failed: {error}"
                        ),
                    }
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_stable_private_client_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let dns = DnsConfig::new("127.0.0.1:53".parse().unwrap());
        let (first, path) =
            WireGuardConfig::load_or_generate(directory.path(), "vpn.example:51820", dns.clone())
                .unwrap();
        let (second, second_path) =
            WireGuardConfig::load_or_generate(directory.path(), "vpn.example:51820", dns).unwrap();
        assert_eq!(first.server_private_key, second.server_private_key);
        assert_eq!(first.peer_public_key, second.peer_public_key);
        assert_eq!(path, second_path);
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some("proxelar-wg.conf")
        );
        let contents = std::fs::read_to_string(path).unwrap();
        assert!(contents.contains("Address = 10.0.0.2/32, fd00::2/128"));
        assert!(contents.contains("Endpoint = vpn.example:51820"));
        assert!(!contents.contains(
            &first
                .server_private_key
                .map(|byte| format!("{byte:02x}"))
                .join("")
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(second_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn rejects_invalid_keys_and_endpoint_injection() {
        let dns = DnsConfig::new("127.0.0.1:53".parse().unwrap());
        assert!(WireGuardConfig::from_base64("bad", "bad", dns.clone()).is_err());
        let directory = tempfile::tempdir().unwrap();
        assert!(WireGuardConfig::load_or_generate(
            directory.path(),
            "host:51820\nAllowedIPs=evil",
            dns,
        )
        .is_err());
    }

    #[test]
    fn boringtun_peer_roundtrip_decrypts_ipv4_packet() {
        let mut server_key = [0_u8; 32];
        let mut client_key = [0_u8; 32];
        rama::crypto::dep::boring::rand::rand_bytes(&mut server_key).unwrap();
        rama::crypto::dep::boring::rand::rand_bytes(&mut client_key).unwrap();
        let server_private = StaticSecret::from(server_key);
        let client_private = StaticSecret::from(client_key);
        let server_public = PublicKey::from(&server_private);
        let client_public = PublicKey::from(&client_private);
        let mut server = Tunn::new(server_private, client_public, None, None, 0, None);
        let mut client = Tunn::new(client_private, server_public, None, None, 1, None);
        let mut client_output = vec![0_u8; 2_048];
        let initiation = match client.format_handshake_initiation(&mut client_output, false) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("unexpected initiation result: {other:?}"),
        };
        let mut server_output = vec![0_u8; 2_048];
        let response = match server.decapsulate(
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            &initiation,
            &mut server_output,
        ) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("unexpected server handshake result: {other:?}"),
        };
        let _ = client.decapsulate(
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            &response,
            &mut client_output,
        );
        let mut ipv4 = vec![0_u8; 20];
        ipv4[0] = 0x45;
        ipv4[2..4].copy_from_slice(&20_u16.to_be_bytes());
        let encrypted = match client.encapsulate(&ipv4, &mut client_output) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("unexpected encryption result: {other:?}"),
        };
        match server.decapsulate(
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            &encrypted,
            &mut server_output,
        ) {
            TunnResult::WriteToTunnelV4(packet, _) => assert_eq!(packet, ipv4),
            other => panic!("unexpected decryption result: {other:?}"),
        }
    }

    #[tokio::test]
    async fn proxy_mode_starts_and_shuts_down_cleanly() {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = probe.local_addr().unwrap();
        drop(probe);
        let config = WireGuardConfig::from_base64(
            &encode_key(&[7_u8; 32]),
            &encode_key(&[9_u8; 32]),
            DnsConfig::new("127.0.0.1:53".parse().unwrap()),
        )
        .unwrap();
        let (event_tx, _event_rx) = mpsc::channel(8);
        let directory = tempfile::tempdir().unwrap();
        let proxy = crate::Proxy::new(crate::ProxyConfig {
            addr: address,
            mode: crate::ProxyMode::WireGuard { config },
            event_tx,
            ca_dir: directory.path().to_path_buf(),
            upstream_tls: crate::UpstreamTlsConfig::Default,
            upstream_http_version: crate::UpstreamHttpVersion::default(),
            intercept: None,
            body_capture_limit: Some(1_024),
            #[cfg(feature = "scripting")]
            script_path: None,
            replay_rx: None,
        });
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(proxy.start(async {
            let _ = shutdown_rx.await;
        }));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!task.is_finished());
        shutdown_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[test]
    fn validates_endpoints_existing_keys_and_debug_redaction() {
        for endpoint in ["vpn.example:51820", "127.0.0.1:51820", "[::1]:51820"] {
            validate_endpoint(endpoint).unwrap();
        }
        for endpoint in [
            "",
            "vpn.example",
            "http://vpn.example:51820",
            "host:\n51820",
        ] {
            assert_eq!(
                validate_endpoint(endpoint).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("key");
        let key = [42_u8; 32];
        std::fs::write(&path, format!("  {}\n", encode_key(&key))).unwrap();
        assert_eq!(load_or_generate_key(&path).unwrap(), key);
        std::fs::write(&path, "not-base64").unwrap();
        assert_eq!(
            load_or_generate_key(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            decode_key(&encode_key(&[1_u8; 16].repeat(2).try_into().unwrap())).unwrap(),
            [1_u8; 32]
        );

        let config = WireGuardConfig::from_base64(
            &encode_key(&[7_u8; 32]),
            &encode_key(&[9_u8; 32]),
            DnsConfig::new("127.0.0.1:53".parse().unwrap()),
        )
        .unwrap();
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&encode_key(&[7_u8; 32])));
        assert_eq!(config.server_public_key().len(), 44);
    }

    #[tokio::test]
    async fn replay_receivers_and_cancelled_loops_stop_cleanly() {
        let request = ProxiedRequest::new(
            rama::http::Method::GET,
            "http://example.test/".parse().unwrap(),
            rama::http::Version::HTTP_11,
            rama::http::HeaderMap::new(),
            rama::bytes::Bytes::new(),
            1,
        );
        let (request_tx, request_rx) = mpsc::channel(1);
        request_tx.send(request).await.unwrap();
        let mut request_rx = Some(request_rx);
        assert_eq!(
            receive_replay(&mut request_rx)
                .await
                .unwrap()
                .uri()
                .host_str()
                .as_deref(),
            Some("example.test")
        );
        drop(request_tx);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), receive_replay(&mut request_rx))
                .await
                .is_err()
        );
        let mut absent = None;
        assert!(
            tokio::time::timeout(Duration::from_millis(10), receive_replay(&mut absent))
                .await
                .is_err()
        );

        let (stack, _, _, _) = StackBuilder::default().build().unwrap();
        let (_decrypted_tx, decrypted_rx) = mpsc::channel(1);
        let (encrypted_tx, _encrypted_rx) = mpsc::channel(1);
        let cancel = CancellationToken::new();
        cancel.cancel();
        stack_bridge(stack, decrypted_rx, encrypted_tx, cancel)
            .await
            .unwrap();

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = WireGuardConfig::from_base64(
            &encode_key(&[7_u8; 32]),
            &encode_key(&[9_u8; 32]),
            DnsConfig::new("127.0.0.1:53".parse().unwrap()),
        )
        .unwrap();
        let (decrypted_tx, _decrypted_rx) = mpsc::channel(1);
        let (_encrypted_tx, encrypted_rx) = mpsc::channel(1);
        let cancel = CancellationToken::new();
        cancel.cancel();
        wireguard_loop(
            socket,
            Peer::new(&config),
            decrypted_tx,
            encrypted_rx,
            cancel,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn packet_processors_complete_a_handshake_and_exchange_packets() {
        let mut server_key = [0_u8; 32];
        let mut client_key = [0_u8; 32];
        rama::crypto::dep::boring::rand::rand_bytes(&mut server_key).unwrap();
        rama::crypto::dep::boring::rand::rand_bytes(&mut client_key).unwrap();
        let server_private = StaticSecret::from(server_key);
        let client_private = StaticSecret::from(client_key);
        let server_public = PublicKey::from(&server_private);
        let client_public = PublicKey::from(&client_private);
        let config = WireGuardConfig {
            server_private_key: server_key,
            peer_public_key: *client_public.as_bytes(),
            dns: DnsConfig::new("127.0.0.1:53".parse().unwrap()),
        };
        let mut peer = Peer::new(&config);
        let mut client = Tunn::new(client_private, server_public, None, None, 1, None);
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_address = client_socket.local_addr().unwrap();
        let (decrypted_tx, mut decrypted_rx) = mpsc::channel(4);
        let mut client_output = vec![0_u8; 2_048];
        let initiation = match client.format_handshake_initiation(&mut client_output, false) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("unexpected initiation result: {other:?}"),
        };
        let mut server_output = vec![0_u8; MAX_PACKET_SIZE];
        process_incoming(
            &server_socket,
            &mut peer,
            client_address,
            &initiation,
            &mut server_output,
            &decrypted_tx,
        )
        .await
        .unwrap();
        let mut handshake = vec![0_u8; 2_048];
        let (handshake_len, _) = client_socket.recv_from(&mut handshake).await.unwrap();
        let _ = client.decapsulate(
            Some(server_socket.local_addr().unwrap().ip()),
            &handshake[..handshake_len],
            &mut client_output,
        );
        assert_eq!(peer.endpoint, Some(client_address));

        let mut ipv4 = vec![0_u8; 20];
        ipv4[0] = 0x45;
        ipv4[2..4].copy_from_slice(&20_u16.to_be_bytes());
        let encrypted = match client.encapsulate(&ipv4, &mut client_output) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("unexpected encryption result: {other:?}"),
        };
        process_incoming(
            &server_socket,
            &mut peer,
            client_address,
            &encrypted,
            &mut server_output,
            &decrypted_tx,
        )
        .await
        .unwrap();
        assert_eq!(decrypted_rx.recv().await.unwrap(), ipv4);

        let response_packet = vec![0x45; 20];
        process_outgoing(
            &server_socket,
            &mut peer,
            &response_packet,
            &mut server_output,
        )
        .await
        .unwrap();
        let (encrypted_len, _) = client_socket.recv_from(&mut handshake).await.unwrap();
        assert!(encrypted_len > 0);
        let _ = client.decapsulate(
            Some(server_socket.local_addr().unwrap().ip()),
            &handshake[..encrypted_len],
            &mut client_output,
        );
        process_timer(&server_socket, &mut peer, &mut server_output)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn packet_processors_drop_invalid_oversized_and_unroutable_packets() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = WireGuardConfig::from_base64(
            &encode_key(&[7_u8; 32]),
            &encode_key(&[9_u8; 32]),
            DnsConfig::new("127.0.0.1:53".parse().unwrap()),
        )
        .unwrap();
        let mut peer = Peer::new(&config);
        let (decrypted_tx, mut decrypted_rx) = mpsc::channel(1);
        let mut output = vec![0_u8; MAX_PACKET_SIZE];
        process_incoming(
            &server_socket,
            &mut peer,
            "127.0.0.1:9".parse().unwrap(),
            b"invalid",
            &mut output,
            &decrypted_tx,
        )
        .await
        .unwrap();
        assert!(decrypted_rx.try_recv().is_err());
        process_outgoing(&server_socket, &mut peer, b"small", &mut output)
            .await
            .unwrap();
        process_outgoing(
            &server_socket,
            &mut peer,
            &vec![0_u8; MAX_PACKET_SIZE],
            &mut output,
        )
        .await
        .unwrap();
        process_timer(&server_socket, &mut peer, &mut output)
            .await
            .unwrap();
    }
}
