//! Privilege-free WireGuard capture backed by a userspace TCP/IP stack.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "http3")]
use std::collections::HashMap;

use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use futures_util::{SinkExt, StreamExt};
use http::uri::Authority;
use netstack_smoltcp::{StackBuilder, TcpListener, UdpSocket as VirtualUdpSocket};
use proxyapi_models::ProxiedRequest;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::ca::Ssl;
use crate::event::ProxyEvent;
use crate::handler::CapturingHandler;

#[cfg(feature = "http3")]
use crate::HttpHandler as _;
#[cfg(feature = "http3")]
use proxelar_proto::{BoxFuture, HttpService, ProtocolError, ProxyRequest, ProxyResponse};
#[cfg(feature = "http3")]
use rustls::client::danger::ServerCertVerifier;

use super::{dns, forward, http1::NativePool, udp, DnsConfig};

const MAX_PACKET_SIZE: usize = 65_535;
const WIREGUARD_OVERHEAD: usize = 80;
const CLIENT_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const SERVER_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const SERVER_KEY_FILE: &str = "wireguard-server.key";
const CLIENT_KEY_FILE: &str = "wireguard-client.key";
// Android derives the tunnel/interface name from this stem and enforces the
// WireGuard 15-character interface-name limit.
const CLIENT_CONFIG_FILE: &str = "proxelar-wg.conf";
#[cfg(feature = "http3")]
const H3_FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

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
    let authority = endpoint
        .parse::<Authority>()
        .map_err(|_| invalid_input("WireGuard endpoint must be HOST:PORT"))?;
    if authority.host().is_empty() || authority.port_u16().is_none() {
        return Err(invalid_input("WireGuard endpoint must be HOST:PORT"));
    }
    Ok(())
}

fn load_or_generate_key(path: &Path) -> io::Result<[u8; 32]> {
    match std::fs::read_to_string(path) {
        Ok(value) => decode_key(value.trim()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut key = [0_u8; 32];
            getrandom::fill(&mut key).map_err(|error| io::Error::other(error.to_string()))?;
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
    native_pool: Arc<NativePool>,
    native_route: Option<String>,
    upstream_tls: super::UpstreamTlsConfig,
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
    #[cfg(feature = "http3")]
    let h3_verifier = super::tls::h3_server_verifier(&upstream_tls)
        .map_err(|error| io::Error::other(error.to_string()))?;
    #[cfg(not(feature = "http3"))]
    let _ = upstream_tls;

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
        Arc::clone(&ca),
        Arc::clone(&native_pool),
        native_route.clone(),
        cancel.clone(),
    ));
    tasks.spawn(udp_loop(
        virtual_udp,
        UdpLoopConfig {
            dns: config.dns,
            event_tx,
            cancel: cancel.clone(),
            #[cfg(feature = "http3")]
            handler: handler.clone(),
            #[cfg(feature = "http3")]
            ca: Arc::clone(&ca),
            #[cfg(feature = "http3")]
            verifier: h3_verifier,
        },
    ));
    tasks.spawn(replay_loop(
        handler,
        native_pool,
        native_route,
        replay_rx,
        cancel.clone(),
    ));

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
    native_pool: Arc<NativePool>,
    native_route: Option<String>,
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
                        Arc::clone(&native_pool),
                        native_route.clone(),
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
    native_pool: Arc<NativePool>,
    native_route: Option<String>,
    cancel: CancellationToken,
) -> io::Result<()> {
    loop {
        tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            connection = listener.next() => {
                let Some((stream, source, destination)) = connection else { return Ok(()); };
                let authority = destination
                    .to_string()
                    .parse::<Authority>()
                    .map_err(|_| invalid_input("invalid WireGuard TCP destination"))?;
                tokio::spawn(forward::handle_captured_stream(
                    stream,
                    source,
                    handler.clone(),
                    Arc::clone(&ca),
                    Arc::clone(&native_pool),
                    native_route.clone(),
                    SocketAddr::new(IpAddr::V4(SERVER_ADDRESS), 80),
                    authority,
                ));
            }
        }
    }
}

struct UdpLoopConfig {
    dns: DnsConfig,
    event_tx: mpsc::Sender<ProxyEvent>,
    cancel: CancellationToken,
    #[cfg(feature = "http3")]
    handler: CapturingHandler,
    #[cfg(feature = "http3")]
    ca: Arc<Ssl>,
    #[cfg(feature = "http3")]
    verifier: Arc<dyn ServerCertVerifier>,
}

#[cfg(not(feature = "http3"))]
async fn udp_loop(socket: VirtualUdpSocket, config: UdpLoopConfig) -> io::Result<()> {
    let (mut reader, mut writer) = socket.split();
    let (response_tx, mut response_rx) = mpsc::channel(1_024);
    loop {
        tokio::select! {
            () = config.cancel.cancelled() => return Ok(()),
            response = response_rx.recv() => {
                let Some(response) = response else { return Ok(()); };
                writer.send(response).await?;
            }
            datagram = reader.next() => {
                let Some((request, source, destination)) = datagram else { return Ok(()); };
                spawn_udp_exchange(
                    request,
                    source,
                    destination,
                    config.dns.clone(),
                    config.event_tx.clone(),
                    response_tx.clone(),
                );
            }
        }
    }
}

fn spawn_udp_exchange(
    request: Vec<u8>,
    source: SocketAddr,
    destination: SocketAddr,
    dns_config: DnsConfig,
    event_tx: mpsc::Sender<ProxyEvent>,
    response_tx: mpsc::Sender<(Vec<u8>, SocketAddr, SocketAddr)>,
) {
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
            Err(error) => {
                tracing::debug!("WireGuard UDP exchange {source} -> {destination} failed: {error}")
            }
        }
    });
}

#[cfg(feature = "http3")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct UdpFlowKey {
    source: SocketAddr,
    destination: SocketAddr,
}

#[cfg(feature = "http3")]
struct H3FlowHandle {
    generation: u64,
    datagrams: mpsc::Sender<Vec<u8>>,
}

#[cfg(feature = "http3")]
#[derive(Debug, Eq, PartialEq)]
enum H3DatagramDispatch {
    Queued,
    Saturated,
    Closed(Vec<u8>),
}

#[cfg(feature = "http3")]
fn dispatch_h3_datagram(flow: &H3FlowHandle, datagram: Vec<u8>) -> H3DatagramDispatch {
    match flow.datagrams.try_send(datagram) {
        Ok(()) => H3DatagramDispatch::Queued,
        Err(mpsc::error::TrySendError::Full(_)) => H3DatagramDispatch::Saturated,
        Err(mpsc::error::TrySendError::Closed(datagram)) => H3DatagramDispatch::Closed(datagram),
    }
}

#[cfg(feature = "http3")]
struct H3FlowContext {
    handler: CapturingHandler,
    ca: Arc<Ssl>,
    verifier: Arc<dyn ServerCertVerifier>,
    response_tx: mpsc::Sender<(Vec<u8>, SocketAddr, SocketAddr)>,
    completed_tx: mpsc::Sender<(UdpFlowKey, u64)>,
    cancel: CancellationToken,
}

#[cfg(feature = "http3")]
async fn udp_loop(socket: VirtualUdpSocket, config: UdpLoopConfig) -> io::Result<()> {
    let (mut reader, mut writer) = socket.split();
    let (response_tx, mut response_rx) = mpsc::channel(1_024);
    let (completed_tx, mut completed_rx) = mpsc::channel(128);
    let mut h3_flows = HashMap::<UdpFlowKey, H3FlowHandle>::new();
    let mut next_generation = 0_u64;

    loop {
        tokio::select! {
            () = config.cancel.cancelled() => return Ok(()),
            response = response_rx.recv() => {
                let Some(response) = response else { return Ok(()); };
                writer.send(response).await?;
            }
            completed = completed_rx.recv() => {
                let Some((key, generation)) = completed else { return Ok(()); };
                if h3_flows.get(&key).is_some_and(|flow| flow.generation == generation) {
                    h3_flows.remove(&key);
                }
            }
            datagram = reader.next() => {
                let Some((mut request, source, destination)) = datagram else { return Ok(()); };
                let key = UdpFlowKey { source, destination };
                if let Some(flow) = h3_flows.get(&key) {
                    match dispatch_h3_datagram(flow, request) {
                        H3DatagramDispatch::Queued => continue,
                        H3DatagramDispatch::Saturated => {
                            tracing::trace!(
                                "Dropping WireGuard HTTP/3 datagram for saturated flow {source} -> {destination}"
                            );
                            continue;
                        }
                        H3DatagramDispatch::Closed(datagram) => request = datagram,
                    }
                    h3_flows.remove(&key);
                }

                if destination.port() != 53 && is_quic_initial(&request) {
                    next_generation = next_generation.wrapping_add(1);
                    let generation = next_generation;
                    match start_h3_flow(
                        key,
                        generation,
                        H3FlowContext {
                            handler: config.handler.clone(),
                            ca: Arc::clone(&config.ca),
                            verifier: Arc::clone(&config.verifier),
                            response_tx: response_tx.clone(),
                            completed_tx: completed_tx.clone(),
                            cancel: config.cancel.clone(),
                        },
                    ).await {
                        Ok(flow) => {
                            match dispatch_h3_datagram(&flow, request) {
                                H3DatagramDispatch::Queued => {
                                    h3_flows.insert(key, flow);
                                    continue;
                                }
                                H3DatagramDispatch::Saturated => {
                                    tracing::trace!(
                                        "Dropping initial WireGuard HTTP/3 datagram for saturated flow {source} -> {destination}"
                                    );
                                    continue;
                                }
                                H3DatagramDispatch::Closed(datagram) => request = datagram,
                            }
                        }
                        Err(error) => tracing::debug!(
                            "WireGuard HTTP/3 interception {source} -> {destination} failed to start: {error}"
                        ),
                    }
                }

                spawn_udp_exchange(
                    request,
                    source,
                    destination,
                    config.dns.clone(),
                    config.event_tx.clone(),
                    response_tx.clone(),
                );
            }
        }
    }
}

#[cfg(feature = "http3")]
fn is_quic_initial(datagram: &[u8]) -> bool {
    let mut packet = datagram.to_vec();
    tokio_quiche::quiche::Header::from_slice(&mut packet, 0).is_ok_and(|header| {
        header.ty == tokio_quiche::quiche::Type::Initial
            && tokio_quiche::quiche::version_is_supported(header.version)
    })
}

#[cfg(feature = "http3")]
async fn start_h3_flow(
    key: UdpFlowKey,
    generation: u64,
    context: H3FlowContext,
) -> io::Result<H3FlowHandle> {
    use tokio_quiche::metrics::DefaultMetrics;
    use tokio_quiche::settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths};
    use tokio_quiche::{listen, ConnectionParams};

    let H3FlowContext {
        handler,
        ca,
        verifier,
        response_tx,
        completed_tx,
        cancel,
    } = context;
    let authority = key
        .destination
        .to_string()
        .parse::<Authority>()
        .map_err(|_| invalid_input("invalid WireGuard HTTP/3 destination"))?;
    let certificate = ca
        .gen_h3_certificate(&authority)
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
    let tls_files = tempfile::tempdir()?;
    let cert_path = tls_files.path().join("wireguard-h3-cert.pem");
    let key_path = tls_files.path().join("wireguard-h3-key.pem");
    std::fs::write(&cert_path, &certificate.certificate_pem)?;
    std::fs::write(&key_path, &certificate.private_key_pem)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }
    let cert_path_str = cert_path
        .to_str()
        .ok_or_else(|| invalid_input("WireGuard HTTP/3 certificate path is not UTF-8"))?;
    let key_path_str = key_path
        .to_str()
        .ok_or_else(|| invalid_input("WireGuard HTTP/3 key path is not UTF-8"))?;

    let server_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = server_socket.local_addr()?;
    let relay_socket = UdpSocket::bind("127.0.0.1:0").await?;
    relay_socket.connect(server_addr).await?;
    let mut quic_settings = QuicSettings::default();
    quic_settings.alpn = vec![b"h3".to_vec()];
    quic_settings.enable_dgram = false;
    quic_settings.enable_early_data = false;
    let params = ConnectionParams::new_server(
        quic_settings,
        TlsCertificatePaths {
            cert: cert_path_str,
            private_key: key_path_str,
            kind: CertificateKind::X509,
        },
        Hooks {
            connection_hook: Some(Arc::new(super::http3::DynamicH3CertificateHook::new(
                Arc::clone(&ca),
                authority,
            ))),
        },
    );
    let connections = listen([server_socket], params, DefaultMetrics)?
        .pop()
        .ok_or_else(|| io::Error::other("WireGuard HTTP/3 listener was not created"))?;
    let (datagram_tx, datagram_rx) = mpsc::channel(128);
    tokio::spawn(run_h3_flow(H3FlowRuntime {
        key,
        generation,
        relay_socket,
        connections,
        datagrams: datagram_rx,
        handler,
        verifier,
        cert_path,
        key_path,
        _tls_files: tls_files,
        response_tx,
        completed_tx,
        cancel,
    }));
    Ok(H3FlowHandle {
        generation,
        datagrams: datagram_tx,
    })
}

#[cfg(feature = "http3")]
struct H3FlowRuntime {
    key: UdpFlowKey,
    generation: u64,
    relay_socket: UdpSocket,
    connections: tokio_quiche::QuicConnectionStream<tokio_quiche::metrics::DefaultMetrics>,
    datagrams: mpsc::Receiver<Vec<u8>>,
    handler: CapturingHandler,
    verifier: Arc<dyn ServerCertVerifier>,
    cert_path: PathBuf,
    key_path: PathBuf,
    _tls_files: tempfile::TempDir,
    response_tx: mpsc::Sender<(Vec<u8>, SocketAddr, SocketAddr)>,
    completed_tx: mpsc::Sender<(UdpFlowKey, u64)>,
    cancel: CancellationToken,
}

#[cfg(feature = "http3")]
async fn run_h3_flow(runtime: H3FlowRuntime) {
    use tokio_quiche::ServerH3Driver;

    let H3FlowRuntime {
        key,
        generation,
        relay_socket,
        mut connections,
        mut datagrams,
        handler,
        verifier,
        cert_path,
        key_path,
        _tls_files,
        response_tx,
        completed_tx,
        cancel,
    } = runtime;
    let upstreams = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let mut buffer = vec![0_u8; MAX_PACKET_SIZE];
    let idle = tokio::time::sleep(H3_FLOW_IDLE_TIMEOUT);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            () = &mut idle => break,
            datagram = datagrams.recv() => {
                let Some(datagram) = datagram else { break; };
                if let Err(error) = relay_socket.send(&datagram).await {
                    tracing::debug!("WireGuard HTTP/3 relay send failed: {error}");
                    break;
                }
                idle.as_mut().reset(tokio::time::Instant::now() + H3_FLOW_IDLE_TIMEOUT);
            }
            received = relay_socket.recv(&mut buffer) => {
                match received {
                    Ok(length) => {
                        if response_tx
                            .send((buffer[..length].to_vec(), key.destination, key.source))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        idle.as_mut().reset(tokio::time::Instant::now() + H3_FLOW_IDLE_TIMEOUT);
                    }
                    Err(error) => {
                        tracing::debug!("WireGuard HTTP/3 relay receive failed: {error}");
                        break;
                    }
                }
            }
            connection = connections.next() => {
                let Some(connection) = connection else { break; };
                match connection {
                    Ok(initial) => {
                        let (driver, controller) =
                            ServerH3Driver::new(super::http3::default_http3_settings());
                        let connection = initial.start(driver);
                        let service = WireGuardH3Service {
                            remote_addr: key.source,
                            destination: key.destination,
                            handler: handler.clone(),
                            verifier: Arc::clone(&verifier),
                            cert_path: cert_path.clone(),
                            key_path: key_path.clone(),
                            upstreams: Arc::clone(&upstreams),
                        };
                        tokio::spawn(async move {
                            if let Err(error) = super::http3::serve_connection(
                                connection,
                                controller,
                                service,
                            ).await {
                                tracing::debug!("WireGuard HTTP/3 connection failed: {error}");
                            }
                        });
                    }
                    Err(error) => tracing::debug!("Rejected WireGuard HTTP/3 initial packet: {error}"),
                }
            }
        }
    }
    let _ = completed_tx.send((key, generation)).await;
}

#[cfg(feature = "http3")]
#[derive(Clone)]
struct WireGuardH3Service {
    remote_addr: SocketAddr,
    destination: SocketAddr,
    handler: CapturingHandler,
    verifier: Arc<dyn ServerCertVerifier>,
    cert_path: PathBuf,
    key_path: PathBuf,
    upstreams: Arc<tokio::sync::Mutex<HashMap<Authority, super::http3::ReverseH3Upstream>>>,
}

#[cfg(feature = "http3")]
impl HttpService for WireGuardH3Service {
    fn call(
        &mut self,
        request: ProxyRequest,
    ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
        let mut handler = self.handler.clone();
        let remote_addr = self.remote_addr;
        let destination = self.destination;
        let verifier = Arc::clone(&self.verifier);
        let cert_path = self.cert_path.clone();
        let key_path = self.key_path.clone();
        let upstreams = Arc::clone(&self.upstreams);
        Box::pin(async move {
            let context = crate::HttpContext { remote_addr };
            if super::http3::is_extended_websocket(&request) {
                let websocket_upstreams = Arc::clone(&upstreams);
                let websocket_verifier = Arc::clone(&verifier);
                let websocket_cert_path = cert_path.clone();
                let websocket_key_path = key_path.clone();
                return super::http3::handle_extended_websocket(
                    request,
                    handler,
                    remote_addr,
                    None,
                    move |request| async move {
                        let authority = request.head.uri.authority().cloned().ok_or_else(|| {
                            ProtocolError::new(
                                proxelar_proto::ErrorKind::MalformedMessage,
                                "HTTP/3 WebSocket request has no authority",
                            )
                        })?;
                        let upstream = {
                            let mut clients = websocket_upstreams.lock().await;
                            clients
                                .entry(authority)
                                .or_insert_with(|| {
                                    super::http3::ReverseH3Upstream::new_with_remote(
                                        request.head.uri.clone(),
                                        websocket_verifier,
                                        websocket_cert_path,
                                        websocket_key_path,
                                        destination,
                                    )
                                })
                                .clone()
                        };
                        upstream.send(request).await
                    },
                )
                .await;
            }
            let request = match handler.handle_request(&context, request).await {
                crate::RequestOrResponse::Request(request) => request,
                crate::RequestOrResponse::Response(response) => return Ok(response),
            };
            let Some(authority) = request.head.uri.authority().cloned() else {
                return Ok(handler.synthetic_protocol_response(
                    http::StatusCode::BAD_REQUEST,
                    http::HeaderMap::new(),
                    bytes::Bytes::from_static(b"HTTP/3 request has no authority"),
                ));
            };
            let upstream = {
                let mut clients = upstreams.lock().await;
                clients
                    .entry(authority)
                    .or_insert_with(|| {
                        super::http3::ReverseH3Upstream::new_with_remote(
                            request.head.uri.clone(),
                            verifier,
                            cert_path,
                            key_path,
                            destination,
                        )
                    })
                    .clone()
            };
            match upstream.send(request).await {
                Ok(response) => Ok(handler.handle_response(&context, response).await),
                Err(error) => {
                    tracing::debug!("WireGuard HTTP/3 upstream failed: {error}");
                    Ok(handler.synthetic_protocol_response(
                        http::StatusCode::BAD_GATEWAY,
                        http::HeaderMap::new(),
                        bytes::Bytes::from_static(b"Bad Gateway"),
                    ))
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "http3")]
    #[test]
    fn classifies_only_supported_quic_initial_packets() {
        let initial = [0xc0, 0x00, 0x00, 0x00, 0x01, 1, 7, 1, 9, 0];
        let unsupported = [0xc0, 0xfa, 0xfa, 0xfa, 0xfa, 1, 7, 1, 9, 0];

        assert!(is_quic_initial(&initial));
        assert!(!is_quic_initial(&unsupported));
        assert!(!is_quic_initial(b"ordinary UDP"));
    }

    #[cfg(feature = "http3")]
    #[tokio::test]
    async fn saturated_h3_flow_queue_drops_without_waiting() {
        let (datagrams, mut receiver) = mpsc::channel(1);
        let flow = H3FlowHandle {
            generation: 1,
            datagrams,
        };

        assert_eq!(
            dispatch_h3_datagram(&flow, vec![1]),
            H3DatagramDispatch::Queued
        );
        assert_eq!(
            dispatch_h3_datagram(&flow, vec![2]),
            H3DatagramDispatch::Saturated
        );
        assert_eq!(receiver.recv().await, Some(vec![1]));

        drop(receiver);
        assert_eq!(
            dispatch_h3_datagram(&flow, vec![3]),
            H3DatagramDispatch::Closed(vec![3])
        );
    }

    #[cfg(feature = "http3")]
    #[derive(Clone)]
    struct WireGuardTestH3Service;

    #[cfg(feature = "http3")]
    impl HttpService for WireGuardTestH3Service {
        fn call(
            &mut self,
            request: ProxyRequest,
        ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
            Box::pin(async move {
                assert_eq!(request.head.version, http::Version::HTTP_3);
                assert_eq!(request.head.uri.path(), "/inside-wireguard");
                let mut headers = proxyapi_models::HeaderBlock::new();
                headers.add("x-wireguard-upstream", "h3").unwrap();
                Ok(ProxyResponse::new(
                    proxelar_proto::ResponseHead::new(
                        http::StatusCode::CREATED,
                        http::Version::HTTP_3,
                        headers,
                    ),
                    proxelar_proto::ProxyBody::full("wireguard h3 upstream"),
                ))
            })
        }
    }

    #[cfg(feature = "http3")]
    async fn spawn_wireguard_test_h3_upstream() -> (
        SocketAddr,
        tokio::task::JoinHandle<()>,
        tempfile::TempDir,
        PathBuf,
        PathBuf,
    ) {
        use tokio_quiche::metrics::DefaultMetrics;
        use tokio_quiche::settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths};
        use tokio_quiche::{listen, ConnectionParams, ServerH3Driver};

        let ca_dir = tempfile::tempdir().unwrap();
        let ca = Ssl::load_or_generate(ca_dir.path()).unwrap();
        let authority: Authority = "127.0.0.1:443".parse().unwrap();
        let certificate = ca.gen_h3_certificate(&authority).await.unwrap();
        let tls_dir = tempfile::tempdir().unwrap();
        let cert_path = tls_dir.path().join("cert.pem");
        let key_path = tls_dir.path().join("key.pem");
        std::fs::write(&cert_path, &certificate.certificate_pem).unwrap();
        std::fs::write(&key_path, &certificate.private_key_pem).unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let mut quic_settings = QuicSettings::default();
        quic_settings.alpn = vec![b"h3".to_vec()];
        let params = ConnectionParams::new_server(
            quic_settings,
            TlsCertificatePaths {
                cert: cert_path.to_str().unwrap(),
                private_key: key_path.to_str().unwrap(),
                kind: CertificateKind::X509,
            },
            Hooks::default(),
        );
        let mut connections = listen([socket], params, DefaultMetrics).unwrap().remove(0);
        let task = tokio::spawn(async move {
            let initial = connections.next().await.unwrap().unwrap();
            let (driver, controller) =
                ServerH3Driver::new(super::super::http3::default_http3_settings());
            let connection = initial.start(driver);
            super::super::http3::serve_connection(connection, controller, WireGuardTestH3Service)
                .await
                .unwrap();
        });
        (address, task, tls_dir, cert_path, key_path)
    }

    #[cfg(feature = "http3")]
    #[tokio::test]
    async fn wireguard_h3_relay_routes_captures_and_mints_sni_certificate() {
        use crate::handler::DEFAULT_BODY_CAPTURE_LIMIT;
        use crate::UpstreamTlsConfig;
        use proxelar_proto::{ProxyBody, RequestHead};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let (upstream_addr, upstream_task, upstream_tls_dir, cert_path, key_path) =
            spawn_wireguard_test_h3_upstream().await;
        let proxy_ca_dir = tempfile::tempdir().unwrap();
        let proxy_ca = Arc::new(Ssl::load_or_generate(proxy_ca_dir.path()).unwrap());
        let proxy_ca_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(proxy_ca_file.path(), proxy_ca.ca_cert_pem()).unwrap();
        let client_verifier = super::super::tls::h3_server_verifier(
            &UpstreamTlsConfig::CaFileOnly(proxy_ca_file.path().to_path_buf()),
        )
        .unwrap();
        let upstream_verifier =
            super::super::tls::h3_server_verifier(&UpstreamTlsConfig::Insecure).unwrap();
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let handler =
            CapturingHandler::new(event_tx).with_body_capture_limit(DEFAULT_BODY_CAPTURE_LIMIT);
        let flow_key = UdpFlowKey {
            source: "10.0.0.2:42424".parse().unwrap(),
            destination: upstream_addr,
        };
        let (response_tx, mut response_rx) = mpsc::channel(128);
        let (completed_tx, _completed_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let flow = start_h3_flow(
            flow_key,
            1,
            H3FlowContext {
                handler,
                ca: proxy_ca,
                verifier: upstream_verifier,
                response_tx,
                completed_tx,
                cancel: cancel.clone(),
            },
        )
        .await
        .unwrap();

        let bridge = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let bridge_addr = bridge.local_addr().unwrap();
        let bridge_task = {
            let bridge = Arc::clone(&bridge);
            let datagrams = flow.datagrams;
            tokio::spawn(async move {
                let mut client = None;
                let mut buffer = vec![0_u8; MAX_PACKET_SIZE];
                loop {
                    tokio::select! {
                        received = bridge.recv_from(&mut buffer) => {
                            let (length, source) = received.unwrap();
                            client = Some(source);
                            if datagrams.send(buffer[..length].to_vec()).await.is_err() {
                                break;
                            }
                        }
                        response = response_rx.recv() => {
                            let Some((response, _, _)) = response else { break; };
                            if let Some(client) = client {
                                bridge.send_to(&response, client).await.unwrap();
                            }
                        }
                    }
                }
            })
        };

        let target: http::Uri = format!("https://wireguard.test:{}/", bridge_addr.port())
            .parse()
            .unwrap();
        let client = super::super::http3::ReverseH3Upstream::new_with_remote(
            target,
            client_verifier,
            cert_path,
            key_path,
            bridge_addr,
        );
        let request = ProxyRequest::new(
            RequestHead::new(
                http::Method::GET,
                format!(
                    "https://wireguard.test:{}/inside-wireguard",
                    bridge_addr.port()
                )
                .parse()
                .unwrap(),
                http::Version::HTTP_3,
                proxyapi_models::HeaderBlock::new(),
            ),
            ProxyBody::empty(),
        );
        let response = tokio::time::timeout(Duration::from_secs(5), client.send(request))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.head.status, http::StatusCode::CREATED);
        assert_eq!(
            response.head.headers.get("x-wireguard-upstream"),
            Some(b"h3".as_slice())
        );
        assert_eq!(
            response.body.collect().await.unwrap().data,
            "wireguard h3 upstream"
        );
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), event_rx.recv())
                .await
                .unwrap(),
            Some(ProxyEvent::RequestComplete { .. })
        ));

        cancel.cancel();
        bridge_task.abort();
        upstream_task.abort();
        drop(upstream_tls_dir);
    }

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
        getrandom::fill(&mut server_key).unwrap();
        getrandom::fill(&mut client_key).unwrap();
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
        let _ = rustls::crypto::ring::default_provider().install_default();
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
            http::Method::GET,
            "http://example.test/".parse().unwrap(),
            http::Version::HTTP_11,
            proxyapi_models::HeaderBlock::new(),
            bytes::Bytes::new(),
            1,
        );
        let (request_tx, request_rx) = mpsc::channel(1);
        request_tx.send(request).await.unwrap();
        let mut request_rx = Some(request_rx);
        assert_eq!(
            receive_replay(&mut request_rx).await.unwrap().uri().host(),
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
        getrandom::fill(&mut server_key).unwrap();
        getrandom::fill(&mut client_key).unwrap();
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
