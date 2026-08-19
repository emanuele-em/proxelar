mod dns;
pub(crate) mod forward;
mod http1;
mod http2;
#[cfg(feature = "http3")]
mod http3;
mod outbound;
mod raw;
pub(crate) mod reverse;
mod socks;
mod tls;
mod udp;
mod wireguard;

use std::{error::Error as StdError, future::Future, net::SocketAddr, path::PathBuf, sync::Arc};

use http::Uri;
use proxyapi_models::ProxiedRequest;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::ca::Ssl;
use crate::error::Error;
use crate::event::ProxyEvent;
use crate::handler::CapturingHandler;
use crate::intercept::InterceptConfig;
#[cfg(feature = "scripting")]
use crate::scripting::ScriptEngine;

pub use dns::DnsConfig;
pub use outbound::UpstreamProxyConfig;
pub use tls::UpstreamTlsConfig;
pub use wireguard::WireGuardConfig;

pub(crate) type BoxError = Box<dyn StdError + Send + Sync>;

/// Check if an error is a benign "shutting down" or "connection closed" error.
///
/// Protocol engines can report these when the peer closes during shutdown.
pub(crate) fn is_benign_shutdown_error(e: &dyn std::error::Error) -> bool {
    let msg = e.to_string();
    msg.contains("shutting down") || msg.contains("connection was not closed cleanly")
}

/// Normalize a transport-neutral request for the native HTTP/1 client. The
/// client adds the destination Host field only at serialization time.
pub(crate) fn prepare_upstream_protocol_request(
    req: &mut crate::ProxyRequest,
    preserve_upgrade: bool,
) -> Result<(), proxelar_proto::ProtocolError> {
    if !preserve_upgrade {
        let connection_tokens = req
            .head
            .headers
            .get_all("connection")
            .flat_map(|value| value.split(|byte| *byte == b','))
            .map(trim_header_ows)
            .filter(|token| !token.is_empty())
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        req.head.headers.remove("connection");
        for token in connection_tokens {
            req.head.headers.remove(token);
        }
        for name in [
            b"keep-alive".as_slice(),
            b"proxy-connection".as_slice(),
            b"transfer-encoding".as_slice(),
            b"upgrade".as_slice(),
        ] {
            req.head.headers.remove(name);
        }
    }
    req.head.headers.remove("host");
    req.head.headers.remove("proxy-authorization");
    req.head.headers.remove("te");

    let cookies = req
        .head
        .headers
        .get_all("cookie")
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    if !cookies.is_empty() {
        let joined = bstr::join(b"; ", cookies);
        req.head.headers.set("cookie", joined).map_err(|error| {
            proxelar_proto::ProtocolError::new(
                proxelar_proto::ErrorKind::MalformedMessage,
                error.to_string(),
            )
        })?;
    }
    req.head.version = http::Version::HTTP_11;
    Ok(())
}

fn trim_header_ows(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

/// Configuration for creating a [`Proxy`].
pub struct ProxyConfig {
    /// Address to listen on.
    pub addr: SocketAddr,
    /// Listener and capture mode.
    pub mode: ProxyMode,
    /// Channel for emitting captured proxy events.
    pub event_tx: mpsc::Sender<ProxyEvent>,
    /// Directory for CA certificate and key files.
    pub ca_dir: PathBuf,
    /// Upstream HTTPS server trust policy.
    pub upstream_tls: UpstreamTlsConfig,
    /// Optional intercept controller for interactive request/response editing.
    pub intercept: Option<Arc<InterceptConfig>>,
    /// Maximum body bytes buffered for capture/editing before streaming passthrough.
    ///
    /// `None` means unlimited capture.
    pub body_capture_limit: Option<usize>,
    /// Optional path to a Lua script for request/response hooks.
    #[cfg(feature = "scripting")]
    pub script_path: Option<PathBuf>,
    /// Optional channel for receiving replay requests from the UI.
    pub replay_rx: Option<mpsc::Receiver<ProxiedRequest>>,
}

/// Listener and capture topology used by the proxy.
#[derive(Debug, Clone)]
pub enum ProxyMode {
    /// Forward proxy: clients send CONNECT requests, proxy tunnels and intercepts.
    Forward,
    /// Reverse proxy: all requests are rewritten to the given target URI.
    Reverse {
        /// Target upstream (must include scheme and authority, e.g. `http://localhost:3000`).
        target: Uri,
    },
    /// SOCKS5 listener with HTTP/HTTPS inspection and raw TCP fallback.
    Socks5,
    /// UDP DNS inspection/override mode.
    Dns { config: DnsConfig },
    /// Raw UDP request/response inspection through a fixed target.
    Udp { target: SocketAddr },
    /// Privilege-free WireGuard endpoint with userspace TCP/UDP reconstruction.
    WireGuard { config: WireGuardConfig },
}

/// The proxy server.
pub struct Proxy {
    config: ProxyConfig,
    route_rules: Option<Arc<crate::rules::RouteRules>>,
    upstream_proxy: Option<UpstreamProxyConfig>,
}

impl Proxy {
    /// Create a new proxy with the given configuration.
    pub const fn new(config: ProxyConfig) -> Self {
        Self {
            config,
            route_rules: None,
            upstream_proxy: None,
        }
    }

    /// Attach declarative map-local, map-remote, redirect, mock, and header rules.
    #[must_use]
    pub fn with_route_rules(mut self, rules: Arc<crate::rules::RouteRules>) -> Self {
        self.route_rules = Some(rules);
        self
    }

    /// Chain all upstream requests through an HTTP CONNECT or SOCKS5 proxy.
    #[must_use]
    pub fn with_upstream_proxy(mut self, proxy: UpstreamProxyConfig) -> Self {
        self.upstream_proxy = Some(proxy);
        self
    }

    /// Start the proxy and run until the `shutdown` future resolves.
    pub async fn start(self, shutdown: impl Future<Output = ()>) -> Result<(), Error> {
        if let ProxyMode::Dns { config } = &self.config.mode {
            return dns::serve(
                self.config.addr,
                config.clone(),
                self.config.event_tx.clone(),
                shutdown,
            )
            .await
            .map_err(Error::Io);
        }
        if let ProxyMode::Udp { target } = &self.config.mode {
            return udp::serve(
                self.config.addr,
                *target,
                self.config.event_tx.clone(),
                shutdown,
            )
            .await
            .map_err(Error::Io);
        }
        // Load Lua script engine if a script path was provided.
        #[cfg(feature = "scripting")]
        let script_engine: Option<Arc<ScriptEngine>> = self
            .config
            .script_path
            .as_ref()
            .map(|p| {
                tracing::info!("Loading Lua script: {}", p.display());
                ScriptEngine::new(p).map(Arc::new)
            })
            .transpose()?;

        let ca_dir = self.config.ca_dir.clone();
        let ca =
            Arc::new(tokio::task::spawn_blocking(move || Ssl::load_or_generate(&ca_dir)).await??);

        if self.config.upstream_tls.is_insecure() {
            tracing::warn!(
                "Upstream TLS certificate verification is disabled; traffic is vulnerable to upstream MITM"
            );
        }

        let tls_config = Arc::new(tls::build_client_config(&self.config.upstream_tls)?);
        let outbound = outbound::OutboundConnector::new(self.upstream_proxy.as_ref())?;
        let native_route = self
            .upstream_proxy
            .as_ref()
            .map(|proxy| proxy.destination().to_string());
        let native_pool = Arc::new(http1::new_pool(outbound.clone(), Arc::clone(&tls_config)));
        let mut replay_rx = self.config.replay_rx;

        if let ProxyMode::WireGuard { config } = &self.config.mode {
            let mut handler = CapturingHandler::new(self.config.event_tx.clone())
                .with_body_capture_limit(self.config.body_capture_limit);
            if let Some(ref intercept) = self.config.intercept {
                handler = handler.with_intercept(Arc::clone(intercept));
            }
            if let Some(ref rules) = self.route_rules {
                handler = handler.with_route_rules(Arc::clone(rules));
            }
            #[cfg(feature = "scripting")]
            if let Some(ref engine) = script_engine {
                handler = handler.with_script_engine(Arc::clone(engine));
            }
            return wireguard::serve(
                self.config.addr,
                config.clone(),
                handler,
                ca,
                native_pool,
                native_route,
                self.config.upstream_tls.clone(),
                self.config.event_tx.clone(),
                replay_rx,
                shutdown,
            )
            .await
            .map_err(Error::Io);
        }

        let reverse_scheme = match &self.config.mode {
            ProxyMode::Reverse { target } => target.scheme_str(),
            _ => None,
        };
        let listener_plan = match reverse_scheme {
            Some(scheme) => reverse_listener_plan(scheme)?,
            None => ReverseListenerPlan::tcp_only(),
        };
        #[cfg(feature = "http3")]
        if listener_plan.http3 && self.upstream_proxy.is_some() {
            return Err(Error::Other(
                "reverse HTTP/3 cannot use a TCP-only upstream proxy".to_owned(),
            ));
        }

        let listener = if listener_plan.tcp {
            Some(TcpListener::bind(self.config.addr).await?)
        } else {
            None
        };
        let listen_addr = match listener.as_ref() {
            Some(listener) => {
                let address = listener.local_addr()?;
                tracing::info!("Proxy listening on {address}");
                address
            }
            None => self.config.addr,
        };

        #[cfg(feature = "http3")]
        let mut h3_server = if listener_plan.http3 {
            let ProxyMode::Reverse { target } = &self.config.mode else {
                unreachable!("HTTP/3 listener is reverse-only")
            };
            let mut handler = CapturingHandler::new(self.config.event_tx.clone())
                .with_body_capture_limit(self.config.body_capture_limit);
            if let Some(ref intercept) = self.config.intercept {
                handler = handler.with_intercept(Arc::clone(intercept));
            }
            if let Some(ref rules) = self.route_rules {
                handler = handler.with_route_rules(Arc::clone(rules));
            }
            #[cfg(feature = "scripting")]
            if let Some(ref engine) = script_engine {
                handler = handler.with_script_engine(Arc::clone(engine));
            }
            let address = if listener_plan.tcp {
                listen_addr
            } else {
                self.config.addr
            };
            let server = reverse::ReverseH3Server::bind(
                address,
                target.clone(),
                handler,
                Arc::clone(&ca),
                &self.config.upstream_tls,
            )
            .await?;
            Some(Box::pin(server.serve()) as H3ServerFuture)
        } else {
            None
        };
        #[cfg(not(feature = "http3"))]
        let mut h3_server: Option<()> = None;

        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                result = accept_tcp(listener.as_ref()) => {
                    let (stream, remote_addr) = match result {
                        Ok(conn) => conn,
                        Err(e) => {
                            tracing::warn!("Failed to accept connection: {e}");
                            continue;
                        }
                    };
                    let mut handler = CapturingHandler::new(self.config.event_tx.clone())
                        .with_body_capture_limit(self.config.body_capture_limit);
                    if let Some(ref ic) = self.config.intercept {
                        handler = handler.with_intercept(Arc::clone(ic));
                    }
                    if let Some(ref rules) = self.route_rules {
                        handler = handler.with_route_rules(Arc::clone(rules));
                    }
                    #[cfg(feature = "scripting")]
                    if let Some(ref engine) = script_engine {
                        handler = handler.with_script_engine(Arc::clone(engine));
                    }
                    let ca = Arc::clone(&ca);
                    let outbound = outbound.clone();
                    let upstream_tls = Arc::clone(&tls_config);
                    let native_pool = Arc::clone(&native_pool);
                    let native_route = native_route.clone();

                    match &self.config.mode {
                        ProxyMode::Forward => {
                            tokio::spawn(forward::handle_connection(
                                stream,
                                remote_addr,
                                handler,
                                ca,
                                native_pool,
                                native_route,
                                listen_addr,
                            ));
                        }
                        ProxyMode::Reverse { target } => {
                            let config = reverse::ReverseConnectionConfig::new(
                                target.clone(),
                                ca,
                                native_pool,
                                native_route,
                                outbound,
                                upstream_tls,
                            );
                            tokio::spawn(reverse::handle_connection(
                                stream,
                                remote_addr,
                                handler,
                                config,
                            ));
                        }
                        ProxyMode::Socks5 => {
                            tokio::spawn(socks::handle_connection(
                                stream,
                                remote_addr,
                                handler,
                                ca,
                                outbound,
                                upstream_tls,
                                self.config.addr,
                            ));
                        }
                        ProxyMode::Dns { .. } => unreachable!("DNS mode uses its UDP serve loop"),
                        ProxyMode::Udp { .. } => unreachable!("UDP mode uses its datagram loop"),
                        ProxyMode::WireGuard { .. } => {
                            unreachable!("WireGuard mode uses its UDP serve loop")
                        }
                    }
                }
                result = poll_h3_server(&mut h3_server) => {
                    return result;
                }
                Some(req) = recv_replay(&mut replay_rx) => {
                    let mut handler = CapturingHandler::new(self.config.event_tx.clone())
                        .with_body_capture_limit(self.config.body_capture_limit);
                    if let Some(ref ic) = self.config.intercept {
                        handler = handler.with_intercept(Arc::clone(ic));
                    }
                    if let Some(ref rules) = self.route_rules {
                        handler = handler.with_route_rules(Arc::clone(rules));
                    }
                    #[cfg(feature = "scripting")]
                    if let Some(ref engine) = script_engine {
                        handler = handler.with_script_engine(Arc::clone(engine));
                    }
                    tokio::spawn(forward::handle_replay(
                        req,
                        handler,
                        Arc::clone(&native_pool),
                        native_route.clone(),
                    ));
                }
                () = &mut shutdown => {
                    tracing::info!("Proxy shutting down");
                    break;
                }
            }
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReverseListenerPlan {
    tcp: bool,
    #[cfg(feature = "http3")]
    http3: bool,
}

impl ReverseListenerPlan {
    const fn tcp_only() -> Self {
        Self {
            tcp: true,
            #[cfg(feature = "http3")]
            http3: false,
        }
    }
}

fn reverse_listener_plan(scheme: &str) -> Result<ReverseListenerPlan, Error> {
    match scheme {
        "http" => Ok(ReverseListenerPlan::tcp_only()),
        "https" => Ok(ReverseListenerPlan {
            tcp: true,
            #[cfg(feature = "http3")]
            http3: true,
        }),
        "http3" => {
            #[cfg(feature = "http3")]
            {
                Ok(ReverseListenerPlan {
                    tcp: false,
                    http3: true,
                })
            }
            #[cfg(not(feature = "http3"))]
            {
                Err(Error::Other(
                    "reverse:http3 requires the proxyapi/http3 feature".to_owned(),
                ))
            }
        }
        _ => Err(Error::Other(
            "reverse target scheme must be http, https, or http3".to_owned(),
        )),
    }
}

async fn accept_tcp(listener: Option<&TcpListener>) -> std::io::Result<(TcpStream, SocketAddr)> {
    match listener {
        Some(listener) => listener.accept().await,
        None => std::future::pending().await,
    }
}

#[cfg(feature = "http3")]
type H3ServerFuture = std::pin::Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'static>>;

#[cfg(feature = "http3")]
async fn poll_h3_server(server: &mut Option<H3ServerFuture>) -> Result<(), Error> {
    match server {
        Some(server) => server.await,
        None => std::future::pending().await,
    }
}

#[cfg(not(feature = "http3"))]
async fn poll_h3_server(_server: &mut Option<()>) -> Result<(), Error> {
    std::future::pending().await
}

/// Receive the next replay request, or wait forever when no channel is present.
///
/// Used in the `select!` loop to make the replay arm a no-op when the UI
/// hasn't provided a replay channel.
async fn recv_replay(rx: &mut Option<mpsc::Receiver<ProxiedRequest>>) -> Option<ProxiedRequest> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::DEFAULT_BODY_CAPTURE_LIMIT;
    use bytes::Bytes;
    use http::{Method, Version};
    use std::io;

    #[test]
    fn benign_shutdown_error_detection_matches_expected_messages() {
        let shutting_down = io::Error::other("connection is shutting down");
        let unclean = io::Error::other("connection was not closed cleanly");
        let refused = io::Error::other("connection refused");

        assert!(is_benign_shutdown_error(&shutting_down));
        assert!(is_benign_shutdown_error(&unclean));
        assert!(!is_benign_shutdown_error(&refused));
    }

    #[test]
    fn proxy_new_stores_config() {
        let (event_tx, _event_rx) = mpsc::channel(1);
        let config = ProxyConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            mode: ProxyMode::Reverse {
                target: "http://example.test".parse().unwrap(),
            },
            event_tx,
            ca_dir: PathBuf::from("."),
            upstream_tls: UpstreamTlsConfig::Default,
            intercept: None,
            body_capture_limit: DEFAULT_BODY_CAPTURE_LIMIT,
            #[cfg(feature = "scripting")]
            script_path: None,
            replay_rx: None,
        };

        let proxy = Proxy::new(config);

        assert_eq!(proxy.config.addr.port(), 0);
        assert!(matches!(proxy.config.mode, ProxyMode::Reverse { .. }));
    }

    #[tokio::test]
    async fn recv_replay_reads_from_channel() {
        let (tx, rx) = mpsc::channel(1);
        let req = ProxiedRequest::new(
            Method::GET,
            "http://example.test/replay".parse().unwrap(),
            Version::HTTP_11,
            proxyapi_models::HeaderBlock::new(),
            Bytes::new(),
            1,
        );
        tx.send(req).await.unwrap();
        let mut rx = Some(rx);

        let received = recv_replay(&mut rx).await.unwrap();

        assert_eq!(received.uri().path(), "/replay");
    }

    #[tokio::test]
    async fn recv_replay_without_channel_waits_forever() {
        let mut rx = None;
        let result =
            tokio::time::timeout(std::time::Duration::from_millis(10), recv_replay(&mut rx)).await;

        assert!(result.is_err());
    }

    #[test]
    fn protocol_normalizer_preserves_ordered_header_invariants() {
        let mut headers = proxyapi_models::HeaderBlock::new();
        for (name, value) in [
            ("Host", "wrong-host.test"),
            ("Cookie", "a=1"),
            ("X-Keep", "first"),
            ("cookie", "b=2"),
            ("Connection", "x-remove, keep-alive"),
            ("X-Remove", "yes"),
            ("Keep-Alive", "timeout=5"),
            ("Transfer-Encoding", "chunked"),
            ("Upgrade", "websocket"),
        ] {
            headers.add(name, value).unwrap();
        }
        let mut request = crate::ProxyRequest::new(
            crate::RequestHead::new(
                Method::GET,
                "http://upstream.test/path".parse().unwrap(),
                Version::HTTP_2,
                headers,
            ),
            crate::ProxyBody::empty(),
        );

        prepare_upstream_protocol_request(&mut request, false).unwrap();

        assert_eq!(request.head.version, Version::HTTP_11);
        for removed in [
            "host",
            "connection",
            "x-remove",
            "keep-alive",
            "transfer-encoding",
            "upgrade",
        ] {
            assert!(!request.head.headers.contains_key(removed), "{removed}");
        }
        assert_eq!(
            request.head.headers.get("cookie"),
            Some(b"a=1; b=2".as_slice())
        );
        assert_eq!(
            request.head.headers.get("x-keep"),
            Some(b"first".as_slice())
        );
    }

    #[test]
    fn prepare_upstream_upgrade_request_preserves_upgrade_headers() {
        let mut headers = proxyapi_models::HeaderBlock::new();
        for (name, value) in [
            ("Host", "wrong-host.test"),
            ("Connection", "Upgrade"),
            ("Upgrade", "websocket"),
            ("Proxy-Authorization", "Basic secret"),
        ] {
            headers.add(name, value).unwrap();
        }
        let mut request = crate::ProxyRequest::new(
            crate::RequestHead::new(
                Method::GET,
                "http://upstream.test/ws".parse().unwrap(),
                Version::HTTP_2,
                headers,
            ),
            crate::ProxyBody::empty(),
        );

        prepare_upstream_protocol_request(&mut request, true).unwrap();

        assert_eq!(request.head.version, Version::HTTP_11);
        assert!(!request.head.headers.contains_key("host"));
        assert!(!request.head.headers.contains_key("proxy-authorization"));
        assert_eq!(
            request.head.headers.get("connection"),
            Some(b"Upgrade".as_slice())
        );
        assert_eq!(
            request.head.headers.get("upgrade"),
            Some(b"websocket".as_slice())
        );
    }

    #[test]
    fn reverse_listener_selection_is_scheme_driven() {
        assert!(reverse_listener_plan("http").unwrap().tcp);

        let https = reverse_listener_plan("https").unwrap();
        assert!(https.tcp);
        #[cfg(feature = "http3")]
        assert!(https.http3);

        #[cfg(feature = "http3")]
        {
            let http3 = reverse_listener_plan("http3").unwrap();
            assert!(!http3.tcp);
            assert!(http3.http3);
        }
        #[cfg(not(feature = "http3"))]
        assert!(reverse_listener_plan("http3").is_err());

        assert!(reverse_listener_plan("quic").is_err());
    }
}
