mod connector;
mod dns;
pub(crate) mod forward;
mod outbound;
pub(crate) mod raw;
pub(crate) mod reverse;
mod socks;
mod tls;
mod udp;
mod wireguard;

use rama::telemetry::tracing;
use std::{future::Future, net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};

use rama::error::extra::OpaqueError;
use rama::error::BoxError;
use rama::extensions::ExtensionsRef;
use rama::http::client::EasyHttpWebClient;
use rama::http::conn::TargetHttpVersion;
use rama::http::layer::remove_header::{
    coalesce_cookie_headers, remove_hop_by_hop_request_headers, remove_hop_by_hop_response_headers,
};
use rama::http::server::HttpServer;
use rama::http::{HeaderMap, Request, Response, Version};
use rama::io::peek::PeekTimeoutPolicy as RamaPeekTimeoutPolicy;
use rama::net::address::HostWithPort;
use rama::net::address::ProxyAddress;
use rama::net::client::{ConnectRequest, ConnectorService};
use rama::net::uri::Uri;
use rama::rt::Executor;
use rama::service::BoxService;
use rama::tcp::server::TcpListener;
use rama::tls::boring::proxy::TlsMitmEgressServerAuth;
use rama::Service;

use proxyapi_models::ProxiedRequest;
use tokio::sync::mpsc;

use crate::ca::Ssl;
use crate::error::Error;
use crate::event::ProxyEvent;
use crate::handler::CapturingHandler;
use crate::intercept::InterceptConfig;
#[cfg(feature = "scripting")]
use crate::scripting::ScriptEngine;

use forward::MitmConfig;

pub use dns::DnsConfig;
pub use outbound::UpstreamProxyConfig;
pub use tls::UpstreamTlsConfig;
pub use wireguard::WireGuardConfig;

/// How the upstream HTTP version is chosen when forwarding requests.
///
/// Historically proxelar forced every upstream request to HTTP/1.1, which broke
/// HTTP/2-only origins. The default is now [`Auto`](UpstreamHttpVersion::Auto),
/// preserving the client-negotiated version end-to-end.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum UpstreamHttpVersion {
    /// Preserve the client-negotiated version (h1 stays h1, h2 stays h2).
    #[default]
    Auto,
    /// Always talk HTTP/1.1 upstream.
    Http1,
    /// Always talk HTTP/2 upstream.
    Http2,
}

/// Policy applied when protocol detection times out before reaching a verdict.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PeekTimeoutPolicy {
    /// Continue through the observed raw-tunnel fallback.
    #[default]
    FailOpen,
    /// Close the connection instead of allowing uninspected traffic through.
    FailClosed,
}

impl FromStr for PeekTimeoutPolicy {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "fail-open" | "open" => Ok(Self::FailOpen),
            "fail-closed" | "closed" => Ok(Self::FailClosed),
            _ => Err("expected `fail-open` or `fail-closed`".to_owned()),
        }
    }
}

impl From<PeekTimeoutPolicy> for RamaPeekTimeoutPolicy {
    fn from(value: PeekTimeoutPolicy) -> Self {
        match value {
            PeekTimeoutPolicy::FailOpen => Self::FailOpen,
            PeekTimeoutPolicy::FailClosed => Self::FailClosed,
        }
    }
}

impl FromStr for UpstreamHttpVersion {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" | "preserve" => Ok(Self::Auto),
            "http1" | "http/1.1" | "h1" | "1" => Ok(Self::Http1),
            "http2" | "http/2" | "h2" | "2" => Ok(Self::Http2),
            _ => Err("expected `auto`, `http1`, or `http2`".to_owned()),
        }
    }
}

/// Upstream HTTP(S) client — rama's `EasyHttpWebClient` configured with
/// BoringSSL TLS, optional upstream-proxy chaining, and no connection pool.
/// Built once and shared; the wrapper only applies proxelar's per-request
/// version policy and exposes the same transport to raw tunnel paths.
pub(crate) struct UpstreamClient {
    inner: BoxService<Request, Response, OpaqueError>,
    raw: connector::RawConnector,
    tls_config: rama::tls::client::TlsClientConfig,
    mitm_egress_server_auth: TlsMitmEgressServerAuth,
    exec: Executor,
    version: UpstreamHttpVersion,
}

fn box_client<C>(client: C) -> BoxService<Request, Response, OpaqueError>
where
    C: Service<Request, Output = Response, Error = OpaqueError> + Send + Sync + 'static,
{
    client.boxed()
}

impl UpstreamClient {
    fn build(
        tls_config: rama::tls::client::TlsClientConfig,
        mitm_egress_server_auth: TlsMitmEgressServerAuth,
        proxy: Option<ProxyAddress>,
        version: UpstreamHttpVersion,
        exec: Executor,
    ) -> Result<Self, BoxError> {
        let raw = connector::routed(proxy);
        let inner = Self::build_http_client(
            connector::with_timeout(raw.clone()),
            tls_config.clone(),
            exec.clone(),
            false,
        )?;

        Ok(Self {
            inner,
            raw,
            tls_config,
            mitm_egress_server_auth,
            exec,
            version,
        })
    }

    fn build_http_client(
        raw: connector::TimedRawConnector,
        tls_config: rama::tls::client::TlsClientConfig,
        exec: Executor,
        pooled: bool,
    ) -> Result<BoxService<Request, Response, OpaqueError>, BoxError> {
        let builder = EasyHttpWebClient::connector_builder()
            .with_custom_transport_connector(raw)
            // DNS and proxy routing are already part of the shared raw
            // connector, so the HTTP stack starts directly at TLS.
            .with_dns_connector(())
            .without_tls_proxy_support()
            .without_proxy_support()
            .with_tls_support_using_boringssl(tls_config)
            .with_default_http_connector(exec);
        if pooled {
            Ok(box_client(
                builder.with_default_connection_pool().build_client(),
            ))
        } else {
            // Direct proxy traffic intentionally gets a fresh upstream
            // connection per request. A SOCKS tunnel uses the pooled branch
            // below solely to preserve its already-established 1:1 egress.
            Ok(box_client(builder.without_connection_pool().build_client()))
        }
    }

    pub(crate) fn raw_connector(&self) -> connector::RawConnector {
        self.raw.clone()
    }

    pub(crate) async fn connect_raw(
        &self,
        target: HostWithPort,
    ) -> Result<connector::RawConnection, BoxError> {
        let connection = connector::with_timeout(self.raw.clone())
            .connect(ConnectRequest::new(target))
            .await?;
        Ok(connection.conn)
    }

    pub(crate) fn pinned(&self, connection: connector::RawConnection) -> Result<Self, BoxError> {
        let raw = connector::pinned(connection);
        let inner = Self::build_http_client(
            connector::with_timeout(raw.clone()),
            self.tls_config.clone(),
            self.exec.clone(),
            true,
        )?;
        Ok(Self {
            inner,
            raw,
            tls_config: self.tls_config.clone(),
            mitm_egress_server_auth: self.mitm_egress_server_auth.clone(),
            exec: self.exec.clone(),
            version: self.version,
        })
    }

    pub(crate) fn mitm_egress_server_auth(&self) -> TlsMitmEgressServerAuth {
        self.mitm_egress_server_auth.clone()
    }

    pub(crate) fn version(&self) -> UpstreamHttpVersion {
        self.version
    }

    /// Forward a request upstream, applying the configured version policy.
    pub(crate) async fn serve(&self, req: Request) -> Result<Response, BoxError> {
        match self.version {
            UpstreamHttpVersion::Auto => {
                let version = req.version();
                req.extensions().insert(TargetHttpVersion(version));
            }
            UpstreamHttpVersion::Http1 => {
                req.extensions().insert(TargetHttpVersion(Version::HTTP_11));
            }
            UpstreamHttpVersion::Http2 => {
                req.extensions().insert(TargetHttpVersion(Version::HTTP_2));
            }
        }
        self.inner.serve(req).await.map_err(Into::into)
    }

    /// Forward a WebSocket upgrade request upstream (always HTTP/1.1).
    pub(crate) async fn serve_upgrade(&self, req: Request) -> Result<Response, BoxError> {
        req.extensions().insert(TargetHttpVersion(Version::HTTP_11));
        self.inner.serve(req).await.map_err(Into::into)
    }
}

pub(crate) fn sanitize_response_for_client<B>(res: &mut Response<B>, version: Version) {
    if version == Version::HTTP_2 {
        remove_hop_by_hop_response_headers(res.headers_mut());
    }
}

/// Sanitize a request's headers before it is forwarded upstream: drop per-hop
/// and proxy-only headers and coalesce duplicate `Cookie`s (both via rama's RFC
/// 9110 / 6265 helpers). Shared by the forward and reverse paths so they cannot
/// drift on what reaches the origin.
pub(super) fn sanitize_forwarded_request_headers(headers: &mut HeaderMap) {
    remove_hop_by_hop_request_headers(headers);
    coalesce_cookie_headers(headers);
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
    /// How the upstream HTTP version is negotiated (default: preserve).
    pub upstream_http_version: UpstreamHttpVersion,
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
    peek_timeout_policy: PeekTimeoutPolicy,
}

impl Proxy {
    /// Create a new proxy with the given configuration.
    pub const fn new(config: ProxyConfig) -> Self {
        Self {
            config,
            route_rules: None,
            upstream_proxy: None,
            peek_timeout_policy: PeekTimeoutPolicy::FailOpen,
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

    /// Choose whether an inconclusive protocol peek falls back to raw traffic.
    #[must_use]
    pub fn with_peek_timeout_policy(mut self, policy: PeekTimeoutPolicy) -> Self {
        self.peek_timeout_policy = policy;
        self
    }

    fn build_handler(
        &self,
        #[cfg(feature = "scripting")] script_engine: &Option<Arc<ScriptEngine>>,
    ) -> CapturingHandler {
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
        handler
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

        let exec = Executor::default();
        let tls_config = tls::build_client_tls_config(&self.config.upstream_tls)?;
        let mitm_egress_server_auth =
            tls::build_mitm_egress_server_auth(&self.config.upstream_tls)?;
        let proxy_address = match &self.upstream_proxy {
            Some(config) => Some(config.proxy_address()?),
            None => None,
        };
        let client = Arc::new(UpstreamClient::build(
            tls_config,
            mitm_egress_server_auth,
            proxy_address,
            self.config.upstream_http_version,
            exec.clone(),
        )?);

        let handler = self.build_handler(
            #[cfg(feature = "scripting")]
            &script_engine,
        );
        let replay_rx = self.config.replay_rx;

        if let ProxyMode::WireGuard { config } = &self.config.mode {
            return wireguard::serve(
                self.config.addr,
                config.clone(),
                handler,
                ca,
                client,
                self.peek_timeout_policy,
                self.config.event_tx.clone(),
                replay_rx,
                shutdown,
            )
            .await
            .map_err(Error::Io);
        }

        let listener = TcpListener::bind_address(self.config.addr, exec.clone())
            .await
            .map_err(|error| {
                Error::Other(format!("failed to bind {}: {error}", self.config.addr))
            })?;
        tracing::info!("Proxy listening on {}", self.config.addr);

        let replay_handler = handler.clone();
        let replay_client = Arc::clone(&client);

        tokio::pin!(shutdown);

        macro_rules! run {
            ($service:expr) => {{
                let service = $service;
                tokio::select! {
                    () = listener.serve(service) => {}
                    () = replay_loop(replay_rx, replay_handler, replay_client) => {}
                    () = &mut shutdown => { tracing::info!("Proxy shutting down"); }
                }
            }};
        }

        match &self.config.mode {
            ProxyMode::Forward => {
                let cfg = Arc::new(
                    MitmConfig::new(
                        handler,
                        Arc::clone(&client),
                        Arc::clone(&ca),
                        self.config.addr,
                    )
                    .with_peek_timeout_policy(self.peek_timeout_policy),
                );
                let service =
                    HttpServer::auto(exec.clone()).service(forward::forward_http_service(cfg));
                run!(service);
            }
            ProxyMode::Reverse { target } => {
                let service = HttpServer::auto(exec.clone()).service(
                    reverse::ReverseProxyService::new(handler, Arc::clone(&client), target.clone()),
                );
                run!(service);
            }
            ProxyMode::Socks5 => {
                let cfg = Arc::new(
                    MitmConfig::new(
                        handler,
                        Arc::clone(&client),
                        Arc::clone(&ca),
                        self.config.addr,
                    )
                    .with_peek_timeout_policy(self.peek_timeout_policy),
                );
                let service = socks::acceptor(cfg, exec.clone());
                run!(service);
            }
            ProxyMode::Dns { .. } | ProxyMode::Udp { .. } | ProxyMode::WireGuard { .. } => {
                unreachable!("non-TCP modes are handled above")
            }
        }

        Ok(())
    }
}

/// Drive the replay channel, forwarding each request back through the pipeline.
async fn replay_loop(
    rx: Option<mpsc::Receiver<ProxiedRequest>>,
    handler: CapturingHandler,
    client: Arc<UpstreamClient>,
) {
    let Some(mut rx) = rx else {
        std::future::pending::<()>().await;
        return;
    };
    while let Some(req) = rx.recv().await {
        tokio::spawn(forward::handle_replay(
            req,
            handler.clone(),
            Arc::clone(&client),
        ));
    }
    std::future::pending::<()>().await;
}
