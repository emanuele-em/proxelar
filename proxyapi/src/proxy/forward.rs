//! Forward-proxy MITM machinery shared by the CONNECT, SOCKS5, and WireGuard
//! capture paths.
//!
//! The default pipeline is built on rama's eager connector and TLS/HTTP relay
//! services. Its peek stack routes each established ingress/egress pair to TLS
//! MITM, HTTP MITM, or observed raw forwarding without redialing. Explicit HTTP
//! version forcing retains a terminating adapter because a 1:1 relay cannot
//! translate h1 and h2. Rama's WebSocket relay-event service exposes every
//! opcode for capture while data frames can be transformed.

use rama::telemetry::tracing;
use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use rama::bytes::Bytes;

use rama::error::{BoxError, ErrorContext};
use rama::extensions::{Extension, ExtensionsRef};
use rama::http::headers::{HeaderMapExt as _, Host as HostHeader};
use rama::http::io::upgrade::Upgraded;
use rama::http::layer::remove_header::coalesce_cookie_headers;
use rama::http::layer::upgrade::mitm::HttpUpgradeMitmRelayLayer;
use rama::http::layer::upgrade::{EagerHttpProxyConnector, UpgradeLayer};
use rama::http::matcher::MethodMatcher;
use rama::http::proxy::mitm::HttpMitmRelay;
use rama::http::server::HttpServer;
use rama::http::service::web::response::IntoResponse;
use rama::http::ws::handshake::matcher::{
    is_http_req_websocket_handshake, HttpWebSocketRelayServiceRequestMatcher,
};
use rama::http::ws::handshake::mitm::{
    WebSocketRelayDirection, WebSocketRelayEvent, WebSocketRelayEventInput,
    WebSocketRelayEventOutput, WebSocketRelayEventService, WebSocketRelayMessage,
};
#[cfg(feature = "scripting")]
use rama::http::ws::Utf8Bytes;
use rama::http::{Body, HeaderMap, Request, Response, StatusCode, Version};
use rama::io::{peek::PeekTimeoutPolicy as RamaPeekTimeoutPolicy, BridgeIo, Io};
use rama::layer::{AddInputExtensionLayer, ArcLayer, ConsumeErrLayer};
use rama::net::address::{Authority, Host, HostWithPort};
use rama::net::client::{ConnectRequest, ConnectorService, ConnectorTarget};
use rama::net::http::server::HttpPeekRouter;
use rama::net::Protocol;
use rama::rt::Executor;
use rama::tls::boring::proxy::TlsMitmEgressServerAuth;
use rama::tls::boring::server::TlsAcceptorLayer;
use rama::tls::server::{PeekTlsClientHelloService, TlsPeekRouter};
use rama::{Layer, Service};

use proxyapi_models::{ProxiedResponse, WsDirection, WsFrame, WsOpcode};
use tokio::sync::mpsc;

use crate::ca::{cert_server, Ssl};
use crate::event::ProxyEvent;
use crate::handler::{now_millis, CapturingHandler, RequestOrResponse};

use super::{
    connector::{RawConnection, RawConnector},
    sanitize_response_for_client, PeekTimeoutPolicy, UpstreamClient, UpstreamHttpVersion,
};

/// Maximum payload size captured per WebSocket frame.
const MAX_WS_FRAME_PAYLOAD: Option<usize> = crate::handler::DEFAULT_BODY_CAPTURE_LIMIT;
/// Upper bound on how long each protocol peeker waits for a client to reveal its
/// protocol. A real client sends its opener (request-line, TLS ClientHello, or
/// h2 preface) immediately, and a known non-HTTP opener fails fast to the raw
/// tunnel, so this only fires on a client that begins an HTTP-looking
/// request-line and then stalls (a slowloris-style half-open), bounding the
/// resources it can hold.
const PEEK_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-tunnel context injected into every request served over an intercepted
/// stream, so the MITM service can rebuild absolute URIs and pin the upstream
/// connector to the tunnel target while the request still targets it.
#[derive(Debug, Clone, Extension)]
struct TunnelContext {
    scheme: Protocol,
    authority: HostWithPort,
}

/// Capture flow ID for a WebSocket connection, threaded from the MITM service
/// (which emits `WebSocketConnected`) to the relay service via the upstream
/// response extensions, so per-frame events share the connection's ID.
#[derive(Debug, Clone, Copy, Extension)]
struct WsConnId(u64);

/// Shared configuration for the MITM HTTP service.
#[derive(Clone)]
pub(crate) struct MitmConfig {
    handler: CapturingHandler,
    client: Arc<UpstreamClient>,
    routed_client: Arc<UpstreamClient>,
    ca: Arc<Ssl>,
    egress_server_auth: TlsMitmEgressServerAuth,
    upstream_http_version: UpstreamHttpVersion,
    peek_timeout_policy: RamaPeekTimeoutPolicy,
    exec: Executor,
    listen_addr: std::net::SocketAddr,
}

impl MitmConfig {
    pub(crate) fn new(
        handler: CapturingHandler,
        client: Arc<UpstreamClient>,
        ca: Arc<Ssl>,
        listen_addr: std::net::SocketAddr,
    ) -> Self {
        let egress_server_auth = client.mitm_egress_server_auth();
        let upstream_http_version = client.version();
        Self {
            handler,
            routed_client: Arc::clone(&client),
            client,
            ca,
            egress_server_auth,
            upstream_http_version,
            peek_timeout_policy: RamaPeekTimeoutPolicy::FailOpen,
            exec: Executor::default(),
            listen_addr,
        }
    }

    pub(crate) fn raw_connector(&self) -> RawConnector {
        self.client.raw_connector()
    }

    pub(crate) fn with_pinned_client(&self, connection: RawConnection) -> Result<Self, BoxError> {
        Ok(Self {
            handler: self.handler.clone(),
            client: Arc::new(self.client.pinned(connection)?),
            routed_client: Arc::clone(&self.routed_client),
            ca: Arc::clone(&self.ca),
            egress_server_auth: self.egress_server_auth.clone(),
            upstream_http_version: self.upstream_http_version,
            peek_timeout_policy: self.peek_timeout_policy,
            exec: self.exec.clone(),
            listen_addr: self.listen_addr,
        })
    }

    pub(crate) fn with_peek_timeout_policy(mut self, policy: PeekTimeoutPolicy) -> Self {
        self.peek_timeout_policy = policy.into();
        self
    }

    async fn serve_request(&self, req: Request) -> Result<Response, BoxError> {
        let tunnel = req.extensions().get_ref::<TunnelContext>().cloned();
        self.serve_request_with(req, tunnel, |req, is_ws, uses_tunnel| async move {
            let client = if uses_tunnel {
                &self.client
            } else {
                &self.routed_client
            };
            if is_ws {
                client.serve_upgrade(req).await
            } else {
                client.serve(req).await
            }
        })
        .await
    }

    async fn serve_request_with<F, Fut, E>(
        &self,
        req: Request,
        tunnel: Option<TunnelContext>,
        forward: F,
    ) -> Result<Response, BoxError>
    where
        F: FnOnce(Request, bool, bool) -> Fut,
        Fut: Future<Output = Result<Response, E>>,
        E: Into<BoxError>,
    {
        // A request straight to the listener (or via the proxy to `proxel.ar`)
        // is answered with the certificate install page.
        if tunnel.is_none() && is_direct_cert_request(&req, self.listen_addr) {
            return Ok(cert_server::handle(&req, &self.ca.ca_cert_pem(), None));
        }
        if cert_server::is_cert_request(&req) {
            return Ok(cert_server::handle(
                &req,
                &self.ca.ca_cert_pem(),
                Some(self.listen_addr),
            ));
        }

        let (scheme, authority) = match &tunnel {
            Some(t) => (t.scheme.clone(), Some(t.authority.clone())),
            None => (Protocol::HTTP, None),
        };

        let req = match reconstruct_uri(req, scheme) {
            Ok(req) => req,
            Err(response) => return Ok(response),
        };
        let original_destination = request_destination(&req);

        let client_version = req.version();
        let mut handler = self.handler.clone();

        // The upgrade-relay layer owns the client/upstream upgrade handshake; we
        // only need to know whether to negotiate the WS version upstream.
        let is_ws = is_http_req_websocket_handshake(&req);

        let req = match handler.handle_request(req).await {
            RequestOrResponse::Request(req) => req,
            RequestOrResponse::Response(mut res) => {
                sanitize_response_for_client(&mut res, client_version);
                return Ok(res);
            }
        };

        // Preserve the established egress for an untouched request, including
        // valid SNI != Host/domain-fronting traffic. Only an explicit
        // rules/Lua/intercept destination rewrite selects fresh egress.
        let uses_tunnel = tunnel.is_some() && request_destination(&req) == original_destination;
        let upstream_req = prepare_upstream_request(
            req,
            is_ws,
            uses_tunnel.then_some(authority.as_ref()).flatten(),
        );

        let result = forward(upstream_req, is_ws, uses_tunnel)
            .await
            .map_err(Into::into);

        match result {
            Ok(res) => {
                if is_ws && res.status() == StatusCode::SWITCHING_PROTOCOLS {
                    return Ok(finalize_ws_upgrade(res, &mut handler).await);
                }
                let mut res = handler.handle_upstream_response(res).await;
                sanitize_response_for_client(&mut res, client_version);
                Ok(res)
            }
            Err(err) => {
                if uses_tunnel {
                    return Err(err);
                }
                tracing::error!("Client request error: {err}");
                let mut res = handler.synthetic_response(
                    StatusCode::BAD_GATEWAY,
                    HeaderMap::new(),
                    Bytes::from_static(b"Bad Gateway"),
                );
                sanitize_response_for_client(&mut res, client_version);
                Ok(res)
            }
        }
    }
}

/// The MITM HTTP service: inspects every request going through the proxy and
/// forwards it upstream via the shared client.
#[derive(Clone)]
struct MitmHttpService {
    cfg: Arc<MitmConfig>,
}

impl Service<Request> for MitmHttpService {
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        self.cfg.serve_request(req).await
    }
}

fn mitm_http_service(cfg: Arc<MitmConfig>) -> MitmHttpService {
    MitmHttpService { cfg }
}

/// Per-tunnel HTTP middleware applied to rama's pre-established egress client.
/// Rama owns the HTTP connection state; Proxelar only reconstructs, captures,
/// transforms, and records requests and responses.
#[derive(Clone)]
struct RelayMitmHttpLayer {
    cfg: Arc<MitmConfig>,
    tunnel: TunnelContext,
}

impl<S> Layer<S> for RelayMitmHttpLayer {
    type Service = RelayMitmHttpService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RelayMitmHttpService {
            cfg: Arc::clone(&self.cfg),
            tunnel: self.tunnel.clone(),
            inner,
        }
    }
}

#[derive(Clone)]
struct RelayMitmHttpService<S> {
    cfg: Arc<MitmConfig>,
    tunnel: TunnelContext,
    inner: S,
}

impl<S> Service<Request> for RelayMitmHttpService<S>
where
    S: Service<Request, Output = Response>,
    S::Error: Into<BoxError>,
{
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        let routed_client = Arc::clone(&self.cfg.routed_client);
        self.cfg
            .serve_request_with(
                req,
                Some(self.tunnel.clone()),
                |req, is_ws, uses_tunnel| async move {
                    if uses_tunnel {
                        self.inner.serve(req).await.map_err(Into::into)
                    } else if is_ws {
                        routed_client.serve_upgrade(req).await
                    } else {
                        routed_client.serve(req).await
                    }
                },
            )
            .await
    }
}

fn websocket_mitm_layer(
    cfg: &MitmConfig,
) -> HttpUpgradeMitmRelayLayer<HttpWebSocketRelayServiceRequestMatcher<WsRelayService>> {
    let relay = WsRelayService {
        event_tx: cfg.handler.event_tx_clone(),
        #[cfg(feature = "scripting")]
        script_engine: cfg.handler.script_engine_clone(),
    };
    HttpUpgradeMitmRelayLayer::new(
        cfg.exec.clone(),
        HttpWebSocketRelayServiceRequestMatcher::new(relay),
    )
}

/// The MITM HTTP service wrapped in rama's upgrade-relay layer, which owns the
/// two-sided WebSocket handshake (both `handle_upgrade`s, the join, the bridge)
/// and drives our [`WsRelayService`] for the relayed frames. Non-upgrade
/// requests pass straight through to the inner service.
fn mitm_http_service_with_ws(
    cfg: Arc<MitmConfig>,
) -> impl Service<Request, Output = Response, Error = BoxError> + Clone {
    websocket_mitm_layer(&cfg).into_layer(mitm_http_service(cfg))
}

/// Build the top-level forward-proxy HTTP service: CONNECT tunnels are hijacked
/// by [`UpgradeLayer`]; everything else (absolute-form forwards + the cert page)
/// is served directly.
pub(crate) fn forward_http_service(
    cfg: Arc<MitmConfig>,
) -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    let exec = cfg.exec.clone();
    let connect = EagerHttpProxyConnector::new(
        super::connector::with_timeout(cfg.raw_connector()),
        MitmBridgeService {
            cfg: Arc::clone(&cfg),
        },
    );
    (
        ConsumeErrLayer::default(),
        UpgradeLayer::new(exec, MethodMatcher::CONNECT, connect),
    )
        .into_layer(mitm_http_service_with_ws(cfg))
}

/// Shared eager CONNECT/SOCKS bridge service. The default `auto` policy uses
/// rama's connection-preserving TLS/HTTP relay. Explicit version forcing keeps
/// the terminating adapter because a 1:1 relay cannot translate h1 and h2.
#[derive(Clone)]
pub(crate) struct MitmBridgeService {
    cfg: Arc<MitmConfig>,
}

impl MitmBridgeService {
    pub(crate) fn new(cfg: Arc<MitmConfig>) -> Self {
        Self { cfg }
    }
}

impl<Ingress> Service<BridgeIo<Ingress, RawConnection>> for MitmBridgeService
where
    Ingress: Io + Unpin + ExtensionsRef,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, bridge: BridgeIo<Ingress, RawConnection>) -> Result<(), BoxError> {
        let target = bridge
            .extensions()
            .get_ref::<ConnectorTarget>()
            .map(|target| target.0.clone())
            .context("MITM bridge missing connector target")?;

        if self.cfg.upstream_http_version == UpstreamHttpVersion::Auto {
            serve_relay_tunnel(bridge, target, Arc::clone(&self.cfg)).await
        } else {
            let BridgeIo(ingress, egress) = bridge;
            let cfg = Arc::new(self.cfg.with_pinned_client(egress)?);
            serve_terminating_tunnel(ingress, target, cfg).await
        }
    }
}

/// Relay an already-established ingress/egress pair. TLS fingerprints and the
/// origin certificate are mirrored by rama; HTTP connection state remains 1:1.
async fn serve_relay_tunnel<Ingress>(
    bridge: BridgeIo<Ingress, RawConnection>,
    target: HostWithPort,
    cfg: Arc<MitmConfig>,
) -> Result<(), BoxError>
where
    Ingress: Io + Unpin + ExtensionsRef,
{
    let https_http = HttpMitmRelay::new(cfg.exec.clone()).with_http_middleware((
        websocket_mitm_layer(&cfg),
        RelayMitmHttpLayer {
            cfg: Arc::clone(&cfg),
            tunnel: TunnelContext {
                scheme: Protocol::HTTPS,
                authority: target.clone(),
            },
        },
        ArcLayer::new(),
    ));
    let http = HttpMitmRelay::new(cfg.exec.clone()).with_http_middleware((
        websocket_mitm_layer(&cfg),
        RelayMitmHttpLayer {
            cfg: Arc::clone(&cfg),
            tunnel: TunnelContext {
                scheme: Protocol::HTTP,
                authority: target.clone(),
            },
        },
        ArcLayer::new(),
    ));
    let raw = RawBridgeService {
        target,
        event_tx: cfg.handler.event_tx_clone(),
    };

    let maybe_http = HttpPeekRouter::new(http)
        .with_known_non_http_protocol_methods()
        .with_peek_timeout(PEEK_TIMEOUT)
        .with_peek_timeout_policy(cfg.peek_timeout_policy)
        .with_fallback(raw.clone());
    let maybe_https = HttpPeekRouter::new(https_http)
        .with_known_non_http_protocol_methods()
        .with_peek_timeout(PEEK_TIMEOUT)
        .with_peek_timeout_policy(cfg.peek_timeout_policy)
        .with_fallback(raw);
    let tls = cfg
        .ca
        .tls_mitm_relay(cfg.egress_server_auth.clone())
        .into_layer(maybe_https);
    PeekTlsClientHelloService::new(tls)
        .with_peek_timeout(PEEK_TIMEOUT)
        .with_peek_timeout_policy(cfg.peek_timeout_policy)
        .with_fallback(maybe_http)
        .serve(bridge)
        .await
}

/// Raw fallback for a bridge whose egress was already established eagerly.
#[derive(Clone)]
struct RawBridgeService {
    target: HostWithPort,
    event_tx: mpsc::Sender<ProxyEvent>,
}

impl<Ingress, Egress> Service<BridgeIo<Ingress, Egress>> for RawBridgeService
where
    Ingress: Io + Unpin,
    Egress: Io + Unpin,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(
        &self,
        BridgeIo(ingress, egress): BridgeIo<Ingress, Egress>,
    ) -> Result<(), BoxError> {
        super::raw::tunnel(
            ingress,
            egress,
            self.target.to_string(),
            self.event_tx.clone(),
        )
        .await
        .map_err(Into::into)
    }
}

/// Legacy version-adapting path used only when the operator explicitly forces
/// an upstream HTTP version. The connector is pinned to the eager egress.
async fn serve_terminating_tunnel<IO>(
    io: IO,
    target: HostWithPort,
    cfg: Arc<MitmConfig>,
) -> Result<(), BoxError>
where
    IO: Io + Unpin + ExtensionsRef,
{
    let exec = cfg.exec.clone();

    let https_service = {
        let tls_cfg = cfg.ca.tls_server_config(&target.host);
        let inner = (
            AddInputExtensionLayer::new(TunnelContext {
                scheme: Protocol::HTTPS,
                authority: target.clone(),
            }),
            ConsumeErrLayer::default(),
        )
            .into_layer(mitm_http_service_with_ws(Arc::clone(&cfg)));
        TlsAcceptorLayer::new(tls_cfg)
            .with_store_client_hello(true)
            .into_layer(HttpServer::auto(exec.clone()).service(inner))
    };

    let http_service = {
        let inner = (
            AddInputExtensionLayer::new(TunnelContext {
                scheme: Protocol::HTTP,
                authority: target.clone(),
            }),
            ConsumeErrLayer::default(),
        )
            .into_layer(mitm_http_service_with_ws(Arc::clone(&cfg)));
        HttpServer::auto(exec.clone()).service(inner)
    };

    let raw_service = RawTunnelService {
        target: target.clone(),
        client: Arc::clone(&cfg.client),
        event_tx: cfg.handler.event_tx_clone(),
    };

    // Peek stack: rama's TLS peeker (0x16 record header) routes to TLS-MITM,
    // else rama's HTTP peeker routes h1/h2 to HTTP-MITM. The HTTP peeker skips
    // known non-HTTP protocol openers (PING, SMTP/IRC/SSH/PROXY, …) straight to
    // the raw tunnel without waiting, and the raw tunnel is also its fallback
    // for anything else non-HTTP. The peek timeout bounds a client that begins
    // an HTTP-looking request-line and then stalls.
    let router = TlsPeekRouter::new(https_service)
        .with_peek_timeout(PEEK_TIMEOUT)
        .with_peek_timeout_policy(cfg.peek_timeout_policy)
        .with_fallback(
            HttpPeekRouter::new(http_service)
                .with_known_non_http_protocol_methods()
                .with_peek_timeout(PEEK_TIMEOUT)
                .with_peek_timeout_policy(cfg.peek_timeout_policy)
                .with_fallback(raw_service),
        );

    router.serve(io).await
}

/// Raw byte-tunnel fallback for unknown protocols. Dials the target and relays
/// bytes bidirectionally, emitting `TcpConnected`/`TcpData`/`TcpClosed` events.
#[derive(Clone)]
struct RawTunnelService {
    target: HostWithPort,
    client: Arc<UpstreamClient>,
    event_tx: mpsc::Sender<ProxyEvent>,
}

impl<IO> Service<IO> for RawTunnelService
where
    IO: Io + Unpin,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, mut io: IO) -> Result<Self::Output, Self::Error> {
        let target = self.target.to_string();
        let mut upstream = self
            .client
            .connect_raw(self.target.clone())
            .await
            .with_context(|| format!("connect raw tunnel to {target}"))?;
        super::raw::tunnel(&mut io, &mut upstream, target, self.event_tx.clone())
            .await
            .map_err(Into::into)
    }
}

/// True when the request targets the listener itself (used to serve the cert
/// install page for direct browser visits).
fn is_direct_cert_request<B>(request: &Request<B>, listen_addr: std::net::SocketAddr) -> bool {
    // Only origin-form requests to the listener qualify; an absolute URI means a
    // normal forward request.
    if request.uri().host().is_some() {
        return false;
    }
    let Some(host) = request
        .headers()
        .get(rama::http::header::HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return true;
    };
    let Ok(authority) = HostWithPort::try_from(host) else {
        // Host without an explicit port: compare host only.
        return match Host::try_from(host) {
            Ok(h) => host_matches_listener(&h, listen_addr, 80),
            Err(_) => false,
        };
    };
    host_matches_listener(&authority.host, listen_addr, authority.port)
}

fn host_matches_listener(host: &Host, listen_addr: std::net::SocketAddr, port: u16) -> bool {
    if port != listen_addr.port() {
        return false;
    }
    match host {
        Host::Name(domain) if domain.as_str().eq_ignore_ascii_case("localhost") => {
            listen_addr.ip().is_loopback() || listen_addr.ip().is_unspecified()
        }
        Host::Address(ip) => {
            *ip == listen_addr.ip() || (listen_addr.ip().is_unspecified() && ip.is_loopback())
        }
        _ => false,
    }
}

/// Rebuild an origin-form request URI without replacing explicit request-target
/// components. HTTP authority takes precedence over TLS SNI/CONNECT metadata;
/// the latter only supplies the scheme when the inner request has none.
#[allow(clippy::result_large_err)]
fn reconstruct_uri(mut req: Request, scheme: Protocol) -> Result<Request, Response> {
    let mut uri = req.uri().clone();
    if uri.scheme().is_none() {
        uri.set_scheme(scheme);
    }
    if uri.authority().is_none() {
        let Some(host) = req.headers().typed_get::<HostHeader>() else {
            return Err(bad_request("Bad Request: missing Host header"));
        };
        uri.set_authority(Authority::new(host.0));
    }
    *req.uri_mut() = uri;
    Ok(req)
}

/// Typed scheme and authority used to detect an explicit destination rewrite.
fn request_destination(req: &Request) -> Option<(Protocol, HostWithPort)> {
    let uri = req.uri();
    let scheme = uri.scheme()?.clone();
    let authority = uri.authority()?;
    let port = authority.port_u16().or_else(|| scheme.default_port())?;
    Some((
        scheme,
        HostWithPort::new(authority.host().into_owned(), port),
    ))
}

fn bad_request(message: &'static str) -> Response {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Body::from(Bytes::from_static(message.as_bytes())))
        .unwrap_or_else(|_| StatusCode::BAD_REQUEST.into_response())
}

/// Normalize a captured request for upstream forwarding: sanitize forwarded
/// headers (see [`super::sanitize_forwarded_request_headers`]), drop `Host`, and
/// retain the eager tunnel target only when request processing did not rewrite
/// the destination. WebSocket upgrades keep `Connection`/`Upgrade` and are
/// forced to HTTP/1.1.
fn prepare_upstream_request(
    mut req: Request,
    is_ws: bool,
    tunnel_authority: Option<&HostWithPort>,
) -> Request {
    if is_ws {
        // Upgrade handshakes intentionally keep `Connection`/`Upgrade`.
        req.headers_mut().remove(rama::http::header::HOST);
        req.headers_mut()
            .remove(rama::http::header::PROXY_AUTHORIZATION);
        coalesce_cookie_headers(req.headers_mut());
        // WebSocket upgrades only speak HTTP/1.1.
        *req.version_mut() = Version::HTTP_11;
    } else {
        super::sanitize_forwarded_request_headers(req.headers_mut());
        req.headers_mut().remove(rama::http::header::HOST);
    }

    if let Some(authority) = tunnel_authority {
        req.extensions().insert(ConnectorTarget(authority.clone()));
    }

    req
}

/// Finalize a MITM'd WebSocket 101: emit `WebSocketConnected` from the captured
/// request and stamp the flow ID onto the response so [`WsRelayService`] (driven
/// by rama's upgrade-relay layer) can tag per-frame events. The response is
/// returned whole — its `on_upgrade` extension is what the layer relays.
async fn finalize_ws_upgrade(res: Response, handler: &mut CapturingHandler) -> Response {
    let conn_id = handler
        .take_pending_id()
        .unwrap_or_else(crate::event::next_id);
    let ws_response = ProxiedResponse::new(
        res.status(),
        res.version(),
        res.headers().clone(),
        Bytes::new(),
        now_millis(),
    );
    if let Some(captured_req) = handler.take_captured_request().await {
        handler.send_event(ProxyEvent::WebSocketConnected {
            id: conn_id,
            request: Box::new(captured_req),
            response: Box::new(ws_response),
        });
    }
    res.extensions().insert(WsConnId(conn_id));
    res
}

/// Relay service handed to rama's upgrade-relay layer. Once the layer has
/// upgraded both sides it invokes this over the bridged streams; rama owns the
/// masking, roles and control-frame handling (auto-pong, coordinated close). We
/// read the flow ID stamped on the upstream response (grafted onto the egress
/// stream by the layer), drive [`WsCaptureMiddleware`] for the relayed frames,
/// and emit `WebSocketClosed` when the relay ends.
#[derive(Clone)]
struct WsRelayService {
    event_tx: mpsc::Sender<ProxyEvent>,
    #[cfg(feature = "scripting")]
    script_engine: Option<Arc<crate::scripting::ScriptEngine>>,
}

impl Service<BridgeIo<Upgraded, Upgraded>> for WsRelayService {
    type Output = ();
    type Error = BoxError;

    async fn serve(
        &self,
        BridgeIo(ingress, egress): BridgeIo<Upgraded, Upgraded>,
    ) -> Result<Self::Output, Self::Error> {
        let conn_id = egress
            .extensions()
            .get_ref::<WsConnId>()
            .map_or_else(crate::event::next_id, |c| c.0);
        let middleware = WsCaptureMiddleware {
            conn_id,
            event_tx: self.event_tx.clone(),
            #[cfg(feature = "scripting")]
            script_engine: self.script_engine.clone(),
        };
        let result = WebSocketRelayEventService::new(middleware)
            .serve(BridgeIo(ingress, egress))
            .await;
        let _ = self
            .event_tx
            .try_send(ProxyEvent::WebSocketClosed { conn_id });
        result.map_err(Into::into)
    }
}

/// Relay middleware that captures every WebSocket frame (both directions, all
/// opcodes) and, for data frames, applies the optional Lua transform. Control
/// frames are only observed — the relay owns their handling.
struct WsCaptureMiddleware {
    conn_id: u64,
    event_tx: mpsc::Sender<ProxyEvent>,
    #[cfg(feature = "scripting")]
    script_engine: Option<Arc<crate::scripting::ScriptEngine>>,
}

impl Service<WebSocketRelayEventInput> for WsCaptureMiddleware {
    type Output = WebSocketRelayEventOutput;
    type Error = Infallible;

    async fn serve(&self, input: WebSocketRelayEventInput) -> Result<Self::Output, Self::Error> {
        let direction = match input.direction {
            WebSocketRelayDirection::Ingress => WsDirection::ClientToServer,
            WebSocketRelayDirection::Egress => WsDirection::ServerToClient,
        };
        // Only data frames are transformable; the relay owns control frames.
        #[cfg(feature = "scripting")]
        if let Some(engine) = self.script_engine.clone() {
            if let WebSocketRelayEvent::Data(message) = &input.event {
                let messages = script_data_messages(&engine, direction, message);
                for message in &messages {
                    emit_ws_frame(
                        &self.event_tx,
                        self.conn_id,
                        &WebSocketRelayEvent::Data(message.clone()),
                        direction,
                    );
                }
                return Ok(WebSocketRelayEventOutput {
                    messages,
                    close: None,
                    extensions: input.extensions,
                });
            }
        }

        emit_ws_frame(&self.event_tx, self.conn_id, &input.event, direction);
        Ok(input.into())
    }
}

/// Run the Lua `on_websocket_frame` hook for a data frame, returning the
/// messages to forward (empty = drop, one = pass-through or replacement).
#[cfg(feature = "scripting")]
fn script_data_messages(
    engine: &crate::scripting::ScriptEngine,
    direction: WsDirection,
    message: &WebSocketRelayMessage,
) -> Vec<WebSocketRelayMessage> {
    let direction_name = match direction {
        WsDirection::ClientToServer => "client_to_server",
        WsDirection::ServerToClient => "server_to_client",
    };
    let (opcode, payload): (&str, &[u8]) = match message {
        WebSocketRelayMessage::Text(text) => ("text", text.as_bytes()),
        WebSocketRelayMessage::Binary(bytes) => ("binary", bytes.as_ref()),
    };
    match engine.on_websocket_frame(direction_name, opcode, payload) {
        Ok(crate::scripting::ScriptWebSocketAction::PassThrough) => vec![message.clone()],
        Ok(crate::scripting::ScriptWebSocketAction::Drop) => Vec::new(),
        Ok(crate::scripting::ScriptWebSocketAction::Forward(payload)) => match message {
            WebSocketRelayMessage::Text(_) => match Utf8Bytes::try_from(payload) {
                Ok(text) => vec![WebSocketRelayMessage::Text(text)],
                Err(error) => {
                    tracing::warn!("Lua WebSocket text replacement was not UTF-8: {error}");
                    Vec::new()
                }
            },
            WebSocketRelayMessage::Binary(_) => vec![WebSocketRelayMessage::Binary(payload)],
        },
        Err(error) => {
            tracing::warn!("Lua on_websocket_frame error (passing through): {error}");
            vec![message.clone()]
        }
    }
}

/// Emit a [`WsFrame`] capture event for one relayed frame.
fn emit_ws_frame(
    tx: &mpsc::Sender<ProxyEvent>,
    conn_id: u64,
    event: &WebSocketRelayEvent,
    direction: WsDirection,
) {
    let time = now_millis();
    let (opcode, raw): (WsOpcode, &[u8]) = match event {
        WebSocketRelayEvent::Data(WebSocketRelayMessage::Text(s)) => (WsOpcode::Text, s.as_bytes()),
        WebSocketRelayEvent::Data(WebSocketRelayMessage::Binary(b)) => {
            (WsOpcode::Binary, b.as_ref())
        }
        WebSocketRelayEvent::Ping(b) => (WsOpcode::Ping, b.as_ref()),
        WebSocketRelayEvent::Pong(b) => (WsOpcode::Pong, b.as_ref()),
        WebSocketRelayEvent::Close(_) => (WsOpcode::Close, b""),
    };
    let limit = MAX_WS_FRAME_PAYLOAD.unwrap_or(raw.len());
    let truncated = raw.len() > limit;
    let payload = Bytes::copy_from_slice(&raw[..raw.len().min(limit)]);
    let _ = tx.try_send(ProxyEvent::WebSocketFrame {
        conn_id,
        frame: Box::new(WsFrame::new(direction, opcode, time, payload, truncated)),
    });
}

/// Inspect an already-established stream whose original destination is known
/// (WireGuard userspace-capture entry point).
pub(super) async fn handle_captured_stream<IO>(
    io: IO,
    handler: CapturingHandler,
    ca: Arc<Ssl>,
    client: Arc<UpstreamClient>,
    listen_addr: std::net::SocketAddr,
    authority: HostWithPort,
    peek_timeout_policy: PeekTimeoutPolicy,
) where
    IO: Io + Unpin + ExtensionsRef,
{
    let cfg = Arc::new(
        MitmConfig::new(handler, client, ca, listen_addr)
            .with_peek_timeout_policy(peek_timeout_policy),
    );
    io.extensions().insert(ConnectorTarget(authority.clone()));
    let connector = super::connector::with_timeout(cfg.raw_connector());
    let established = connector
        .connect(ConnectRequest::new_with_extensions(
            authority,
            io.extensions().fork(),
        ))
        .await;
    let result = match established {
        Ok(established) => {
            MitmBridgeService::new(cfg)
                .serve(BridgeIo(io, established.conn))
                .await
        }
        Err(error) => Err(error.into()),
    };
    if let Err(error) = result {
        tracing::debug!("Captured stream failed: {error}");
    }
}

/// Send a previously captured request back through the proxy pipeline.
pub(crate) async fn handle_replay(
    req: proxyapi_models::ProxiedRequest,
    mut handler: CapturingHandler,
    client: Arc<UpstreamClient>,
) {
    let Some(fwd_req) = handler.handle_replayed_request(req).await else {
        return;
    };
    let fwd_req = prepare_upstream_request(fwd_req, false, None);
    match client.serve(fwd_req).await {
        Ok(res) => {
            handler.record_upstream_response(res).await;
        }
        Err(err) => {
            tracing::warn!("Replay request failed: {err}");
            handler.emit_synthetic_completion(
                StatusCode::BAD_GATEWAY,
                HeaderMap::new(),
                Bytes::from(format!("Replay request failed: {err}")),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_https_uri_is_not_downgraded() {
        let request = Request::builder()
            .uri("https://secure.example/path")
            .header(rama::http::header::HOST, "wrong.example")
            .body(Body::empty())
            .unwrap();

        let request = reconstruct_uri(request, Protocol::HTTP).unwrap();
        assert_eq!(request.uri().to_string(), "https://secure.example/path");
    }

    #[test]
    fn host_header_is_preserved_without_forcing_new_egress() {
        let request = Request::builder()
            .uri("/fronted")
            .header(rama::http::header::HOST, "virtual.example")
            .body(Body::empty())
            .unwrap();
        let request = reconstruct_uri(request, Protocol::HTTPS).unwrap();
        assert_eq!(request.uri().to_string(), "https://virtual.example/fronted");
        let original = request_destination(&request);
        assert_eq!(request_destination(&request), original);

        let mut rewritten = request;
        rewritten
            .uri_mut()
            .set_authority(Authority::try_from("rewritten.example").unwrap());
        assert_ne!(request_destination(&rewritten), original);
    }

    #[cfg(feature = "scripting")]
    #[tokio::test]
    async fn websocket_capture_records_lua_output_and_omits_drops() {
        use std::io::Write as _;

        use rama::extensions::Extensions;

        let mut script = tempfile::NamedTempFile::new().unwrap();
        script
            .write_all(
                br#"
                function on_websocket_frame(frame)
                    if frame.payload == "drop" then return false end
                    return "changed"
                end
                "#,
            )
            .unwrap();
        script.flush().unwrap();
        let engine = Arc::new(crate::scripting::ScriptEngine::new(script.path()).unwrap());
        let (event_tx, mut event_rx) = mpsc::channel(4);
        let middleware = WsCaptureMiddleware {
            conn_id: 7,
            event_tx,
            script_engine: Some(engine),
        };

        let output = middleware
            .serve(WebSocketRelayEventInput {
                direction: WebSocketRelayDirection::Ingress,
                event: WebSocketRelayEvent::Data(WebSocketRelayMessage::Text(
                    Utf8Bytes::from_static("original"),
                )),
                extensions: Extensions::new(),
            })
            .await
            .unwrap();
        assert_eq!(
            output.messages,
            [WebSocketRelayMessage::Text(Utf8Bytes::from_static(
                "changed"
            ))]
        );
        let ProxyEvent::WebSocketFrame { frame, .. } = event_rx.recv().await.unwrap() else {
            panic!("expected WebSocket frame");
        };
        assert_eq!(frame.payload.as_ref(), b"changed");

        let output = middleware
            .serve(WebSocketRelayEventInput {
                direction: WebSocketRelayDirection::Ingress,
                event: WebSocketRelayEvent::Data(WebSocketRelayMessage::Text(
                    Utf8Bytes::from_static("drop"),
                )),
                extensions: Extensions::new(),
            })
            .await
            .unwrap();
        assert!(output.messages.is_empty());
        assert!(event_rx.try_recv().is_err());

        let output = middleware
            .serve(WebSocketRelayEventInput {
                direction: WebSocketRelayDirection::Egress,
                event: WebSocketRelayEvent::Ping(Bytes::from_static(b"ping")),
                extensions: Extensions::new(),
            })
            .await
            .unwrap();
        assert!(output.messages.is_empty());
        let ProxyEvent::WebSocketFrame { frame, .. } = event_rx.recv().await.unwrap() else {
            panic!("expected captured control frame");
        };
        assert_eq!(frame.opcode, WsOpcode::Ping);
        assert_eq!(frame.payload.as_ref(), b"ping");
    }
}
