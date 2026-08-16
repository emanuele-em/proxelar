//! Forward-proxy MITM machinery shared by the CONNECT, SOCKS5, and WireGuard
//! capture paths.
//!
//! The whole pipeline is built on rama primitives: an HTTP/1+2 auto server, a
//! BoringSSL TLS acceptor fed by the persistent CA, a peek stack (rama's TLS
//! peeker then its HTTP peeker, the latter skipping known non-HTTP protocol
//! openers) that routes each tunnel to TLS-MITM, HTTP-MITM, or a raw byte
//! tunnel, and rama's WebSocket relay-event service so every opcode is tapped
//! for capture while data frames can be transformed.

use rama::telemetry::tracing;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use rama::bytes::Bytes;

use rama::error::{BoxError, ErrorContext};
use rama::extensions::{Extension, ExtensionsRef};
use rama::http::io::upgrade::Upgraded;
use rama::http::layer::remove_header::coalesce_cookie_headers;
use rama::http::layer::upgrade::mitm::HttpUpgradeMitmRelayLayer;
use rama::http::layer::upgrade::{DefaultHttpProxyConnectReplyService, UpgradeLayer};
use rama::http::matcher::MethodMatcher;
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
use rama::io::{BridgeIo, Io};
use rama::layer::{AddInputExtensionLayer, ConsumeErrLayer};
use rama::net::address::{Host, HostWithPort};
use rama::net::client::ConnectorTarget;
use rama::net::http::server::HttpPeekRouter;
use rama::net::AuthorityInputExt;
use rama::net::Protocol;
use rama::rt::Executor;
use rama::service::service_fn;
use rama::tls::boring::server::TlsAcceptorLayer;
use rama::tls::server::TlsPeekRouter;
use rama::{Layer, Service};

use proxyapi_models::{ProxiedResponse, WsDirection, WsFrame, WsOpcode};
use tokio::sync::mpsc;

use crate::ca::{cert_server, Ssl};
use crate::event::ProxyEvent;
use crate::handler::{now_millis, CapturingHandler, RequestOrResponse};

use super::{
    connector::{RawConnection, RawConnector},
    sanitize_response_for_client, UpstreamClient,
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
/// connector to the tunnel target regardless of the inner `Host`.
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
    ca: Arc<Ssl>,
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
        Self {
            handler,
            client,
            ca,
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
            ca: Arc::clone(&self.ca),
            exec: self.exec.clone(),
            listen_addr: self.listen_addr,
        })
    }

    async fn serve_request(&self, req: Request) -> Response {
        let tunnel = req.extensions().get_ref::<TunnelContext>().cloned();

        // A request straight to the listener (or via the proxy to `proxel.ar`)
        // is answered with the certificate install page.
        if tunnel.is_none() && is_direct_cert_request(&req, self.listen_addr) {
            return cert_server::handle(&req, &self.ca.ca_cert_pem(), None);
        }
        if cert_server::is_cert_request(&req) {
            return cert_server::handle(&req, &self.ca.ca_cert_pem(), Some(self.listen_addr));
        }

        let (scheme, authority) = match &tunnel {
            Some(t) => (t.scheme.clone(), Some(t.authority.clone())),
            None => (Protocol::HTTP, None),
        };

        let req = match reconstruct_uri(req, scheme) {
            Ok(req) => req,
            Err(response) => return response,
        };

        let client_version = req.version();
        let mut handler = self.handler.clone();

        // The upgrade-relay layer owns the client/upstream upgrade handshake; we
        // only need to know whether to negotiate the WS version upstream.
        let is_ws = is_http_req_websocket_handshake(&req);

        let req = match handler.handle_request(req).await {
            RequestOrResponse::Request(req) => req,
            RequestOrResponse::Response(mut res) => {
                sanitize_response_for_client(&mut res, client_version);
                return res;
            }
        };

        let upstream_req = prepare_upstream_request(req, is_ws, authority.as_ref());

        let result = if is_ws {
            self.client.serve_upgrade(upstream_req).await
        } else {
            self.client.serve(upstream_req).await
        };

        match result {
            Ok(res) => {
                if is_ws && res.status() == StatusCode::SWITCHING_PROTOCOLS {
                    return finalize_ws_upgrade(res, &mut handler).await;
                }
                let mut res = handler.handle_upstream_response(res).await;
                sanitize_response_for_client(&mut res, client_version);
                res
            }
            Err(err) => {
                tracing::error!("Client request error: {err}");
                let mut res = handler.synthetic_response(
                    StatusCode::BAD_GATEWAY,
                    HeaderMap::new(),
                    Bytes::from_static(b"Bad Gateway"),
                );
                sanitize_response_for_client(&mut res, client_version);
                res
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
    type Error = Infallible;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        Ok(self.cfg.serve_request(req).await)
    }
}

fn mitm_http_service(cfg: Arc<MitmConfig>) -> MitmHttpService {
    MitmHttpService { cfg }
}

/// The MITM HTTP service wrapped in rama's upgrade-relay layer, which owns the
/// two-sided WebSocket handshake (both `handle_upgrade`s, the join, the bridge)
/// and drives our [`WsRelayService`] for the relayed frames. Non-upgrade
/// requests pass straight through to the inner service.
fn mitm_http_service_with_ws(
    cfg: Arc<MitmConfig>,
) -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    let exec = cfg.exec.clone();
    let relay = WsRelayService {
        event_tx: cfg.handler.event_tx_clone(),
        #[cfg(feature = "scripting")]
        script_engine: cfg.handler.script_engine_clone(),
    };
    HttpUpgradeMitmRelayLayer::new(exec, HttpWebSocketRelayServiceRequestMatcher::new(relay))
        .into_layer(mitm_http_service(cfg))
}

/// Build the top-level forward-proxy HTTP service: CONNECT tunnels are hijacked
/// by [`UpgradeLayer`]; everything else (absolute-form forwards + the cert page)
/// is served directly.
pub(crate) fn forward_http_service(
    cfg: Arc<MitmConfig>,
) -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    let exec = cfg.exec.clone();
    let connect_cfg = Arc::clone(&cfg);
    (
        ConsumeErrLayer::default(),
        UpgradeLayer::new(
            exec,
            MethodMatcher::CONNECT,
            DefaultHttpProxyConnectReplyService::new(),
            service_fn(move |upgraded: Upgraded| {
                let cfg = Arc::clone(&connect_cfg);
                async move { on_connect(upgraded, cfg).await }
            }),
        ),
    )
        .into_layer(mitm_http_service_with_ws(cfg))
}

/// CONNECT handler: after the 200 reply, peek the tunneled stream and dispatch
/// to the TLS MITM, plain HTTP, or raw byte tunnel path.
async fn on_connect(upgraded: Upgraded, cfg: Arc<MitmConfig>) -> Result<(), BoxError> {
    let target = upgraded
        .extensions()
        .get_ref::<ConnectorTarget>()
        .map(|t| t.0.clone())
        .context("CONNECT tunnel missing connector target")?;
    serve_mitm_tunnel(upgraded, target, cfg).await
}

/// Inspect an already-established stream whose destination is `target`, peeking
/// the first bytes to route between TLS MITM, plain HTTP, and a raw byte tunnel.
pub(crate) async fn serve_mitm_tunnel<IO>(
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
        let inner = AddInputExtensionLayer::new(TunnelContext {
            scheme: Protocol::HTTPS,
            authority: target.clone(),
        })
        .into_layer(mitm_http_service_with_ws(Arc::clone(&cfg)));
        TlsAcceptorLayer::new(tls_cfg)
            .with_store_client_hello(true)
            .into_layer(HttpServer::auto(exec.clone()).service(inner))
    };

    let http_service = {
        let inner = AddInputExtensionLayer::new(TunnelContext {
            scheme: Protocol::HTTP,
            authority: target.clone(),
        })
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
        .with_fallback(
            HttpPeekRouter::new(http_service)
                .with_known_non_http_protocol_methods()
                .with_peek_timeout(PEEK_TIMEOUT)
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

/// Rebuild the request URI in absolute form so the captured (user-facing)
/// request carries a full `scheme://authority/path` URL rather than a bare
/// origin-form path. Routing itself is pinned by the `ConnectorTarget` extension.
#[allow(clippy::result_large_err)]
fn reconstruct_uri(mut req: Request, scheme: Protocol) -> Result<Request, Response> {
    // The request must still name a host (absolute-form URI, Host header, or
    // terminated-TLS SNI); a host-less request is a 400.
    if req.authority().is_none() {
        return Err(bad_request("Bad Request: missing Host header"));
    }
    // rama's `request_uri` assembles scheme://authority/path from the request
    // context; override the scheme with the tunnel's, since a decrypted (MITM'd)
    // HTTPS request is otherwise indistinguishable from plaintext.
    let mut uri = req.request_uri();
    uri.set_scheme(scheme);
    *req.uri_mut() = uri;
    Ok(req)
}

fn bad_request(message: &'static str) -> Response {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Body::from(Bytes::from_static(message.as_bytes())))
        .unwrap_or_else(|_| StatusCode::BAD_REQUEST.into_response())
}

/// Normalize a captured request for upstream forwarding: sanitize forwarded
/// headers (see [`super::sanitize_forwarded_request_headers`]), drop `Host`, and
/// pin the upstream connector to the tunnel target so a spoofed inner `Host`
/// cannot re-route it. WebSocket upgrades keep `Connection`/`Upgrade` and are
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
        let Ok(()) = WebSocketRelayEventService::new(middleware)
            .serve(BridgeIo(ingress, egress))
            .await;
        let _ = self
            .event_tx
            .try_send(ProxyEvent::WebSocketClosed { conn_id });
        Ok(())
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
        emit_ws_frame(&self.event_tx, self.conn_id, &input.event, direction);

        // Only data frames are transformable; the relay owns control frames.
        #[cfg(feature = "scripting")]
        if let Some(engine) = self.script_engine.clone() {
            if let WebSocketRelayEvent::Data(message) = &input.event {
                let messages = script_data_messages(&engine, direction, message);
                return Ok(WebSocketRelayEventOutput {
                    messages,
                    close: None,
                    extensions: input.extensions,
                });
            }
        }

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
    _remote_addr: std::net::SocketAddr,
    handler: CapturingHandler,
    ca: Arc<Ssl>,
    client: Arc<UpstreamClient>,
    listen_addr: std::net::SocketAddr,
    authority: HostWithPort,
) where
    IO: Io + Unpin + ExtensionsRef,
{
    let cfg = Arc::new(MitmConfig::new(handler, client, ca, listen_addr));
    if let Err(error) = serve_mitm_tunnel(io, authority, cfg).await {
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
