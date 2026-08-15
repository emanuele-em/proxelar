//! Forward-proxy MITM machinery shared by the CONNECT, SOCKS5, and WireGuard
//! capture paths.
//!
//! The whole pipeline is built on rama primitives: an HTTP/1+2 auto server, a
//! BoringSSL TLS acceptor fed by the persistent CA, a peek stack (rama's TLS
//! peeker then its HTTP peeker, the latter skipping known non-HTTP protocol
//! openers) that routes each tunnel to TLS-MITM, HTTP-MITM, or a raw byte
//! tunnel, and a forked WebSocket relay loop so every opcode — not just
//! Text/Binary — is tapped and can be transformed.

use rama::telemetry::tracing;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use rama::bytes::Bytes;

use rama::error::{BoxError, ErrorContext};
use rama::extensions::{Extension, ExtensionsRef};
use rama::http::io::upgrade::{handle_upgrade, Upgraded};
use rama::http::layer::remove_header::coalesce_cookie_headers;
use rama::http::layer::upgrade::{DefaultHttpProxyConnectReplyService, UpgradeLayer};
use rama::http::matcher::MethodMatcher;
use rama::http::server::HttpServer;
use rama::http::service::web::response::IntoResponse;
use rama::http::ws::handshake::matcher::is_http_req_websocket_handshake;
use rama::http::ws::protocol::Role;
use rama::http::ws::{AsyncWebSocket, Message, ProtocolError};
use rama::http::{Body, HeaderMap, Request, Response, StatusCode, Version};
use rama::io::Io;
use rama::layer::{AddInputExtensionLayer, ConsumeErrLayer};
use rama::net::address::{Host, HostWithPort};
use rama::net::client::ConnectorTarget;
use rama::net::http::server::HttpPeekRouter;
use rama::net::uri::Uri;
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

use super::{sanitize_response_for_client, UpstreamClient};

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

        let req = match reconstruct_uri(req, scheme, authority.as_ref()) {
            Ok(req) => req,
            Err(response) => return response,
        };

        let client_version = req.version();
        let mut handler = self.handler.clone();

        // Capture the client-side upgrade future before `handle_request` consumes
        // and rebuilds the request.
        let is_ws = is_http_req_websocket_handshake(&req);
        let ingress_upgrade = if is_ws {
            Some(handle_upgrade(&req))
        } else {
            None
        };

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
                    return upgrade_websocket_response(res, handler, ingress_upgrade).await;
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
        .into_layer(mitm_http_service(cfg))
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
        .into_layer(mitm_http_service(Arc::clone(&cfg)));
        TlsAcceptorLayer::new(tls_cfg)
            .with_store_client_hello(true)
            .into_layer(HttpServer::auto(exec.clone()).service(inner))
    };

    let http_service = {
        let inner = AddInputExtensionLayer::new(TunnelContext {
            scheme: Protocol::HTTP,
            authority: target.clone(),
        })
        .into_layer(mitm_http_service(Arc::clone(&cfg)));
        HttpServer::auto(exec.clone()).service(inner)
    };

    let raw_service = RawTunnelService {
        target: target.clone(),
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
        let mut upstream = tokio::net::TcpStream::connect(&target)
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

/// Rebuild the request URI in absolute form for upstream forwarding.
#[allow(clippy::result_large_err)]
fn reconstruct_uri(
    mut req: Request,
    scheme: Protocol,
    authority: Option<&HostWithPort>,
) -> Result<Request, Response> {
    let host_with_port = match authority {
        Some(authority) => {
            // Inside a CONNECT/SOCKS tunnel the inner request must still identify
            // its host (absolute-form URI or a Host header); a Host-less request
            // is a 400 rather than being silently routed to the tunnel target.
            if req.uri().authority().is_none() && host_header_authority(&req).is_none() {
                return Err(bad_request("Bad Request: missing Host header"));
            }
            authority.clone()
        }
        None => {
            if req.uri().authority().is_some() {
                // Already an absolute-form forward request.
                return Ok(req);
            }
            match host_header_authority(&req) {
                Some(authority) => authority,
                None => return Err(bad_request("Bad Request: missing Host header")),
            }
        }
    };

    let scheme_str = if scheme == Protocol::HTTPS {
        "https"
    } else {
        "http"
    };
    let target = if req.uri().query_or_empty().is_empty() {
        format!(
            "{scheme_str}://{host_with_port}{}",
            req.uri().path_or_root()
        )
    } else {
        format!(
            "{scheme_str}://{host_with_port}{}?{}",
            req.uri().path_or_root(),
            req.uri().query_or_empty()
        )
    };

    match Uri::parse(target) {
        Ok(uri) => {
            *req.uri_mut() = uri;
            Ok(req)
        }
        Err(error) => {
            tracing::warn!("Failed to rebuild tunnel URI: {error}");
            Err(bad_request("Bad Request: invalid URI"))
        }
    }
}

fn host_header_authority<B>(req: &Request<B>) -> Option<HostWithPort> {
    let host = req
        .headers()
        .get(rama::http::header::HOST)
        .and_then(|value| value.to_str().ok())?;
    if let Ok(authority) = HostWithPort::try_from(host) {
        return Some(authority);
    }
    Host::try_from(host)
        .ok()
        .map(|host| HostWithPort { host, port: 80 })
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

/// Turn a 101 upstream response into a MITM WebSocket relay.
async fn upgrade_websocket_response(
    res: Response,
    mut handler: CapturingHandler,
    ingress_upgrade: Option<
        impl std::future::Future<Output = Result<Upgraded, BoxError>> + Send + 'static,
    >,
) -> Response {
    let egress_upgrade = handle_upgrade(&res);
    let (parts, _body) = res.into_parts();

    let ws_response = ProxiedResponse::new(
        parts.status,
        parts.version,
        parts.headers.clone(),
        Bytes::new(),
        now_millis(),
    );

    let conn_id = handler
        .take_pending_id()
        .unwrap_or_else(crate::event::next_id);
    if let Some(captured_req) = handler.take_captured_request().await {
        handler.send_event(ProxyEvent::WebSocketConnected {
            id: conn_id,
            request: Box::new(captured_req),
            response: Box::new(ws_response),
        });
    }

    if let Some(ingress_upgrade) = ingress_upgrade {
        let event_tx = handler.event_tx_clone();
        #[cfg(feature = "scripting")]
        let script_engine = handler.script_engine_clone();
        tokio::spawn(async move {
            pump_websocket_frames(
                conn_id,
                ingress_upgrade,
                egress_upgrade,
                event_tx,
                #[cfg(feature = "scripting")]
                script_engine,
            )
            .await;
        });
    }

    Response::from_parts(parts, Body::empty())
}

/// Await both upgrade futures, wrap the streams in rama WebSockets (proxy is
/// `Role::Server` toward the client and `Role::Client` toward upstream), then
/// relay every frame — including control frames — while tapping and optionally
/// transforming each one.
async fn pump_websocket_frames<Fi, Fe>(
    conn_id: u64,
    ingress_upgrade: Fi,
    egress_upgrade: Fe,
    event_tx: mpsc::Sender<ProxyEvent>,
    #[cfg(feature = "scripting")] script_engine: Option<Arc<crate::scripting::ScriptEngine>>,
) where
    Fi: std::future::Future<Output = Result<Upgraded, BoxError>>,
    Fe: std::future::Future<Output = Result<Upgraded, BoxError>>,
{
    let (ingress, egress) = match tokio::try_join!(ingress_upgrade, egress_upgrade) {
        Ok(pair) => pair,
        Err(err) => {
            tracing::warn!("WebSocket upgrade failed for conn_id={conn_id}: {err}");
            return;
        }
    };

    let mut client_ws = AsyncWebSocket::from_raw_socket(ingress, Role::Server, None).await;
    let mut server_ws = AsyncWebSocket::from_raw_socket(egress, Role::Client, None).await;

    loop {
        tokio::select! {
            msg = client_ws.recv_message() => match msg {
                Ok(frame) => {
                    #[cfg(feature = "scripting")]
                    let Some(frame) = transform_ws_frame(frame, WsDirection::ClientToServer, script_engine.as_deref()) else { continue; };
                    emit_ws_frame(&event_tx, conn_id, &frame, WsDirection::ClientToServer);
                    if server_ws.send_message(frame).await.is_err() { break; }
                }
                Err(err) => { log_ws_close("client", conn_id, &err); break; }
            },
            msg = server_ws.recv_message() => match msg {
                Ok(frame) => {
                    #[cfg(feature = "scripting")]
                    let Some(frame) = transform_ws_frame(frame, WsDirection::ServerToClient, script_engine.as_deref()) else { continue; };
                    emit_ws_frame(&event_tx, conn_id, &frame, WsDirection::ServerToClient);
                    if client_ws.send_message(frame).await.is_err() { break; }
                }
                Err(err) => { log_ws_close("server", conn_id, &err); break; }
            },
        }
    }

    let _ = event_tx.try_send(ProxyEvent::WebSocketClosed { conn_id });
}

fn log_ws_close(side: &str, conn_id: u64, err: &ProtocolError) {
    if err.is_connection_error() || matches!(err, ProtocolError::ResetWithoutClosingHandshake) {
        tracing::debug!("WS {side} disconnected conn_id={conn_id}: {err}");
    } else {
        tracing::debug!("WS {side} error conn_id={conn_id}: {err}");
    }
}

#[cfg(feature = "scripting")]
fn transform_ws_frame(
    frame: Message,
    direction: WsDirection,
    engine: Option<&crate::scripting::ScriptEngine>,
) -> Option<Message> {
    let Some(engine) = engine else {
        return Some(frame);
    };
    let direction_name = match direction {
        WsDirection::ClientToServer => "client_to_server",
        WsDirection::ServerToClient => "server_to_client",
    };
    let (opcode, payload): (&str, &[u8]) = match &frame {
        Message::Text(payload) => ("text", payload.as_bytes()),
        Message::Binary(payload) => ("binary", payload.as_ref()),
        Message::Ping(payload) => ("ping", payload.as_ref()),
        Message::Pong(payload) => ("pong", payload.as_ref()),
        Message::Close(_) | Message::Frame(_) => return Some(frame),
    };
    match engine.on_websocket_frame(direction_name, opcode, payload) {
        Ok(crate::scripting::ScriptWebSocketAction::PassThrough) => Some(frame),
        Ok(crate::scripting::ScriptWebSocketAction::Drop) => None,
        Ok(crate::scripting::ScriptWebSocketAction::Forward(payload)) => match frame {
            Message::Text(_) => match String::from_utf8(payload.to_vec()) {
                Ok(text) => Some(Message::text(text)),
                Err(error) => {
                    tracing::warn!("Lua WebSocket text replacement was not UTF-8: {error}");
                    None
                }
            },
            Message::Binary(_) => Some(Message::binary(payload)),
            Message::Ping(_) => Some(Message::Ping(payload)),
            Message::Pong(_) => Some(Message::Pong(payload)),
            other @ (Message::Close(_) | Message::Frame(_)) => Some(other),
        },
        Err(error) => {
            tracing::warn!("Lua on_websocket_frame error (passing through): {error}");
            Some(frame)
        }
    }
}

/// Convert a rama WebSocket [`Message`] into a [`WsFrame`] event and send it.
fn emit_ws_frame(
    tx: &mpsc::Sender<ProxyEvent>,
    conn_id: u64,
    msg: &Message,
    direction: WsDirection,
) {
    let time = now_millis();
    let (opcode, raw): (WsOpcode, &[u8]) = match msg {
        Message::Text(s) => (WsOpcode::Text, s.as_bytes()),
        Message::Binary(b) => (WsOpcode::Binary, b.as_ref()),
        Message::Ping(b) => (WsOpcode::Ping, b.as_ref()),
        Message::Pong(b) => (WsOpcode::Pong, b.as_ref()),
        Message::Close(_) => (WsOpcode::Close, b""),
        Message::Frame(_) => (WsOpcode::Continuation, b""),
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
