use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http::uri::{Authority, Scheme};
use http::{Method, Response, Uri};
use proxelar_proto::http1::{
    serve_connection_with_upgrades, BoxIo, ConnectionConfig, ServerConnection, UpgradeReceiver,
};
use proxelar_proto::{
    BoxFuture, HttpService, ProtocolError, ProxyRequest, ProxyResponse, ResponseHead,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};

use proxyapi_models::{ProxiedRequest, ProxiedResponse, WsDirection, WsFrame, WsOpcode};

use crate::ca::{cert_server, CertificateAuthority, Ssl};
use crate::event::ProxyEvent;
use crate::handler::{now_millis, CapturingHandler};
use crate::rewind::Rewind;
use crate::{HttpContext, HttpHandler, RequestOrResponse};

use super::{
    http1::{NativePool, NativeUpstream},
    is_benign_shutdown_error, BoxError,
};

/// HTTP/2 prior-knowledge connection preface.
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// Maximum request prefix inspected while deciding whether a stream is HTTP/1.
const MAX_PROTOCOL_PREFIX: usize = 4096;
/// TLS record content type: Handshake.
const TLS_RECORD_HANDSHAKE: u8 = 0x16;
/// TLS major version byte (SSLv3 / TLS 1.x).
const TLS_VERSION_MAJOR: u8 = 0x03;
/// Maximum payload size captured per WebSocket frame.
const MAX_WS_FRAME_PAYLOAD: Option<usize> = crate::handler::DEFAULT_BODY_CAPTURE_LIMIT;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum StreamProtocol {
    Http,
    Tls,
    Unknown,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_connection(
    mut stream: TcpStream,
    remote_addr: SocketAddr,
    handler: CapturingHandler,
    ca: Arc<Ssl>,
    native_pool: Arc<NativePool>,
    route: Option<String>,
    listen_addr: SocketAddr,
) {
    let (_, buffered) = match sniff_stream_protocol(&mut stream).await {
        Ok(detected) => detected,
        Err(error) => {
            tracing::debug!("Forward proxy protocol detection failed: {error}");
            return;
        }
    };
    let h2 = is_h2_preface(&buffered);
    let stream = Rewind::new_buffered(stream, buffered);
    if !h2 {
        let upstream = NativeUpstream::shared(native_pool, route);
        if let Err(error) = serve_native_stream(
            Box::new(stream),
            Scheme::HTTP,
            handler,
            ca,
            upstream,
            remote_addr,
            listen_addr,
        )
        .await
        {
            tracing::debug!("Forward HTTP/1 connection error: {error}");
        }
        return;
    }

    if let Err(error) = super::http2::serve_forward(
        stream,
        Scheme::HTTP,
        remote_addr,
        handler,
        ca,
        native_pool,
        route,
        listen_addr,
    )
    .await
    {
        if !is_benign_shutdown_error(error.as_ref()) {
            tracing::debug!("Forward HTTP/2 connection error: {error}");
        }
    }
}

enum NativeUpgradePlan {
    Connect(Authority),
    WebSocket {
        upstream: UpgradeReceiver,
        handler: Box<CapturingHandler>,
        conn_id: u64,
    },
}

struct ForwardHttp1Service {
    scheme: Scheme,
    handler: CapturingHandler,
    ca: Arc<Ssl>,
    upstream: NativeUpstream,
    remote_addr: SocketAddr,
    listen_addr: SocketAddr,
    upgrade: Arc<Mutex<Option<NativeUpgradePlan>>>,
}

impl HttpService for ForwardHttp1Service {
    fn call(
        &mut self,
        request: ProxyRequest,
    ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
        let scheme = self.scheme.clone();
        let mut handler = self.handler.clone();
        let ca = Arc::clone(&self.ca);
        let upstream = self.upstream.clone();
        let remote_addr = self.remote_addr;
        let listen_addr = self.listen_addr;
        let upgrade = Arc::clone(&self.upgrade);
        Box::pin(async move {
            if is_direct_cert_protocol_request(&request, listen_addr)
                || is_cert_protocol_request(&request)
            {
                return Ok(handle_cert_protocol_request(
                    &request,
                    &ca.ca_cert_pem(),
                    Some(listen_addr),
                ));
            }

            if request.head.method == Method::CONNECT {
                let authority =
                    request.head.uri.authority().cloned().ok_or_else(|| {
                        protocol_bad_request("CONNECT request is missing authority")
                    })?;
                *upgrade.lock().await = Some(NativeUpgradePlan::Connect(authority));
                return Ok(ProxyResponse::new(
                    ResponseHead::new(
                        http::StatusCode::OK,
                        http::Version::HTTP_11,
                        proxyapi_models::HeaderBlock::new(),
                    ),
                    crate::ProxyBody::empty(),
                ));
            }

            let request = reconstruct_protocol_uri(request, scheme)?;
            if is_cert_protocol_request(&request) {
                return Ok(handle_cert_protocol_request(
                    &request,
                    &ca.ca_cert_pem(),
                    Some(listen_addr),
                ));
            }

            let websocket = is_protocol_websocket_upgrade(&request);
            let ctx = HttpContext { remote_addr };
            let request = match handler.handle_request(&ctx, request).await {
                RequestOrResponse::Request(request) => request,
                RequestOrResponse::Response(response) => return Ok(response),
            };

            match upstream.send(request, websocket).await {
                Ok(mut result)
                    if websocket
                        && result.response.head.status == http::StatusCode::SWITCHING_PROTOCOLS =>
                {
                    let Some(upstream_upgrade) = result.upgrade.take() else {
                        return Ok(handler.synthetic_protocol_response(
                            http::StatusCode::BAD_GATEWAY,
                            http::HeaderMap::new(),
                            Bytes::from_static(b"Bad Gateway: missing WebSocket upgrade"),
                        ));
                    };
                    let ws_response = ProxiedResponse::new(
                        result.response.head.status,
                        result.response.head.version,
                        result.response.head.headers.clone(),
                        Bytes::new(),
                        now_millis(),
                    );
                    let conn_id = handler
                        .take_pending_id()
                        .unwrap_or_else(crate::event::next_id);
                    if let Some(captured_req) = handler.take_captured_request() {
                        handler.send_event(ProxyEvent::WebSocketConnected {
                            id: conn_id,
                            request: Box::new(captured_req),
                            response: Box::new(ws_response),
                        });
                    }
                    *upgrade.lock().await = Some(NativeUpgradePlan::WebSocket {
                        upstream: upstream_upgrade,
                        handler: Box::new(handler),
                        conn_id,
                    });
                    Ok(result.response)
                }
                Ok(result) => Ok(handler.handle_response(&ctx, result.response).await),
                Err(error) => {
                    tracing::error!("Native forward HTTP/1 error: {error}");
                    Ok(handler.synthetic_protocol_response(
                        http::StatusCode::BAD_GATEWAY,
                        http::HeaderMap::new(),
                        Bytes::from_static(b"Bad Gateway"),
                    ))
                }
            }
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn serve_native_stream(
    stream: BoxIo,
    scheme: Scheme,
    handler: CapturingHandler,
    ca: Arc<Ssl>,
    upstream: NativeUpstream,
    remote_addr: SocketAddr,
    listen_addr: SocketAddr,
) -> Result<(), BoxError> {
    let upgrade = Arc::new(Mutex::new(None));
    let service = ForwardHttp1Service {
        scheme,
        handler: handler.clone(),
        ca: Arc::clone(&ca),
        upstream: upstream.clone(),
        remote_addr,
        listen_addr,
        upgrade: Arc::clone(&upgrade),
    };
    let outcome = serve_connection_with_upgrades(stream, service, ConnectionConfig::default())
        .await
        .map_err(|error| -> BoxError { Box::new(error) })?;
    let ServerConnection::Upgraded(client_upgrade) = outcome else {
        return Ok(());
    };
    let Some(plan) = upgrade.lock().await.take() else {
        return Ok(());
    };
    match plan {
        NativeUpgradePlan::Connect(authority) => {
            handle_native_connect(
                client_upgrade,
                authority,
                handler,
                ca,
                upstream,
                remote_addr,
                listen_addr,
            )
            .await;
        }
        NativeUpgradePlan::WebSocket {
            upstream,
            handler,
            conn_id,
        } => match upstream.wait().await {
            Ok(server_upgrade) => {
                pump_native_websocket(conn_id, client_upgrade, server_upgrade, *handler).await;
            }
            Err(error) => tracing::debug!("Native WebSocket upstream upgrade failed: {error}"),
        },
    }
    Ok(())
}

fn protocol_bad_request(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(proxelar_proto::ErrorKind::MalformedMessage, message)
}

pub(super) fn reconstruct_protocol_uri(
    mut request: ProxyRequest,
    scheme: Scheme,
) -> Result<ProxyRequest, ProtocolError> {
    let authority = request
        .head
        .uri
        .authority()
        .cloned()
        .or_else(|| {
            request
                .head
                .headers
                .get("host")
                .and_then(|value| Authority::try_from(value).ok())
        })
        .ok_or_else(|| protocol_bad_request("request is missing a valid Host authority"))?;
    let mut parts = request.head.uri.into_parts();
    parts.scheme = Some(scheme);
    parts.authority = Some(authority);
    request.head.uri = Uri::from_parts(parts)
        .map_err(|error| protocol_bad_request(format!("invalid request URI: {error}")))?;
    Ok(request)
}

pub(super) fn is_protocol_websocket_upgrade(request: &ProxyRequest) -> bool {
    request
        .head
        .headers
        .get("upgrade")
        .is_some_and(|value| value.eq_ignore_ascii_case(b"websocket"))
        && request
            .head
            .headers
            .get_all("connection")
            .flat_map(|value| value.split(|byte| *byte == b','))
            .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"upgrade"))
}

pub(super) fn is_cert_protocol_request(request: &ProxyRequest) -> bool {
    request
        .head
        .uri
        .host()
        .is_some_and(|host| host == "proxel.ar")
        || request.head.headers.get("host").is_some_and(|host| {
            host.eq_ignore_ascii_case(b"proxel.ar")
                || host
                    .get(..11)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"proxel.ar:"))
        })
}

pub(super) fn is_direct_cert_protocol_request(
    request: &ProxyRequest,
    listen_addr: SocketAddr,
) -> bool {
    if request.head.uri.host().is_some() || request.head.uri.path().is_empty() {
        return false;
    }
    let Some(host) = request.head.headers.get("host") else {
        return true;
    };
    let Ok(host) = std::str::from_utf8(host) else {
        return false;
    };
    let Ok(authority) = host.parse::<Authority>() else {
        return false;
    };
    if authority.port_u16().unwrap_or(80) != listen_addr.port() {
        return false;
    }
    if authority.host().eq_ignore_ascii_case("localhost") {
        return listen_addr.ip().is_loopback() || listen_addr.ip().is_unspecified();
    }
    authority
        .host()
        .parse::<std::net::IpAddr>()
        .is_ok_and(|host_ip| {
            host_ip == listen_addr.ip()
                || (listen_addr.ip().is_unspecified() && host_ip.is_loopback())
        })
}

pub(super) fn handle_cert_protocol_request(
    request: &ProxyRequest,
    ca_cert_pem: &[u8],
    proxy_addr: Option<SocketAddr>,
) -> ProxyResponse {
    let mut compatibility = http::Request::new(());
    *compatibility.method_mut() = request.head.method.clone();
    *compatibility.uri_mut() = request.head.uri.clone();
    *compatibility.version_mut() = request.head.version;
    *compatibility.headers_mut() =
        crate::header::to_http(&request.head.headers).unwrap_or_default();
    let response = cert_server::handle(&compatibility, ca_cert_pem, proxy_addr);
    let (parts, body) = response.into_parts();
    ProxyResponse::new(
        ResponseHead::new(
            parts.status,
            parts.version,
            crate::header::from_http(&parts.headers),
        ),
        body,
    )
}

#[allow(clippy::too_many_arguments)]
async fn handle_native_connect(
    upgraded: proxelar_proto::http1::UpgradedIo<BoxIo>,
    authority: Authority,
    handler: CapturingHandler,
    ca: Arc<Ssl>,
    upstream: NativeUpstream,
    remote_addr: SocketAddr,
    listen_addr: SocketAddr,
) {
    let mut stream = Rewind::new_buffered(upgraded.io, upgraded.read_ahead);
    let (protocol, buffered) = match sniff_stream_protocol(&mut stream).await {
        Ok(detected) => detected,
        Err(error) => {
            tracing::debug!("Native CONNECT protocol detection failed: {error}");
            return;
        }
    };
    let h2 = is_h2_preface(&buffered);
    let stream = Rewind::new_buffered(stream, buffered);
    match protocol {
        StreamProtocol::Http => {
            let result = if h2 {
                serve_stream(
                    stream,
                    Scheme::HTTP,
                    handler,
                    ca,
                    upstream,
                    remote_addr,
                    listen_addr,
                )
                .await
            } else {
                Box::pin(serve_native_stream(
                    Box::new(stream),
                    Scheme::HTTP,
                    handler,
                    ca,
                    upstream,
                    remote_addr,
                    listen_addr,
                ))
                .await
            };
            if let Err(error) = result {
                tracing::debug!("Native CONNECT HTTP error: {error}");
            }
        }
        StreamProtocol::Tls => {
            let server_config = match ca.gen_server_config(&authority).await {
                Ok(config) => config,
                Err(error) => {
                    tracing::debug!("Native CONNECT certificate error: {error}");
                    return;
                }
            };
            let stream = match TlsAcceptor::from(server_config).accept(stream).await {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::debug!("Native CONNECT TLS error: {error}");
                    return;
                }
            };
            let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
            let result = if h2 {
                serve_stream(
                    stream,
                    Scheme::HTTPS,
                    handler,
                    ca,
                    upstream,
                    remote_addr,
                    listen_addr,
                )
                .await
            } else {
                Box::pin(serve_native_stream(
                    Box::new(stream),
                    Scheme::HTTPS,
                    handler,
                    ca,
                    upstream,
                    remote_addr,
                    listen_addr,
                ))
                .await
            };
            if let Err(error) = result {
                tracing::debug!("Native CONNECT inspected TLS error: {error}");
            }
        }
        StreamProtocol::Unknown => {
            let mut client = stream;
            let mut server = match TcpStream::connect(authority.as_str()).await {
                Ok(server) => server,
                Err(error) => {
                    tracing::debug!("Native CONNECT upstream tunnel error: {error}");
                    return;
                }
            };
            if let Err(error) = super::raw::tunnel(
                &mut client,
                &mut server,
                authority.to_string(),
                handler.event_tx_clone(),
            )
            .await
            {
                tracing::debug!("Native CONNECT raw tunnel error: {error}");
            }
        }
    }
}

pub(super) async fn pump_native_websocket<I>(
    conn_id: u64,
    client: proxelar_proto::http1::UpgradedIo<I>,
    server: proxelar_proto::http1::UpgradedIo<proxelar_proto::http1::BoxIo>,
    handler: CapturingHandler,
) where
    I: AsyncRead + AsyncWrite + Unpin,
{
    let client = Rewind::new_buffered(client.io, client.read_ahead);
    let server = Rewind::new_buffered(server.io, server.read_ahead);
    let event_tx = handler.event_tx_clone();
    #[cfg(feature = "scripting")]
    let script_engine = handler.script_engine_clone();
    relay_websocket_streams(
        conn_id,
        client,
        server,
        event_tx,
        #[cfg(feature = "scripting")]
        script_engine,
    )
    .await;
}

/// Inspect an already-established stream whose original destination is known.
///
/// WireGuard and other userspace capture transports use this entry point to
/// share HTTP, TLS, and raw-stream behavior.
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_captured_stream<I>(
    mut stream: I,
    remote_addr: SocketAddr,
    handler: CapturingHandler,
    ca: Arc<Ssl>,
    native_pool: Arc<NativePool>,
    route: Option<String>,
    listen_addr: SocketAddr,
    authority: Authority,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (protocol, buffered) = match sniff_stream_protocol(&mut stream).await {
        Ok(result) => result,
        Err(error) => {
            tracing::debug!("Captured-stream protocol detection failed: {error}");
            return;
        }
    };
    let h2 = is_h2_preface(&buffered);
    let stream = Rewind::new_buffered(stream, buffered);
    match protocol {
        StreamProtocol::Http => {
            let result = if h2 {
                serve_stream(
                    stream,
                    Scheme::HTTP,
                    handler,
                    ca,
                    NativeUpstream::shared(Arc::clone(&native_pool), route.clone()),
                    remote_addr,
                    listen_addr,
                )
                .await
            } else {
                serve_native_stream(
                    Box::new(stream),
                    Scheme::HTTP,
                    handler,
                    ca,
                    NativeUpstream::shared(native_pool, route),
                    remote_addr,
                    listen_addr,
                )
                .await
            };
            if let Err(error) = result {
                tracing::debug!("Captured HTTP connection failed: {error}");
            }
        }
        StreamProtocol::Tls => {
            let server_config = match ca.gen_server_config(&authority).await {
                Ok(config) => config,
                Err(error) => {
                    tracing::warn!("Captured-stream certificate generation failed: {error}");
                    return;
                }
            };
            let stream = match TlsAcceptor::from(server_config).accept(stream).await {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::debug!("Captured TLS handshake failed: {error}");
                    return;
                }
            };
            let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
            let result = if h2 {
                serve_stream(
                    stream,
                    Scheme::HTTPS,
                    handler,
                    ca,
                    NativeUpstream::shared(Arc::clone(&native_pool), route.clone()),
                    remote_addr,
                    listen_addr,
                )
                .await
            } else {
                serve_native_stream(
                    Box::new(stream),
                    Scheme::HTTPS,
                    handler,
                    ca,
                    NativeUpstream::shared(native_pool, route),
                    remote_addr,
                    listen_addr,
                )
                .await
            };
            if let Err(error) = result {
                tracing::debug!("Captured HTTPS connection failed: {error}");
            }
        }
        StreamProtocol::Unknown => {
            let mut stream = stream;
            let mut upstream = match TcpStream::connect(authority.as_str()).await {
                Ok(upstream) => upstream,
                Err(error) => {
                    tracing::debug!("Captured TCP connection failed: {error}");
                    return;
                }
            };
            if let Err(error) = super::raw::tunnel(
                &mut stream,
                &mut upstream,
                authority.to_string(),
                handler.event_tx_clone(),
            )
            .await
            {
                tracing::debug!("Captured TCP tunnel failed: {error}");
            }
        }
    }
}

/// Serve HTTP requests over an already-established stream (plain or TLS).
///
/// Each request is passed through the [`CapturingHandler`] for inspection before
/// being forwarded to the upstream server via `client`.
pub(super) async fn serve_stream<I>(
    stream: I,
    scheme: Scheme,
    handler: CapturingHandler,
    ca: Arc<Ssl>,
    upstream: NativeUpstream,
    remote_addr: SocketAddr,
    listen_addr: SocketAddr,
) -> Result<(), BoxError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    super::http2::serve_with_upstream(
        stream,
        scheme,
        remote_addr,
        handler,
        ca,
        upstream,
        None,
        None,
        listen_addr,
    )
    .await
}

/// Serve inspected client traffic over one already-established upstream
/// connection. SOCKS5 uses this to preserve the destination selected by its
/// CONNECT request even when the inner HTTP `Host` value differs.
#[allow(clippy::too_many_arguments)]
pub(super) async fn serve_pinned_stream<I, U>(
    mut stream: I,
    upstream: U,
    authority: Authority,
    scheme: Scheme,
    handler: CapturingHandler,
    ca: Arc<Ssl>,
    remote_addr: SocketAddr,
    listen_addr: SocketAddr,
) -> Result<(), BoxError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (_, buffered) = sniff_stream_protocol(&mut stream).await?;
    let h2 = is_h2_preface(&buffered);
    let stream = Rewind::new_buffered(stream, buffered);
    if h2 {
        return super::http2::serve_pinned(
            stream,
            upstream,
            authority,
            scheme,
            remote_addr,
            handler,
            ca,
            listen_addr,
        )
        .await;
    }

    serve_native_stream(
        Box::new(stream),
        scheme,
        handler,
        ca,
        NativeUpstream::pinned(upstream, authority),
        remote_addr,
        listen_addr,
    )
    .await
}

pub(super) async fn sniff_stream_protocol<I>(
    stream: &mut I,
) -> std::io::Result<(StreamProtocol, Bytes)>
where
    I: AsyncRead + Unpin,
{
    let mut buffer = [0u8; MAX_PROTOCOL_PREFIX];
    let mut filled = 0;

    loop {
        let bytes_read = stream.read(&mut buffer[filled..]).await?;
        if bytes_read == 0 {
            break;
        }

        filled += bytes_read;
        let prefix = &buffer[..filled];

        if is_tls_handshake(prefix) {
            return Ok((StreamProtocol::Tls, Bytes::copy_from_slice(prefix)));
        }
        if is_h2_preface(prefix) || is_http1_request(prefix) {
            return Ok((StreamProtocol::Http, Bytes::copy_from_slice(prefix)));
        }
        if filled < buffer.len() && could_be_known_protocol(prefix) {
            continue;
        }

        return Ok((StreamProtocol::Unknown, Bytes::copy_from_slice(prefix)));
    }

    Ok((
        classify_buffered_protocol(&buffer[..filled]),
        Bytes::copy_from_slice(&buffer[..filled]),
    ))
}

fn classify_buffered_protocol(buffered: &[u8]) -> StreamProtocol {
    if is_tls_handshake(buffered) {
        StreamProtocol::Tls
    } else if is_h2_preface(buffered) || is_http1_request(buffered) {
        StreamProtocol::Http
    } else {
        StreamProtocol::Unknown
    }
}

fn is_tls_handshake(buffered: &[u8]) -> bool {
    buffered.len() >= 2 && buffered[0] == TLS_RECORD_HANDSHAKE && buffered[1] == TLS_VERSION_MAJOR
}

pub(super) fn is_h2_preface(buffered: &[u8]) -> bool {
    buffered.starts_with(H2_PREFACE)
}

fn is_http1_request(buffered: &[u8]) -> bool {
    let Some(method_end) = buffered.iter().position(|byte| *byte == b' ') else {
        return false;
    };
    let Some(version_start) = buffered[method_end + 1..]
        .iter()
        .position(|byte| *byte == b' ')
        .map(|offset| method_end + 1 + offset + 1)
    else {
        return false;
    };
    method_end > 0
        && buffered[..method_end]
            .iter()
            .all(|byte| is_http_token(*byte))
        && version_start + 8 <= buffered.len()
        && buffered[version_start..].starts_with(b"HTTP/1.")
}

fn could_be_known_protocol(buffered: &[u8]) -> bool {
    is_partial_tls_handshake(buffered)
        || H2_PREFACE.starts_with(buffered)
        || could_be_http1_request(buffered)
}

fn could_be_http1_request(buffered: &[u8]) -> bool {
    let Some(method_end) = buffered.iter().position(|byte| *byte == b' ') else {
        return false;
    };
    if method_end == 0
        || !buffered[..method_end]
            .iter()
            .all(|byte| is_http_token(*byte))
    {
        return false;
    }
    buffered[method_end + 1..]
        .iter()
        .position(|byte| *byte == b' ')
        .is_none()
        || is_http1_request(buffered)
}

fn is_http_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn is_partial_tls_handshake(buffered: &[u8]) -> bool {
    buffered == [TLS_RECORD_HANDSHAKE]
}

async fn relay_websocket_streams<C, S>(
    conn_id: u64,
    client: C,
    server: S,
    event_tx: mpsc::Sender<ProxyEvent>,
    #[cfg(feature = "scripting")] script_engine: Option<Arc<crate::scripting::ScriptEngine>>,
) where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut client_ws = WebSocketStream::from_raw_socket(
        client,
        tokio_tungstenite::tungstenite::protocol::Role::Server,
        None,
    )
    .await;
    let mut server_ws = WebSocketStream::from_raw_socket(
        server,
        tokio_tungstenite::tungstenite::protocol::Role::Client,
        None,
    )
    .await;

    relay_websocket_frames(
        conn_id,
        &mut client_ws,
        &mut server_ws,
        event_tx,
        #[cfg(feature = "scripting")]
        script_engine,
    )
    .await;
}

async fn relay_websocket_frames<C, S>(
    conn_id: u64,
    client_ws: &mut WebSocketStream<C>,
    server_ws: &mut WebSocketStream<S>,
    event_tx: mpsc::Sender<ProxyEvent>,
    #[cfg(feature = "scripting")] script_engine: Option<Arc<crate::scripting::ScriptEngine>>,
) where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            msg = client_ws.next() => match msg {
                Some(Ok(frame)) => {
                    #[cfg(feature = "scripting")]
                    let Some(frame) = transform_ws_frame(
                        frame,
                        WsDirection::ClientToServer,
                        script_engine.as_deref(),
                    ) else { continue; };
                    emit_ws_frame(&event_tx, conn_id, &frame, WsDirection::ClientToServer);
                    if server_ws.send(frame).await.is_err() { break; }
                }
                Some(Err(e)) => {
                    tracing::debug!("WS client error conn_id={conn_id}: {e}");
                    break;
                }
                None => break,
            },
            msg = server_ws.next() => match msg {
                Some(Ok(frame)) => {
                    #[cfg(feature = "scripting")]
                    let Some(frame) = transform_ws_frame(
                        frame,
                        WsDirection::ServerToClient,
                        script_engine.as_deref(),
                    ) else { continue; };
                    emit_ws_frame(&event_tx, conn_id, &frame, WsDirection::ServerToClient);
                    if client_ws.send(frame).await.is_err() { break; }
                }
                Some(Err(e)) => {
                    tracing::debug!("WS server error conn_id={conn_id}: {e}");
                    break;
                }
                None => break,
            },
        }
    }

    let _ = event_tx.try_send(ProxyEvent::WebSocketClosed { conn_id });
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
            Message::Text(_) => String::from_utf8(payload.to_vec())
                .map(|payload| Message::Text(payload.into()))
                .map_err(|error| {
                    tracing::warn!("Lua WebSocket text replacement was not UTF-8: {error}");
                })
                .ok(),
            Message::Binary(_) => Some(Message::Binary(payload)),
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

/// Convert a tungstenite [`Message`] into a [`WsFrame`] event and send it.
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

/// Send a previously captured request back through the proxy pipeline.
///
/// Applies intercept logic (if enabled) then forwards via the shared client,
/// emitting a [`ProxyEvent::RequestComplete`] on completion.
pub(super) async fn handle_replay(
    req: ProxiedRequest,
    mut handler: CapturingHandler,
    native_pool: Arc<NativePool>,
    route: Option<String>,
) {
    let Some(fwd_req) = handler.handle_replayed_request(req).await else {
        return;
    };
    let upstream = NativeUpstream::shared(native_pool, route);
    match upstream.send(fwd_req, false).await {
        Ok(res) => {
            handler
                .record_upstream_response(response_from_protocol_for_capture(res.response))
                .await;
        }
        Err(e) => {
            tracing::warn!("Replay request failed: {e}");
            handler.emit_synthetic_completion(
                http::StatusCode::BAD_GATEWAY,
                http::HeaderMap::new(),
                Bytes::from(format!("Replay request failed: {e}")),
            );
        }
    }
}

fn response_from_protocol_for_capture(
    response: crate::ProxyResponse,
) -> Response<crate::ProxyBody> {
    let (head, body) = response.into_parts();
    let mut response = Response::new(body);
    *response.status_mut() = head.status;
    *response.version_mut() = head.version;
    *response.headers_mut() = crate::header::to_http(&head.headers).unwrap_or_default();
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_upgrade_requires_upgrade_header_and_connection_token() {
        fn request(headers: &[(&[u8], &[u8])]) -> ProxyRequest {
            let mut block = proxyapi_models::HeaderBlock::new();
            for (name, value) in headers {
                block.add(*name, *value).unwrap();
            }
            ProxyRequest::new(
                proxelar_proto::RequestHead::new(
                    Method::GET,
                    "http://example.test/ws".parse().unwrap(),
                    http::Version::HTTP_11,
                    block,
                ),
                crate::ProxyBody::empty(),
            )
        }

        assert!(is_protocol_websocket_upgrade(&request(&[
            (b"Upgrade", b"WebSocket"),
            (b"Connection", b"keep-alive, Upgrade"),
        ])));
        assert!(!is_protocol_websocket_upgrade(&request(&[(
            b"Upgrade",
            b"websocket"
        ),])));
        assert!(!is_protocol_websocket_upgrade(&request(&[
            (b"Upgrade", b"h2c"),
            (b"Connection", b"upgrade"),
        ])));
    }

    #[test]
    fn classify_buffered_protocol_detects_http2_preface() {
        assert_eq!(classify_buffered_protocol(H2_PREFACE), StreamProtocol::Http);
    }

    #[test]
    fn classify_buffered_protocol_detects_http1_methods_and_tls() {
        assert_eq!(
            classify_buffered_protocol(b"POST /upload HTTP/1.1\r\n"),
            StreamProtocol::Http
        );
        assert_eq!(
            classify_buffered_protocol(b"PROPFIND /collection HTTP/1.1\r\n"),
            StreamProtocol::Http
        );
        assert_eq!(
            classify_buffered_protocol(&[TLS_RECORD_HANDSHAKE, TLS_VERSION_MAJOR, 0x03, 0x00]),
            StreamProtocol::Tls
        );
        assert_eq!(
            classify_buffered_protocol(b"\x01\x02\x03"),
            StreamProtocol::Unknown
        );
    }

    #[test]
    fn could_be_known_protocol_waits_for_partial_prefixes() {
        assert!(could_be_known_protocol(b"P"));
        assert!(!could_be_known_protocol(b"CUSTOM"));
        assert!(could_be_known_protocol(b"CUSTOM /path"));
        assert!(could_be_known_protocol(b"PRI * HTTP/2.0\r\n"));
        assert!(could_be_known_protocol(&[TLS_RECORD_HANDSHAKE]));
        assert!(!could_be_known_protocol(b"\x01NOPE"));
    }

    #[tokio::test]
    async fn emit_ws_frame_maps_text_message_to_event() {
        let (tx, mut rx) = mpsc::channel(1);

        emit_ws_frame(
            &tx,
            42,
            &Message::Text("hello".into()),
            WsDirection::ClientToServer,
        );

        match rx.recv().await.unwrap() {
            ProxyEvent::WebSocketFrame { conn_id, frame } => {
                assert_eq!(conn_id, 42);
                assert_eq!(frame.direction, WsDirection::ClientToServer);
                assert_eq!(frame.opcode, WsOpcode::Text);
                assert_eq!(frame.payload.as_ref(), b"hello");
                assert!(!frame.truncated);
            }
            other => panic!("expected WebSocketFrame event, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn emit_ws_frame_maps_control_messages() {
        let (tx, mut rx) = mpsc::channel(3);

        emit_ws_frame(
            &tx,
            7,
            &Message::Binary(vec![1, 2, 3].into()),
            WsDirection::ServerToClient,
        );
        emit_ws_frame(
            &tx,
            7,
            &Message::Ping(Bytes::from_static(b"ping")),
            WsDirection::ServerToClient,
        );
        emit_ws_frame(&tx, 7, &Message::Close(None), WsDirection::ServerToClient);

        let first = rx.recv().await.unwrap();
        let second = rx.recv().await.unwrap();
        let third = rx.recv().await.unwrap();

        match first {
            ProxyEvent::WebSocketFrame { frame, .. } => {
                assert_eq!(frame.opcode, WsOpcode::Binary);
                assert_eq!(frame.payload.as_ref(), &[1, 2, 3]);
            }
            other => panic!("expected binary frame, got {other:?}"),
        }
        match second {
            ProxyEvent::WebSocketFrame { frame, .. } => {
                assert_eq!(frame.opcode, WsOpcode::Ping);
                assert_eq!(frame.payload.as_ref(), b"ping");
            }
            other => panic!("expected ping frame, got {other:?}"),
        }
        match third {
            ProxyEvent::WebSocketFrame { frame, .. } => {
                assert_eq!(frame.opcode, WsOpcode::Close);
                assert!(frame.payload.is_empty());
            }
            other => panic!("expected close frame, got {other:?}"),
        }
    }
}
