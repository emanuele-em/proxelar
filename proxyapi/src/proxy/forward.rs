use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http::uri::{Authority, Scheme};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, Uri};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};

use proxyapi_models::{ProxiedRequest, ProxiedResponse, WsDirection, WsFrame, WsOpcode};

use crate::ca::{cert_server, CertificateAuthority, Ssl};
use crate::event::ProxyEvent;
use crate::handler::{now_millis, CapturingHandler};
use crate::hyper_adapter::{
    from_hyper_request, from_hyper_response, to_hyper_request, to_hyper_response, HyperBody,
};
use crate::rewind::Rewind;
use crate::{HttpContext, HttpHandler, RequestOrResponse};

use super::{
    is_benign_shutdown_error, prepare_upstream_request, prepare_upstream_upgrade_request,
    sanitize_response_for_client, serve_auto_connection, BoxError, Client,
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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum TunnelRequestError {
    MissingHost,
    InvalidHost,
    InvalidUri,
}

#[derive(Clone)]
enum UpstreamClient {
    Shared(Arc<Client>),
    Pinned(Arc<Mutex<hyper::client::conn::http1::SendRequest<HyperBody>>>),
}

impl UpstreamClient {
    async fn pinned<I>(stream: I) -> Result<Self, BoxError>
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (sender, connection) = hyper::client::conn::http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .handshake(TokioIo::new(stream))
            .await?;
        tokio::spawn(async move {
            if let Err(error) = connection.with_upgrades().await {
                tracing::debug!("Pinned upstream HTTP connection closed: {error}");
            }
        });
        Ok(Self::Pinned(Arc::new(Mutex::new(sender))))
    }

    async fn request(
        &self,
        mut request: Request<HyperBody>,
    ) -> Result<Response<hyper::body::Incoming>, BoxError> {
        match self {
            Self::Shared(client) => client.request(request).await.map_err(Into::into),
            Self::Pinned(sender) => {
                use http::header::HOST;

                let authority = request.uri().authority().cloned().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "pinned upstream request is missing an authority",
                    )
                })?;
                request
                    .headers_mut()
                    .insert(HOST, authority.as_str().parse()?);
                let path_and_query: http::uri::PathAndQuery = request
                    .uri()
                    .path_and_query()
                    .map_or("/", http::uri::PathAndQuery::as_str)
                    .parse()?;
                *request.uri_mut() = Uri::builder().path_and_query(path_and_query).build()?;

                let mut sender = sender.lock().await;
                sender.ready().await?;
                sender.send_request(request).await.map_err(Into::into)
            }
        }
    }
}

/// Returns true when the request carries WebSocket upgrade tokens.
fn is_websocket_upgrade<B>(req: &Request<B>) -> bool {
    req.headers()
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
        && req
            .headers()
            .get(hyper::header::CONNECTION)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_ascii_lowercase().contains("upgrade"))
            .unwrap_or(false)
}

pub async fn handle_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    handler: CapturingHandler,
    ca: Arc<Ssl>,
    client: Arc<Client>,
    listen_addr: SocketAddr,
) {
    let io = TokioIo::new(stream);

    let service = service_fn(move |req: Request<hyper::body::Incoming>| {
        let handler = handler.clone();
        let ca = Arc::clone(&ca);
        let client = Arc::clone(&client);

        async move {
            // Direct request to the listener itself. Other origin-form
            // requests are valid embedded-client traffic and are reconstructed
            // from their Host field below.
            if is_direct_cert_request(&req, listen_addr) {
                let resp = wrap_protocol_body(cert_server::handle(&req, &ca.ca_cert_pem(), None));
                return Ok::<_, hyper::Error>(resp);
            }

            // Proxied request to proxel.ar — serve cert page
            if cert_server::is_cert_request(&req) {
                let resp = wrap_protocol_body(cert_server::handle(
                    &req,
                    &ca.ca_cert_pem(),
                    Some(listen_addr),
                ));
                return Ok::<_, hyper::Error>(resp);
            }

            if req.method() == Method::CONNECT {
                return process_connect(req, handler, ca, client, remote_addr, listen_addr);
            }

            let req = match reconstruct_tunnel_uri(req, Scheme::HTTP) {
                Ok(req) => req,
                Err(error) => return Ok(error.into_response()),
            };
            forward_http_request(req, handler, client, remote_addr).await
        }
    });

    if let Err(e) = serve_auto_connection(io, service).await {
        if !is_benign_shutdown_error(e.as_ref()) {
            tracing::debug!("Connection error: {e}");
        }
    }
}

fn is_direct_cert_request<B>(request: &Request<B>, listen_addr: SocketAddr) -> bool {
    if request.uri().host().is_some() || request.uri().path().is_empty() {
        return false;
    }
    let Some(host) = request
        .headers()
        .get(hyper::header::HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return true;
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

/// Inspect an already-established stream whose original destination is known.
///
/// WireGuard and other userspace capture transports use this entry point to
/// share HTTP, TLS, and raw-stream behavior.
pub(super) async fn handle_captured_stream<I>(
    mut stream: I,
    remote_addr: SocketAddr,
    handler: CapturingHandler,
    ca: Arc<Ssl>,
    client: Arc<Client>,
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
    let stream = Rewind::new_buffered(stream, buffered);
    match protocol {
        StreamProtocol::Http => {
            if let Err(error) = serve_stream(
                stream,
                Scheme::HTTP,
                handler,
                ca,
                client,
                remote_addr,
                listen_addr,
            )
            .await
            {
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
            if let Err(error) = serve_stream(
                stream,
                Scheme::HTTPS,
                handler,
                ca,
                client,
                remote_addr,
                listen_addr,
            )
            .await
            {
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

/// Handle a CONNECT request by upgrading the connection and tunneling traffic.
///
/// After the upgrade, the first bytes are peeked to detect whether the client
/// is speaking plain HTTP, TLS, or an unknown protocol, and the connection is
/// dispatched accordingly.
fn process_connect(
    req: Request<hyper::body::Incoming>,
    handler: CapturingHandler,
    ca: Arc<Ssl>,
    client: Arc<Client>,
    remote_addr: SocketAddr,
    listen_addr: SocketAddr,
) -> Result<Response<HyperBody>, hyper::Error> {
    let authority = if let Some(a) = req.uri().authority().cloned() {
        a
    } else {
        tracing::warn!("CONNECT request missing authority");
        return Ok(Response::builder()
            .status(400)
            .body(HyperBody::full(Bytes::from(
                "Bad Request: missing authority",
            )))
            .unwrap_or_else(|_| Response::new(HyperBody::empty())));
    };

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let mut upgraded = TokioIo::new(upgraded);
                let (protocol, buffered) = match sniff_stream_protocol(&mut upgraded).await {
                    Ok(result) => result,
                    Err(e) => {
                        tracing::error!("Failed to read from upgraded connection: {e}");
                        return;
                    }
                };

                let upgraded = Rewind::new_buffered(upgraded, buffered.clone());

                match protocol {
                    StreamProtocol::Http => {
                        if let Err(e) = serve_stream(
                            upgraded,
                            Scheme::HTTP,
                            handler,
                            ca,
                            client,
                            remote_addr,
                            listen_addr,
                        )
                        .await
                        {
                            tracing::debug!("HTTP connect error: {e}");
                        }
                    }
                    StreamProtocol::Tls => {
                        let server_config = match ca.gen_server_config(&authority).await {
                            Ok(cfg) => cfg,
                            Err(e) => {
                                tracing::error!(
                                    "Failed to generate server config for {authority}: {e}"
                                );
                                return;
                            }
                        };
                        let stream = match TlsAcceptor::from(server_config).accept(upgraded).await {
                            Ok(stream) => stream,
                            Err(e) => {
                                tracing::debug!("Failed to establish TLS connection: {e}");
                                return;
                            }
                        };

                        if let Err(e) = serve_stream(
                            stream,
                            Scheme::HTTPS,
                            handler,
                            ca,
                            client,
                            remote_addr,
                            listen_addr,
                        )
                        .await
                        {
                            if !is_benign_shutdown_error(&*e) {
                                tracing::warn!("HTTPS connect error for {authority}: {e}");
                            }
                        }
                    }
                    StreamProtocol::Unknown => {
                        tracing::debug!(
                            "Unknown protocol, read '{:02X?}' from upgraded connection",
                            buffered.as_ref()
                        );

                        let authority_str = authority.as_str();
                        let mut server = match TcpStream::connect(authority_str).await {
                            Ok(server) => server,
                            Err(e) => {
                                tracing::debug!("Failed to connect to {authority_str}: {e}");
                                return;
                            }
                        };

                        let mut upgraded = upgraded;
                        if let Err(e) = super::raw::tunnel(
                            &mut upgraded,
                            &mut server,
                            authority.to_string(),
                            handler.event_tx_clone(),
                        )
                        .await
                        {
                            tracing::debug!(
                                "Failed to tunnel unknown protocol to {authority_str}: {e}"
                            );
                        }
                    }
                }
            }
            Err(e) => tracing::error!("Upgrade error: {e}"),
        }
    });

    Ok(Response::new(HyperBody::empty()))
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
    client: Arc<Client>,
    remote_addr: SocketAddr,
    listen_addr: SocketAddr,
) -> Result<(), BoxError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_stream_with_upstream(
        stream,
        scheme,
        handler,
        ca,
        UpstreamClient::Shared(client),
        remote_addr,
        listen_addr,
    )
    .await
}

/// Serve inspected client traffic over one already-established upstream
/// connection. SOCKS5 uses this to preserve the destination selected by its
/// CONNECT request even when the inner HTTP `Host` value differs.
pub(super) async fn serve_pinned_stream<I, U>(
    stream: I,
    upstream: U,
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
    let upstream = UpstreamClient::pinned(upstream).await?;
    serve_stream_with_upstream(
        stream,
        scheme,
        handler,
        ca,
        upstream,
        remote_addr,
        listen_addr,
    )
    .await
}

async fn serve_stream_with_upstream<I>(
    stream: I,
    scheme: Scheme,
    handler: CapturingHandler,
    ca: Arc<Ssl>,
    upstream: UpstreamClient,
    remote_addr: SocketAddr,
    listen_addr: SocketAddr,
) -> Result<(), BoxError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);

    let service = service_fn(move |mut req: Request<hyper::body::Incoming>| {
        let handler = handler.clone();
        let ca = Arc::clone(&ca);
        let upstream = upstream.clone();
        let scheme = scheme.clone();

        async move {
            req = match reconstruct_tunnel_uri(req, scheme) {
                Ok(req) => req,
                Err(e) => return Ok(e.into_response()),
            };

            // Check for proxel.ar cert request (inside CONNECT tunnel)
            if cert_server::is_cert_request(&req) {
                let resp = wrap_protocol_body(cert_server::handle(
                    &req,
                    &ca.ca_cert_pem(),
                    Some(listen_addr),
                ));
                return Ok::<_, hyper::Error>(resp);
            }

            forward_http_request_with(req, handler, upstream, remote_addr).await
        }
    });

    serve_auto_connection(io, service).await
}

async fn forward_http_request(
    req: Request<hyper::body::Incoming>,
    handler: CapturingHandler,
    client: Arc<Client>,
    remote_addr: SocketAddr,
) -> Result<Response<HyperBody>, hyper::Error> {
    forward_http_request_with(req, handler, UpstreamClient::Shared(client), remote_addr).await
}

async fn forward_http_request_with(
    mut req: Request<hyper::body::Incoming>,
    mut handler: CapturingHandler,
    upstream: UpstreamClient,
    remote_addr: SocketAddr,
) -> Result<Response<HyperBody>, hyper::Error> {
    let client_version = req.version();
    let ctx = HttpContext { remote_addr };

    // Extract WebSocket upgrade future before handle_request consumes req.
    let is_ws = is_websocket_upgrade(&req);
    let client_on_upgrade = if is_ws {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };

    let req = match handler.handle_request(&ctx, from_hyper_request(req)).await {
        RequestOrResponse::Request(req) => match to_hyper_request(req) {
            Ok(req) => req,
            Err(error) => {
                tracing::warn!("Could not adapt request for temporary Hyper client: {error}");
                return Ok(protocol_response_to_hyper(
                    handler.synthetic_protocol_response(
                        http::StatusCode::BAD_REQUEST,
                        http::HeaderMap::new(),
                        Bytes::from_static(b"Invalid request headers"),
                    ),
                ));
            }
        },
        RequestOrResponse::Response(res) => {
            let mut res = protocol_response_to_hyper(res);
            sanitize_response_for_client(&mut res, client_version);
            return Ok(res);
        }
    };

    let upstream_req = if is_ws {
        prepare_upstream_upgrade_request(req)
    } else {
        prepare_upstream_request(req)
    };

    match upstream.request(upstream_req).await {
        Ok(res) => {
            if is_ws && res.status() == hyper::StatusCode::SWITCHING_PROTOCOLS {
                return Ok(upgrade_websocket_response(res, handler, client_on_upgrade));
            }

            let response = handler
                .handle_response(&ctx, from_hyper_response(res))
                .await;
            let mut res = protocol_response_to_hyper(response);
            sanitize_response_for_client(&mut res, client_version);
            Ok(res)
        }
        Err(e) => {
            tracing::error!("Client request error: {e}");
            let mut res = protocol_response_to_hyper(handler.synthetic_protocol_response(
                http::StatusCode::BAD_GATEWAY,
                http::HeaderMap::new(),
                Bytes::from_static(b"Bad Gateway"),
            ));
            sanitize_response_for_client(&mut res, client_version);
            Ok(res)
        }
    }
}

fn protocol_response_to_hyper(response: crate::ProxyResponse) -> Response<HyperBody> {
    to_hyper_response(response).unwrap_or_else(|error| {
        tracing::warn!("Could not adapt response for temporary Hyper server: {error}");
        Response::builder()
            .status(http::StatusCode::BAD_GATEWAY)
            .body(HyperBody::full(Bytes::from_static(
                b"Invalid response headers",
            )))
            .unwrap_or_else(|_| Response::new(HyperBody::empty()))
    })
}

fn wrap_protocol_body(response: Response<crate::ProxyBody>) -> Response<HyperBody> {
    let (parts, body) = response.into_parts();
    Response::from_parts(parts, HyperBody::new(body))
}

fn upgrade_websocket_response(
    mut res: Response<hyper::body::Incoming>,
    mut handler: CapturingHandler,
    client_on_upgrade: Option<hyper::upgrade::OnUpgrade>,
) -> Response<HyperBody> {
    let server_on_upgrade = hyper::upgrade::on(&mut res);
    let (parts, _body) = res.into_parts();

    let ws_response = ProxiedResponse::new(
        parts.status,
        parts.version,
        crate::header::from_http(&parts.headers),
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

    if let Some(client_fut) = client_on_upgrade {
        let event_tx = handler.event_tx_clone();
        #[cfg(feature = "scripting")]
        let script_engine = handler.script_engine_clone();
        tokio::spawn(async move {
            pump_websocket_frames(
                conn_id,
                client_fut,
                server_on_upgrade,
                event_tx,
                #[cfg(feature = "scripting")]
                script_engine,
            )
            .await;
        });
    }

    Response::from_parts(parts, HyperBody::empty())
}

fn reconstruct_tunnel_uri(
    req: Request<hyper::body::Incoming>,
    scheme: Scheme,
) -> Result<Request<hyper::body::Incoming>, TunnelRequestError> {
    let (mut parts, body) = req.into_parts();
    let authority = tunnel_authority(&parts)?;

    let mut uri_parts = parts.uri.into_parts();
    uri_parts.scheme = Some(scheme);
    uri_parts.authority = Some(authority);
    parts.uri = Uri::from_parts(uri_parts).map_err(|e| {
        tracing::warn!("Failed to build URI: {e}");
        TunnelRequestError::InvalidUri
    })?;

    Ok(Request::from_parts(parts, body))
}

fn tunnel_authority(parts: &http::request::Parts) -> Result<Authority, TunnelRequestError> {
    if let Some(authority) = parts.uri.authority() {
        return Ok(authority.clone());
    }

    let Some(host) = parts.headers.get(hyper::header::HOST) else {
        tracing::warn!("Request missing Host header");
        return Err(TunnelRequestError::MissingHost);
    };

    Authority::try_from(host.as_bytes()).map_err(|e| {
        tracing::warn!("Failed to parse authority from Host header: {e}");
        TunnelRequestError::InvalidHost
    })
}

impl TunnelRequestError {
    fn into_response(self) -> Response<HyperBody> {
        Response::builder()
            .status(http::StatusCode::BAD_REQUEST)
            .body(HyperBody::full(Bytes::from_static(
                self.message().as_bytes(),
            )))
            .unwrap_or_else(|_| Response::new(HyperBody::empty()))
    }

    const fn message(self) -> &'static str {
        match self {
            Self::MissingHost => "Bad Request: missing Host header",
            Self::InvalidHost => "Bad Request: invalid Host header",
            Self::InvalidUri => "Bad Request: invalid URI",
        }
    }
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

fn is_h2_preface(buffered: &[u8]) -> bool {
    buffered == H2_PREFACE
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

/// Await both WebSocket upgrade futures, wrap the raw streams in tungstenite
/// frame parsers, then relay frames between client and server while emitting
/// [`ProxyEvent::WebSocketFrame`] events for each one.
///
/// Terminates when either side closes the connection or an error occurs,
/// then emits [`ProxyEvent::WebSocketClosed`].
async fn pump_websocket_frames(
    conn_id: u64,
    client_on_upgrade: hyper::upgrade::OnUpgrade,
    server_on_upgrade: hyper::upgrade::OnUpgrade,
    event_tx: mpsc::Sender<ProxyEvent>,
    #[cfg(feature = "scripting")] script_engine: Option<Arc<crate::scripting::ScriptEngine>>,
) {
    let (client_upgraded, server_upgraded) =
        match tokio::try_join!(client_on_upgrade, server_on_upgrade) {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!("WebSocket upgrade failed for conn_id={conn_id}: {e}");
                return;
            }
        };

    // Proxy acts as server toward the client (expects masked frames, sends unmasked).
    // Proxy acts as client toward the server (sends masked frames, receives unmasked).
    let mut client_ws = WebSocketStream::from_raw_socket(
        TokioIo::new(client_upgraded),
        tokio_tungstenite::tungstenite::protocol::Role::Server,
        None,
    )
    .await;
    let mut server_ws = WebSocketStream::from_raw_socket(
        TokioIo::new(server_upgraded),
        tokio_tungstenite::tungstenite::protocol::Role::Client,
        None,
    )
    .await;

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
pub(crate) async fn handle_replay(
    req: ProxiedRequest,
    mut handler: CapturingHandler,
    client: Arc<Client>,
) {
    let Some(fwd_req) = handler.handle_replayed_request(req).await else {
        return;
    };
    let fwd_req = match to_hyper_request(fwd_req) {
        Ok(request) => request,
        Err(error) => {
            tracing::warn!("Replay request has invalid compatibility headers: {error}");
            handler.emit_synthetic_completion(
                http::StatusCode::BAD_REQUEST,
                http::HeaderMap::new(),
                Bytes::from_static(b"Replay request has invalid headers"),
            );
            return;
        }
    };
    match client.request(prepare_upstream_request(fwd_req)).await {
        Ok(res) => {
            handler
                .record_upstream_response(response_from_protocol_for_capture(from_hyper_response(
                    res,
                )))
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
        let req = Request::builder()
            .uri("http://example.test/ws")
            .header(hyper::header::UPGRADE, "WebSocket")
            .header(hyper::header::CONNECTION, "keep-alive, Upgrade")
            .body(())
            .unwrap();
        assert!(is_websocket_upgrade(&req));

        let missing_connection = Request::builder()
            .uri("http://example.test/ws")
            .header(hyper::header::UPGRADE, "websocket")
            .body(())
            .unwrap();
        assert!(!is_websocket_upgrade(&missing_connection));

        let wrong_upgrade = Request::builder()
            .uri("http://example.test/ws")
            .header(hyper::header::UPGRADE, "h2c")
            .header(hyper::header::CONNECTION, "upgrade")
            .body(())
            .unwrap();
        assert!(!is_websocket_upgrade(&wrong_upgrade));
    }

    #[test]
    fn prepare_upstream_request_removes_host_joins_cookies_and_pins_http11() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://upstream.test/path")
            .version(hyper::Version::HTTP_10)
            .header(hyper::header::HOST, "wrong-host.test")
            .header(hyper::header::COOKIE, "a=1")
            .header(hyper::header::COOKIE, "b=2")
            .body(HyperBody::empty())
            .unwrap();

        let req = prepare_upstream_request(req);

        assert!(!req.headers().contains_key(hyper::header::HOST));
        assert_eq!(
            req.headers().get(hyper::header::COOKIE).unwrap(),
            "a=1; b=2"
        );
        assert_eq!(
            req.headers().get_all(hyper::header::COOKIE).iter().count(),
            1
        );
        assert_eq!(req.version(), hyper::Version::HTTP_11);
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
