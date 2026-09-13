use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt as _, Stream, StreamExt as _};
use http::uri::Authority;
use http::{Method, StatusCode, Uri, Version};
use proxelar_proto::{
    BodyFrame, BoxFuture, ErrorKind, HttpClient, HttpService, ProtocolError, ProxyBody,
    ProxyRequest, ProxyResponse,
};
use proxyapi_models::{HeaderBlock, ProxiedResponse};
use quiche::h3::{Header, NameValue as _};
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::{oneshot, Mutex as AsyncMutex};
use tokio_util::sync::PollSender;

mod driver;
pub(super) use driver::H3Listener;
use driver::{InboundFrame, IncomingH3Headers, OutboundFrame};
type OutboundFrameSender = PollSender<OutboundFrame>;
type InboundFrameStream = mpsc::Receiver<InboundFrame>;

use crate::HttpHandler as _;

const DEFAULT_MAX_HEADER_LIST_SIZE: u64 = 64 * 1024;
const DEFAULT_QPACK_TABLE_CAPACITY: u64 = 4 * 1024;
const DEFAULT_QPACK_BLOCKED_STREAMS: u64 = 16;
const DEFAULT_MAX_REQUESTS_PER_CONNECTION: u64 = 1_000;
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const WEBSOCKET_TUNNEL_CAPACITY: usize = 64 * 1024;

fn default_http3_settings() -> Result<quiche::h3::Config, ProtocolError> {
    let mut config = quiche::h3::Config::new().map_err(|e| protocol(ErrorKind::Io, e))?;
    config.set_max_field_section_size(DEFAULT_MAX_HEADER_LIST_SIZE);
    config.set_qpack_max_table_capacity(DEFAULT_QPACK_TABLE_CAPACITY);
    config.set_qpack_blocked_streams(DEFAULT_QPACK_BLOCKED_STREAMS);
    config.enable_extended_connect(true);
    Ok(config)
}

#[derive(Clone)]
pub(super) struct ReverseH3Upstream {
    inner: Arc<ReverseH3UpstreamInner>,
}

struct ReverseH3UpstreamInner {
    target: http::Uri,
    remote_addr: Option<SocketAddr>,
    verifier: Arc<dyn ServerCertVerifier>,
    client: AsyncMutex<Option<Arc<H3Client>>>,
}

fn h3_error_closes_connection(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::Io | ErrorKind::Timeout | ErrorKind::ProtocolViolation
    )
}

fn clear_if_current<T>(cached: &mut Option<Arc<T>>, failed: &Arc<T>) {
    if cached
        .as_ref()
        .is_some_and(|current| Arc::ptr_eq(current, failed))
    {
        *cached = None;
    }
}

impl ReverseH3Upstream {
    pub(super) fn new(target: http::Uri, verifier: Arc<dyn ServerCertVerifier>) -> Self {
        Self::with_remote_addr(target, verifier, None)
    }

    pub(super) fn new_with_remote(
        target: http::Uri,
        verifier: Arc<dyn ServerCertVerifier>,
        remote_addr: SocketAddr,
    ) -> Self {
        Self::with_remote_addr(target, verifier, Some(remote_addr))
    }

    fn with_remote_addr(
        target: http::Uri,
        verifier: Arc<dyn ServerCertVerifier>,
        remote_addr: Option<SocketAddr>,
    ) -> Self {
        Self {
            inner: Arc::new(ReverseH3UpstreamInner {
                target,
                remote_addr,
                verifier,
                client: AsyncMutex::new(None),
            }),
        }
    }

    pub(super) async fn send(&self, request: ProxyRequest) -> Result<ProxyResponse, ProtocolError> {
        let client = {
            let mut state = self.inner.client.lock().await;
            if let Some(client) = state.as_ref().filter(|client| !client.requests.is_closed()) {
                client.clone()
            } else {
                let client = Arc::new(self.connect().await?);
                *state = Some(client.clone());
                client
            }
        };
        let result = client.request(request).await;
        if result
            .as_ref()
            .is_err_and(|error| h3_error_closes_connection(error.kind()))
        {
            let mut state = self.inner.client.lock().await;
            clear_if_current(&mut state, &client);
        }
        result
    }

    async fn connect(&self) -> Result<H3Client, ProtocolError> {
        let authority = self
            .inner
            .target
            .authority()
            .ok_or_else(|| malformed("HTTP/3 upstream target has no authority"))?;
        let host = authority.host();
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        let port = authority.port_u16().unwrap_or(443);
        let remote_addrs = match self.inner.remote_addr {
            Some(remote_addr) => vec![remote_addr],
            None => tokio::net::lookup_host((host, port))
                .await
                .map_err(|error| protocol(ErrorKind::Io, error))?
                .collect(),
        };

        connect_h3_candidates(remote_addrs, |remote_addr| {
            connect_h3_candidate(remote_addr, host, Arc::clone(&self.inner.verifier))
        })
        .await
    }
}

async fn connect_h3_candidates<T, I, F, Fut>(
    candidates: I,
    mut connect: F,
) -> Result<T, ProtocolError>
where
    I: IntoIterator<Item = SocketAddr>,
    F: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = Result<T, ProtocolError>>,
{
    let mut last_error = None;
    for remote_addr in candidates {
        match connect(remote_addr).await {
            Ok(connection) => return Ok(connection),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| malformed("HTTP/3 upstream target resolved to no addresses")))
}

async fn connect_h3_candidate(
    remote_addr: SocketAddr,
    host: &str,
    verifier: Arc<dyn ServerCertVerifier>,
) -> Result<H3Client, ProtocolError> {
    use boring::ssl::{SslAlert, SslContextBuilder, SslMethod, SslVerifyError, SslVerifyMode};
    let bind_addr = match remote_addr.ip() {
        IpAddr::V4(_) => (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| protocol(ErrorKind::Io, e))?;
    let server_name =
        ServerName::try_from(host.to_owned()).map_err(|e| malformed(e.to_string()))?;
    let mut tls =
        SslContextBuilder::new(SslMethod::tls_client()).map_err(|e| protocol(ErrorKind::Io, e))?;
    tls.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
        verify_boring_peer_with_rustls(ssl, verifier.as_ref(), &server_name).map_err(|error| {
            tracing::debug!("HTTP/3 upstream certificate verification failed: {error}");
            SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE)
        })
    });
    let mut config = driver::transport_config(tls)?;
    let id = driver::connection_id()?;
    let connection = quiche::connect(
        Some(host),
        &id,
        socket
            .local_addr()
            .map_err(|e| protocol(ErrorKind::Io, e))?,
        remote_addr,
        &mut config,
    )
    .map_err(|e| protocol(ErrorKind::Io, e))?;
    driver::connect(socket, connection).await
}

pub(super) fn server_config(
    ca: Arc<crate::ca::Ssl>,
    authority: Authority,
    dynamic: bool,
) -> Result<quiche::Config, ProtocolError> {
    use boring::ssl::{NameType, SelectCertError, SslContextBuilder, SslMethod};
    let mut tls =
        SslContextBuilder::new(SslMethod::tls_server()).map_err(|e| protocol(ErrorKind::Io, e))?;
    let material = ca
        .gen_h3_certificate(&authority)
        .map_err(|e| protocol(ErrorKind::Io, e))?;
    let certificate = boring::x509::X509::from_pem(&material.certificate_pem)
        .map_err(|e| protocol(ErrorKind::Io, e))?;
    let key = boring::pkey::PKey::private_key_from_pem(&material.private_key_pem)
        .map_err(|e| protocol(ErrorKind::Io, e))?;
    tls.set_certificate(&certificate)
        .map_err(|e| protocol(ErrorKind::Io, e))?;
    tls.set_private_key(&key)
        .map_err(|e| protocol(ErrorKind::Io, e))?;
    if dynamic {
        tls.set_select_certificate_callback(move |mut hello| {
            let authority = hello
                .servername(NameType::HOST_NAME)
                .and_then(|name| name.parse::<Authority>().ok())
                .unwrap_or_else(|| authority.clone());
            let material = ca.gen_h3_certificate(&authority).map_err(|error| {
                tracing::debug!("HTTP/3 certificate generation failed for {authority}: {error}");
                SelectCertError::ERROR
            })?;
            let certificate = boring::x509::X509::from_pem(&material.certificate_pem)
                .map_err(|_| SelectCertError::ERROR)?;
            let key = boring::pkey::PKey::private_key_from_pem(&material.private_key_pem)
                .map_err(|_| SelectCertError::ERROR)?;
            hello
                .ssl_mut()
                .set_certificate(&certificate)
                .map_err(|_| SelectCertError::ERROR)?;
            hello
                .ssl_mut()
                .set_private_key(&key)
                .map_err(|_| SelectCertError::ERROR)
        });
    }
    driver::transport_config(tls)
}

fn verify_boring_peer_with_rustls(
    ssl: &mut boring::ssl::SslRef,
    verifier: &dyn ServerCertVerifier,
    server_name: &ServerName<'static>,
) -> Result<(), String> {
    let chain = ssl
        .peer_cert_chain()
        .ok_or_else(|| "server did not provide a certificate chain".to_owned())?;
    let certificates = chain
        .iter()
        .map(|certificate| {
            certificate
                .to_der()
                .map(CertificateDer::from)
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (end_entity, intermediates) = certificates
        .split_first()
        .ok_or_else(|| "server provided an empty certificate chain".to_owned())?;
    verifier
        .verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ssl.ocsp_status().unwrap_or_default(),
            UnixTime::now(),
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
}

pub(super) fn encode_request_headers(
    head: &proxelar_proto::RequestHead,
) -> Result<Vec<Header>, ProtocolError> {
    let block = proxelar_proto::http2::encode_request_head(head)?;
    Ok(to_quiche_headers(&block))
}

pub(super) fn decode_request_headers(
    headers: &[Header],
) -> Result<proxelar_proto::RequestHead, ProtocolError> {
    let block = from_quiche_headers(headers)?;
    let mut head = proxelar_proto::http2::decode_request_head(&block)?;
    head.version = http::Version::HTTP_3;
    Ok(head)
}

pub(super) fn encode_response_headers(
    head: &proxelar_proto::ResponseHead,
) -> Result<Vec<Header>, ProtocolError> {
    let block = proxelar_proto::http2::encode_response_head(head)?;
    Ok(to_quiche_headers(&block))
}

pub(super) fn decode_response_headers(
    headers: &[Header],
) -> Result<proxelar_proto::ResponseHead, ProtocolError> {
    let block = from_quiche_headers(headers)?;
    let mut head = proxelar_proto::http2::decode_response_head(&block)?;
    head.version = http::Version::HTTP_3;
    Ok(head)
}

fn encode_trailers(trailers: &HeaderBlock) -> Result<Vec<Header>, ProtocolError> {
    proxelar_proto::http2::to_h2_trailers(trailers)?;
    let normalized = HeaderBlock::from_fields(trailers.iter().map(|field| {
        proxyapi_models::HeaderField::new(field.name().to_ascii_lowercase(), field.value())
            .expect("validated HTTP trailer field remains valid when lowercased")
    }));
    Ok(to_quiche_headers(&normalized))
}

fn from_quiche_headers(headers: &[Header]) -> Result<HeaderBlock, ProtocolError> {
    let mut block = HeaderBlock::new();
    for header in headers {
        block
            .add(header.name(), header.value())
            .map_err(|error| ProtocolError::new(ErrorKind::MalformedMessage, error.to_string()))?;
    }
    Ok(block)
}

fn to_quiche_headers(headers: &HeaderBlock) -> Vec<Header> {
    headers
        .iter()
        .map(|field| Header::new(field.name(), field.value()))
        .collect()
}

async fn handle_server_request<S>(mut service: S, incoming: IncomingH3Headers)
where
    S: HttpService,
{
    let IncomingH3Headers {
        headers,
        send,
        recv,
        ..
    } = incoming;
    let head = match decode_request_headers(&headers) {
        Ok(head) => head,
        Err(error) => {
            tracing::debug!("Rejecting malformed HTTP/3 request: {error}");
            send_stream_error(send).await;
            return;
        }
    };
    let request_method = head.method.clone();
    let body = inbound_body(recv);
    match service.call(ProxyRequest::new(head, body)).await {
        Ok(response) => {
            if let Err(error) = send_response(send, response, &request_method).await {
                tracing::debug!("HTTP/3 response stream failed: {error}");
            }
        }
        Err(error) => {
            tracing::debug!("HTTP/3 service rejected request: {error}");
            send_stream_error(send).await;
        }
    }
}

async fn send_response(
    mut send: OutboundFrameSender,
    response: ProxyResponse,
    request_method: &Method,
) -> Result<(), ProtocolError> {
    let (informational, head, body) = response.into_parts();
    for informational in informational {
        if !informational.status.is_informational()
            || informational.status == StatusCode::SWITCHING_PROTOCOLS
        {
            return Err(ProtocolError::new(
                ErrorKind::ProtocolViolation,
                "HTTP/3 informational response must be 1xx other than 101",
            ));
        }
        let headers = encode_response_headers(&informational)?;
        send.send(OutboundFrame::Headers(headers))
            .await
            .map_err(|error| protocol(ErrorKind::Io, error))?;
    }
    let headers = encode_response_headers(&head)?;
    send.send(OutboundFrame::Headers(headers))
        .await
        .map_err(|error| protocol(ErrorKind::Io, error))?;
    if proxelar_proto::response_body_is_forbidden(request_method, head.status) {
        send.send(OutboundFrame::Body(Bytes::new(), true))
            .await
            .map_err(|error| protocol(ErrorKind::Io, error))
    } else {
        send_body(send, body).await
    }
}

async fn send_body(
    mut send: OutboundFrameSender,
    mut body: ProxyBody,
) -> Result<(), ProtocolError> {
    while let Some(frame) = body.next().await {
        match frame? {
            BodyFrame::Data(data) => send
                .send(OutboundFrame::Body(data, false))
                .await
                .map_err(|error| protocol(ErrorKind::Io, error))?,
            BodyFrame::Trailers(trailers) => {
                let trailers = encode_trailers(&trailers)?;
                send.send(OutboundFrame::Trailers(trailers))
                    .await
                    .map_err(|error| protocol(ErrorKind::Io, error))?;
                return Ok(());
            }
        }
    }
    send.send(OutboundFrame::Body(Bytes::new(), true))
        .await
        .map_err(|error| protocol(ErrorKind::Io, error))
}

async fn send_stream_error(mut send: OutboundFrameSender) {
    let _ = send.send(OutboundFrame::PeerStreamError).await;
}

struct H3BodyStream {
    recv: InboundFrameStream,
    finished: bool,
}

impl Stream for H3BodyStream {
    type Item = Result<BodyFrame, ProtocolError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.finished {
            return Poll::Ready(None);
        }
        match self.recv.poll_recv(context) {
            Poll::Ready(Some(InboundFrame::Body(data, fin))) => {
                self.finished = fin;
                if data.is_empty() && fin {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Ok(BodyFrame::Data(data))))
                }
            }
            Poll::Ready(Some(InboundFrame::Trailers(trailers))) => {
                Poll::Ready(Some(Ok(BodyFrame::Trailers(trailers))))
            }
            Poll::Ready(Some(InboundFrame::Error(error))) => {
                self.finished = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                self.finished = true;
                Poll::Ready(Some(Err(ProtocolError::new(
                    ErrorKind::Reset,
                    "HTTP/3 body stream closed before FIN",
                ))))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

fn inbound_body(recv: InboundFrameStream) -> ProxyBody {
    ProxyBody::new(H3BodyStream {
        recv,
        finished: false,
    })
}

pub(super) fn is_extended_websocket(request: &ProxyRequest) -> bool {
    request.head.method == Method::CONNECT
        && request
            .head
            .headers
            .get(":protocol")
            .is_some_and(|value| value.eq_ignore_ascii_case(b"websocket"))
}

pub(super) async fn handle_extended_websocket<F, Fut>(
    mut request: ProxyRequest,
    mut handler: crate::handler::CapturingHandler,
    remote_addr: SocketAddr,
    reverse_target: Option<Uri>,
    send_upstream: F,
) -> Result<ProxyResponse, ProtocolError>
where
    F: FnOnce(ProxyRequest) -> Fut,
    Fut: Future<Output = Result<ProxyResponse, ProtocolError>>,
{
    let inbound = std::mem::replace(&mut request.body, ProxyBody::empty());
    // The compatibility hook adapter uses `http::HeaderMap`, which cannot
    // represent pseudo-headers. Restore the already-validated protocol after
    // the request hook, matching the RFC 8441 path.
    request.head.headers.remove(":protocol");
    let context = crate::HttpContext { remote_addr };
    let mut request = match handler.handle_request(&context, request).await {
        crate::RequestOrResponse::Request(request) => request,
        crate::RequestOrResponse::Response(response) => return Ok(response),
    };
    request.body = inbound;
    set_header(&mut request.head.headers, ":protocol", "websocket")?;
    if !is_extended_websocket(&request)
        || request.head.headers.get("sec-websocket-version") != Some(b"13".as_slice())
    {
        return Ok(handler.synthetic_protocol_response(
            StatusCode::BAD_REQUEST,
            http::HeaderMap::new(),
            Bytes::from_static(b"Invalid RFC 9220 WebSocket request"),
        ));
    }
    if let Some(target) = reverse_target {
        request = match super::reverse::rewrite_uri(request, &target) {
            Ok(request) => request,
            Err(error) => {
                tracing::debug!("Failed to rewrite RFC 9220 WebSocket URI: {error}");
                return Ok(handler.synthetic_protocol_response(
                    StatusCode::BAD_GATEWAY,
                    http::HeaderMap::new(),
                    Bytes::from_static(b"Bad Gateway: URI rewrite failed"),
                ));
            }
        };
    }

    let inbound = std::mem::replace(&mut request.body, ProxyBody::empty());
    let (server_tunnel, upstream_body, upstream_response) =
        proxelar_proto::http2::websocket_body_tunnel(WEBSOCKET_TUNNEL_CAPACITY);
    request.body = upstream_body;
    let response = match send_upstream(request).await {
        Ok(response) => response,
        Err(error) => {
            tracing::debug!("RFC 9220 upstream handshake failed: {error}");
            return Ok(handler.synthetic_protocol_response(
                StatusCode::BAD_GATEWAY,
                http::HeaderMap::new(),
                Bytes::from_static(b"Bad Gateway"),
            ));
        }
    };
    if !response.head.status.is_success() {
        return Ok(handler.handle_response(&context, response).await);
    }

    let (informational, mut head, body) = response.into_parts();
    if upstream_response.send(body).is_err() {
        return Ok(handler.synthetic_protocol_response(
            StatusCode::BAD_GATEWAY,
            http::HeaderMap::new(),
            Bytes::from_static(b"Bad Gateway: WebSocket response stream unavailable"),
        ));
    }
    let (client_tunnel, outbound) =
        proxelar_proto::http2::body_tunnel(inbound, WEBSOCKET_TUNNEL_CAPACITY);
    for name in [
        b"content-length".as_slice(),
        b"transfer-encoding".as_slice(),
    ] {
        head.headers.remove(name);
    }
    head.version = Version::HTTP_3;
    let connected = ProxiedResponse::new(
        head.status,
        Version::HTTP_3,
        head.headers.clone(),
        Bytes::new(),
        crate::handler::now_millis(),
    );
    let connection_id = handler
        .take_pending_id()
        .unwrap_or_else(crate::event::next_id);
    if let Some(captured_request) = handler.take_captured_request() {
        handler.send_event(crate::event::ProxyEvent::WebSocketConnected {
            id: connection_id,
            request: Box::new(captured_request),
            response: Box::new(connected),
        });
    }
    tokio::spawn(super::forward::pump_websocket_streams(
        connection_id,
        client_tunnel,
        server_tunnel,
        handler,
    ));
    Ok(ProxyResponse::new(head, outbound).with_informational(informational))
}

fn set_header(
    headers: &mut HeaderBlock,
    name: &str,
    value: impl AsRef<[u8]>,
) -> Result<(), ProtocolError> {
    headers
        .set(name, value)
        .map_err(|error| malformed(error.to_string()))
}

#[derive(Clone)]
pub(super) struct H3Client {
    requests: mpsc::Sender<driver::ClientRequest>,
}

impl H3Client {
    pub(super) async fn request(
        &self,
        request: ProxyRequest,
    ) -> Result<ProxyResponse, ProtocolError> {
        let (response, received) = oneshot::channel();
        self.requests
            .send(driver::ClientRequest { request, response })
            .await
            .map_err(|_| protocol(ErrorKind::Io, "HTTP/3 driver stopped"))?;
        received
            .await
            .map_err(|_| protocol(ErrorKind::Io, "HTTP/3 connection closed"))?
    }
}

impl HttpClient for H3Client {
    fn send(
        &mut self,
        request: ProxyRequest,
    ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
        Box::pin(self.request(request))
    }
}

fn protocol(kind: ErrorKind, error: impl std::fmt::Display) -> ProtocolError {
    ProtocolError::new(kind, error.to_string())
}

fn malformed(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ErrorKind::MalformedMessage, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxelar_proto::{RequestHead, ResponseHead};
    use std::sync::Mutex;
    use tokio::sync::mpsc;
    use tokio_util::sync::PollSender;

    #[test]
    fn h3_stream_errors_do_not_evict_the_connection() {
        assert!(!h3_error_closes_connection(ErrorKind::Reset));
        assert!(!h3_error_closes_connection(ErrorKind::MalformedMessage));
        assert!(!h3_error_closes_connection(ErrorKind::Unsupported));
        assert!(h3_error_closes_connection(ErrorKind::Io));
        assert!(h3_error_closes_connection(ErrorKind::Timeout));
        assert!(h3_error_closes_connection(ErrorKind::ProtocolViolation));
    }

    #[test]
    fn stale_h3_failure_does_not_remove_a_newer_connection() {
        let current = Arc::new(());
        let stale = Arc::new(());
        let mut cached = Some(Arc::clone(&current));

        clear_if_current(&mut cached, &stale);
        assert!(cached
            .as_ref()
            .is_some_and(|cached| Arc::ptr_eq(cached, &current)));

        clear_if_current(&mut cached, &current);
        assert!(cached.is_none());
    }

    #[tokio::test]
    async fn h3_connect_tries_candidates_in_resolver_order() {
        let first: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let second: SocketAddr = "[::1]:443".parse().unwrap();
        let attempts = Arc::new(Mutex::new(Vec::new()));

        let connected = connect_h3_candidates([first, second], {
            let attempts = Arc::clone(&attempts);
            move |candidate| {
                let attempts = Arc::clone(&attempts);
                async move {
                    attempts
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .push(candidate);
                    if candidate == first {
                        Err(protocol(ErrorKind::Io, "first handshake failed"))
                    } else {
                        Ok(candidate)
                    }
                }
            }
        })
        .await
        .unwrap();

        assert_eq!(connected, second);
        assert_eq!(
            *attempts.lock().unwrap_or_else(|error| error.into_inner()),
            vec![first, second]
        );
    }

    #[test]
    fn request_headers_roundtrip_h3_pseudo_fields_and_ordered_duplicates() {
        let mut headers = HeaderBlock::new();
        headers.add("X-First", "one").unwrap();
        headers.add("x-repeat", [0x80, 0xff]).unwrap();
        headers.add("x-repeat", "last").unwrap();
        let head = RequestHead::new(
            http::Method::POST,
            "https://example.test/upload?q=1".parse().unwrap(),
            http::Version::HTTP_11,
            headers,
        );

        let encoded = encode_request_headers(&head).unwrap();
        let decoded = decode_request_headers(&encoded).unwrap();

        assert_eq!(decoded.version, http::Version::HTTP_3);
        assert_eq!(decoded.method, http::Method::POST);
        assert_eq!(decoded.uri, head.uri);
        assert_eq!(
            decoded.headers.get_all("x-repeat").collect::<Vec<_>>(),
            vec![&[0x80, 0xff][..], b"last".as_slice()]
        );
        assert!(decoded
            .headers
            .iter()
            .all(|field| field.name().iter().all(|byte| !byte.is_ascii_uppercase())));
    }

    #[test]
    fn response_headers_roundtrip_ordered_duplicates() {
        let mut headers = HeaderBlock::new();
        headers.add("set-cookie", "a=1").unwrap();
        headers.add("set-cookie", "b=2").unwrap();
        let head = ResponseHead::new(http::StatusCode::OK, http::Version::HTTP_11, headers);

        let decoded = decode_response_headers(&encode_response_headers(&head).unwrap()).unwrap();
        assert_eq!(decoded.version, http::Version::HTTP_3);
        assert_eq!(decoded.headers.get_all("set-cookie").count(), 2);
    }

    #[tokio::test]
    async fn outbound_body_preserves_data_trailers_and_channel_backpressure() {
        let (sender, mut receiver) = mpsc::channel(1);
        let sender = PollSender::new(sender);
        let mut trailers = HeaderBlock::new();
        trailers.add("X-Checksum", "ok").unwrap();
        let body = ProxyBody::from_frames([
            Ok(BodyFrame::Data(Bytes::from_static(b"payload"))),
            Ok(BodyFrame::Trailers(trailers)),
        ]);

        let send_task = tokio::spawn(send_body(sender, body));
        assert!(matches!(
            receiver.recv().await,
            Some(OutboundFrame::Body(data, false)) if data == b"payload".as_slice()
        ));
        assert!(matches!(
            receiver.recv().await,
            Some(OutboundFrame::Trailers(headers))
                if headers[0].name() == b"x-checksum" && headers[0].value() == b"ok"
        ));
        send_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn response_sender_suppresses_semantically_forbidden_bodies() {
        for (method, status) in [
            (Method::HEAD, StatusCode::OK),
            (Method::GET, StatusCode::NO_CONTENT),
            (Method::GET, StatusCode::RESET_CONTENT),
            (Method::GET, StatusCode::NOT_MODIFIED),
        ] {
            let (sender, mut receiver) = mpsc::channel(4);
            send_response(
                PollSender::new(sender),
                ProxyResponse::new(
                    ResponseHead::new(status, Version::HTTP_3, HeaderBlock::new()),
                    ProxyBody::full(Bytes::from_static(b"forbidden response body")),
                ),
                &method,
            )
            .await
            .unwrap();

            assert!(matches!(
                receiver.recv().await,
                Some(OutboundFrame::Headers(_))
            ));
            assert!(matches!(
                receiver.recv().await,
                Some(OutboundFrame::Body(data, true)) if data.is_empty()
            ));
            assert!(receiver.recv().await.is_none());
        }
    }

    #[tokio::test]
    async fn inbound_body_streams_chunks_until_fin() {
        let (sender, receiver) = mpsc::channel(1);
        let mut body = inbound_body(receiver);
        sender
            .send(InboundFrame::Body(b"one".as_slice().into(), false))
            .await
            .unwrap();
        assert!(matches!(
            body.next().await,
            Some(Ok(BodyFrame::Data(data))) if data == b"one".as_slice()
        ));
        sender
            .send(InboundFrame::Body(b"two".as_slice().into(), true))
            .await
            .unwrap();
        assert!(matches!(
            body.next().await,
            Some(Ok(BodyFrame::Data(data))) if data == b"two".as_slice()
        ));
        assert!(body.next().await.is_none());
    }

    #[tokio::test]
    async fn inbound_body_rejects_channel_close_before_fin() {
        let (sender, receiver) = mpsc::channel(1);
        let mut body = inbound_body(receiver);

        sender
            .send(InboundFrame::Body(b"partial".as_slice().into(), false))
            .await
            .unwrap();
        assert!(matches!(
            body.next().await,
            Some(Ok(BodyFrame::Data(data))) if data == b"partial".as_slice()
        ));

        drop(sender);
        let error = body.next().await.unwrap().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Reset);
        assert!(body.next().await.is_none());
    }
}

#[cfg(test)]
#[path = "tests/http3.rs"]
mod failure_tests;
