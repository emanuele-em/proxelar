use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt as _, Stream, StreamExt as _};
use proxelar_proto::{
    BodyFrame, BoxFuture, ErrorKind, HttpClient, HttpService, ProtocolError, ProxyBody,
    ProxyRequest, ProxyResponse,
};
use proxyapi_models::HeaderBlock;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex as AsyncMutex};
use tokio_quiche::http3::driver::{
    ClientH3Controller, ClientH3Event, H3Event, InboundFrame, InboundFrameStream,
    IncomingH3Headers, NewClientRequest, OutboundFrame, OutboundFrameSender, ServerH3Controller,
    ServerH3Event,
};
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::quic::{connect_with_config, ConnectionHook};
use tokio_quiche::quiche::h3::{Header, NameValue as _};
use tokio_quiche::settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths};
use tokio_quiche::socket::Socket;
use tokio_quiche::{ClientH3Driver, ConnectionParams, QuicConnection};

const DEFAULT_MAX_HEADER_LIST_SIZE: u64 = 64 * 1024;
const DEFAULT_QPACK_TABLE_CAPACITY: u64 = 4 * 1024;
const DEFAULT_QPACK_BLOCKED_STREAMS: u64 = 16;
const DEFAULT_MAX_REQUESTS_PER_CONNECTION: u64 = 1_000;
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) fn default_http3_settings() -> Http3Settings {
    Http3Settings {
        max_requests_per_connection: Some(DEFAULT_MAX_REQUESTS_PER_CONNECTION),
        max_header_list_size: Some(DEFAULT_MAX_HEADER_LIST_SIZE),
        qpack_max_table_capacity: Some(DEFAULT_QPACK_TABLE_CAPACITY),
        qpack_blocked_streams: Some(DEFAULT_QPACK_BLOCKED_STREAMS),
        post_accept_timeout: Some(Duration::from_secs(10)),
        enable_extended_connect: false,
    }
}

#[derive(Clone)]
pub(super) struct ReverseH3Upstream {
    inner: Arc<ReverseH3UpstreamInner>,
}

struct ReverseH3UpstreamInner {
    target: http::Uri,
    verifier: Arc<dyn ServerCertVerifier>,
    tls_cert_path: PathBuf,
    tls_key_path: PathBuf,
    client: AsyncMutex<Option<H3Client>>,
}

impl ReverseH3Upstream {
    pub(super) fn new(
        target: http::Uri,
        verifier: Arc<dyn ServerCertVerifier>,
        tls_cert_path: PathBuf,
        tls_key_path: PathBuf,
    ) -> Self {
        Self {
            inner: Arc::new(ReverseH3UpstreamInner {
                target,
                verifier,
                tls_cert_path,
                tls_key_path,
                client: AsyncMutex::new(None),
            }),
        }
    }

    pub(super) async fn send(&self, request: ProxyRequest) -> Result<ProxyResponse, ProtocolError> {
        let client = {
            let mut state = self.inner.client.lock().await;
            if let Some(client) = state.as_ref() {
                client.clone()
            } else {
                let client = self.connect().await?;
                *state = Some(client.clone());
                client
            }
        };
        match client.request(request).await {
            Ok(response) => Ok(response),
            Err(error) => {
                *self.inner.client.lock().await = None;
                Err(error)
            }
        }
    }

    async fn connect(&self) -> Result<H3Client, ProtocolError> {
        let authority = self
            .inner
            .target
            .authority()
            .ok_or_else(|| malformed("HTTP/3 upstream target has no authority"))?;
        let host = authority.host();
        let port = authority.port_u16().unwrap_or(443);
        let remote_addr = tokio::net::lookup_host((host, port))
            .await
            .map_err(|error| protocol(ErrorKind::Io, error))?
            .next()
            .ok_or_else(|| malformed("HTTP/3 upstream target resolved to no addresses"))?;
        let bind_addr = match remote_addr.ip() {
            IpAddr::V4(_) => (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|error| protocol(ErrorKind::Io, error))?;
        socket
            .connect(remote_addr)
            .await
            .map_err(|error| protocol(ErrorKind::Io, error))?;
        let socket = Socket::try_from(socket).map_err(|error| protocol(ErrorKind::Io, error))?;

        let server_name =
            ServerName::try_from(host.to_owned()).map_err(|error| malformed(error.to_string()))?;
        let hook = RustlsVerificationHook {
            verifier: Arc::clone(&self.inner.verifier),
            server_name,
        };
        let mut quic_settings = QuicSettings::default();
        // QUIC can only carry HTTP/3 here. Keeping this explicit also makes
        // the propagated client ALPN offer deterministic.
        quic_settings.alpn = vec![b"h3".to_vec()];
        quic_settings.enable_dgram = false;
        quic_settings.handshake_timeout = Some(DEFAULT_HANDSHAKE_TIMEOUT);
        // The custom callback below applies the same rustls trust policy used
        // by TCP upstreams, including hostname verification.
        quic_settings.verify_peer = false;
        let cert_path = self
            .inner
            .tls_cert_path
            .to_str()
            .ok_or_else(|| malformed("HTTP/3 TLS certificate path is not UTF-8"))?;
        let key_path = self
            .inner
            .tls_key_path
            .to_str()
            .ok_or_else(|| malformed("HTTP/3 TLS key path is not UTF-8"))?;
        let params = ConnectionParams::new_client(
            quic_settings,
            // tokio-quiche invokes a custom TLS hook only when this optional
            // field is present. The hook supplies the client context and does
            // not load these server credentials as a client certificate.
            Some(TlsCertificatePaths {
                cert: cert_path,
                private_key: key_path,
                kind: CertificateKind::X509,
            }),
            Hooks {
                connection_hook: Some(Arc::new(hook)),
            },
        );
        let (driver, controller) = ClientH3Driver::new(default_http3_settings());
        let connection = connect_with_config(socket, Some(host), &params, driver)
            .await
            .map_err(|error| protocol(ErrorKind::Io, error))?;
        Ok(H3Client::new(connection, controller))
    }
}

#[derive(Debug)]
struct RustlsVerificationHook {
    verifier: Arc<dyn ServerCertVerifier>,
    server_name: ServerName<'static>,
}

impl ConnectionHook for RustlsVerificationHook {
    fn create_custom_ssl_context_builder(
        &self,
        _settings: TlsCertificatePaths<'_>,
    ) -> Option<boring::ssl::SslContextBuilder> {
        use boring::ssl::{SslAlert, SslContextBuilder, SslMethod, SslVerifyError, SslVerifyMode};

        let mut builder = SslContextBuilder::new(SslMethod::tls_client()).ok()?;
        let verifier = Arc::clone(&self.verifier);
        let server_name = self.server_name.clone();
        builder.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
            verify_boring_peer_with_rustls(ssl, verifier.as_ref(), &server_name).map_err(|error| {
                tracing::debug!("HTTP/3 upstream certificate verification failed: {error}");
                SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE)
            })
        });
        Some(builder)
    }
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

pub(super) async fn serve_connection<S>(
    _connection: QuicConnection,
    mut controller: ServerH3Controller,
    service: S,
) -> Result<(), ProtocolError>
where
    S: HttpService + Clone + 'static,
{
    while let Some(event) = controller.event_receiver_mut().recv().await {
        match event {
            ServerH3Event::Headers {
                incoming_headers, ..
            } => {
                let request_service = service.clone();
                tokio::spawn(async move {
                    handle_server_request(request_service, incoming_headers).await;
                });
            }
            ServerH3Event::Core(H3Event::ConnectionError(error)) => {
                return Err(protocol(ErrorKind::ProtocolViolation, error));
            }
            ServerH3Event::Core(H3Event::ConnectionShutdown(error)) => {
                return error.map_or(Ok(()), |error| Err(protocol(ErrorKind::Io, error)));
            }
            ServerH3Event::Core(_) => {}
        }
    }
    Ok(())
}

async fn handle_server_request<S>(mut service: S, incoming: IncomingH3Headers)
where
    S: HttpService,
{
    let IncomingH3Headers {
        headers,
        send,
        recv,
        read_fin,
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
    let body = if read_fin {
        ProxyBody::empty()
    } else {
        inbound_body(recv)
    };
    match service.call(ProxyRequest::new(head, body)).await {
        Ok(response) => {
            if let Err(error) = send_response(send, response).await {
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
) -> Result<(), ProtocolError> {
    let (head, body) = response.into_parts();
    let headers = encode_response_headers(&head)?;
    send.send(OutboundFrame::Headers(headers, None))
        .await
        .map_err(|error| protocol(ErrorKind::Io, error))?;
    send_body(send, body).await
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
                send.send(OutboundFrame::Trailers(trailers, None))
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
                    Poll::Ready(Some(Ok(BodyFrame::Data(data.freeze()))))
                }
            }
            Poll::Ready(Some(InboundFrame::Datagram(_))) => {
                self.finished = true;
                Poll::Ready(Some(Err(ProtocolError::new(
                    ErrorKind::ProtocolViolation,
                    "HTTP/3 DATAGRAM arrived on an HTTP body stream",
                ))))
            }
            Poll::Ready(None) => {
                self.finished = true;
                Poll::Ready(None)
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
    .with_trailer_hint(false)
}

type ResponseSender = oneshot::Sender<Result<ProxyResponse, ProtocolError>>;

#[derive(Default)]
struct ClientState {
    pending: HashMap<u64, ResponseSender>,
    streams: HashMap<u64, u64>,
}

#[derive(Clone)]
pub(super) struct H3Client {
    _connection: Arc<QuicConnection>,
    request_sender: tokio_quiche::http3::driver::ClientRequestSender,
    state: Arc<Mutex<ClientState>>,
    next_request_id: Arc<AtomicU64>,
}

impl H3Client {
    pub(super) fn new(connection: QuicConnection, controller: ClientH3Controller) -> Self {
        let request_sender = controller.request_sender();
        let state = Arc::new(Mutex::new(ClientState::default()));
        tokio::spawn(dispatch_client_events(controller, Arc::clone(&state)));
        Self {
            _connection: Arc::new(connection),
            request_sender,
            state,
            next_request_id: Arc::new(AtomicU64::new(1)),
        }
    }

    pub(super) async fn request(
        &self,
        request: ProxyRequest,
    ) -> Result<ProxyResponse, ProtocolError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let (head, body) = request.into_parts();
        let headers = encode_request_headers(&head)?;
        let body_is_empty = body.exact_length() == Some(0) && !body.may_have_trailers();
        let (body_writer, body_receiver) = if body_is_empty {
            (None, None)
        } else {
            let (writer, receiver) = oneshot::channel();
            (Some(writer), Some(receiver))
        };
        let (response_sender, response_receiver) = oneshot::channel();
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .pending
            .insert(request_id, response_sender);

        if let Err(error) = self.request_sender.send(NewClientRequest {
            request_id,
            headers,
            body_writer,
        }) {
            self.state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pending
                .remove(&request_id);
            return Err(protocol(ErrorKind::Io, error));
        }

        if let Some(body_receiver) = body_receiver {
            tokio::spawn(async move {
                if let Ok(send) = body_receiver.await {
                    if let Err(error) = send_body(send, body).await {
                        tracing::debug!("HTTP/3 request body stream failed: {error}");
                    }
                }
            });
        }

        response_receiver
            .await
            .map_err(|error| protocol(ErrorKind::Io, error))?
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

async fn dispatch_client_events(
    mut controller: ClientH3Controller,
    state: Arc<Mutex<ClientState>>,
) {
    while let Some(event) = controller.event_receiver_mut().recv().await {
        match event {
            ClientH3Event::NewOutboundRequest {
                stream_id,
                request_id,
            } => {
                state
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .streams
                    .insert(stream_id, request_id);
            }
            ClientH3Event::Core(H3Event::IncomingHeaders(incoming)) => {
                dispatch_response(&state, incoming);
            }
            ClientH3Event::Core(H3Event::ResetStream { stream_id }) => {
                fail_stream(&state, stream_id, "HTTP/3 stream was reset");
            }
            ClientH3Event::Core(H3Event::StreamClosed { stream_id }) => {
                fail_stream(
                    &state,
                    stream_id,
                    "HTTP/3 stream closed before response headers",
                );
            }
            ClientH3Event::Core(H3Event::ConnectionError(error)) => {
                fail_all(&state, format!("HTTP/3 connection error: {error}"));
                return;
            }
            ClientH3Event::Core(H3Event::ConnectionShutdown(error)) => {
                fail_all(
                    &state,
                    error.map_or_else(
                        || "HTTP/3 connection closed".to_owned(),
                        |error| format!("HTTP/3 connection closed: {error}"),
                    ),
                );
                return;
            }
            ClientH3Event::Core(_) => {}
        }
    }
    fail_all(&state, "HTTP/3 driver stopped".to_owned());
}

fn dispatch_response(state: &Arc<Mutex<ClientState>>, incoming: IncomingH3Headers) {
    let request_id = {
        let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
        state.streams.remove(&incoming.stream_id)
    };
    let Some(request_id) = request_id else {
        return;
    };
    let sender = state
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .pending
        .remove(&request_id);
    let Some(sender) = sender else {
        return;
    };
    let result = decode_response_headers(&incoming.headers).map(|head| {
        let body = if incoming.read_fin {
            ProxyBody::empty()
        } else {
            inbound_body(incoming.recv)
        };
        ProxyResponse::new(head, body)
    });
    let _ = sender.send(result);
}

fn fail_stream(state: &Arc<Mutex<ClientState>>, stream_id: u64, message: &'static str) {
    let sender = {
        let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
        state
            .streams
            .remove(&stream_id)
            .and_then(|request_id| state.pending.remove(&request_id))
    };
    if let Some(sender) = sender {
        let _ = sender.send(Err(ProtocolError::new(ErrorKind::Reset, message)));
    }
}

fn fail_all(state: &Arc<Mutex<ClientState>>, message: String) {
    let pending = {
        let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
        state.streams.clear();
        state
            .pending
            .drain()
            .map(|(_, sender)| sender)
            .collect::<Vec<_>>()
    };
    for sender in pending {
        let _ = sender.send(Err(ProtocolError::new(ErrorKind::Io, message.clone())));
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
    use tokio::sync::mpsc;
    use tokio_util::sync::PollSender;

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
    fn response_headers_and_qpack_limits_are_strict() {
        let mut headers = HeaderBlock::new();
        headers.add("set-cookie", "a=1").unwrap();
        headers.add("set-cookie", "b=2").unwrap();
        let head = ResponseHead::new(http::StatusCode::OK, http::Version::HTTP_11, headers);

        let decoded = decode_response_headers(&encode_response_headers(&head).unwrap()).unwrap();
        assert_eq!(decoded.version, http::Version::HTTP_3);
        assert_eq!(decoded.headers.get_all("set-cookie").count(), 2);

        let settings = default_http3_settings();
        assert_eq!(settings.max_header_list_size, Some(64 * 1024));
        assert_eq!(settings.qpack_max_table_capacity, Some(4 * 1024));
        assert_eq!(settings.qpack_blocked_streams, Some(16));
        assert!(!settings.enable_extended_connect);
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
            Some(OutboundFrame::Trailers(headers, None))
                if headers[0].name() == b"x-checksum" && headers[0].value() == b"ok"
        ));
        send_task.await.unwrap().unwrap();
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
}
