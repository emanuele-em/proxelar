use std::collections::HashMap;
use std::hash::Hash;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf as _, BytesMut};
use futures_core::Stream;
use futures_util::StreamExt as _;
use http::{Method, StatusCode, Version};
use tokio::io::{
    split, AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadHalf, WriteHalf,
};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::timeout;

use crate::{
    BodyResult, BoxFuture, ErrorKind, HttpClient as HttpClientTrait, HttpService, ProtocolError,
    ProxyBody, ProxyRequest, ProxyResponse,
};

use super::{
    encode_request_head, encode_response_head, BodyDecodeStatus, BodyDecoder, BodyDecoderLimits,
    BodyEncoder, BodyFraming, HeadParser, HeadParserLimits, Http1Error, ParseStatus,
};

/// Runtime limits and timeouts shared by client and server HTTP/1 drivers.
#[derive(Clone, Copy, Debug)]
pub struct ConnectionConfig {
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub service_timeout: Duration,
    pub pipeline_capacity: usize,
    pub body_channel_capacity: usize,
    pub head_limits: HeadParserLimits,
    pub body_limits: BodyDecoderLimits,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            service_timeout: Duration::from_secs(60),
            pipeline_capacity: 16,
            body_channel_capacity: 1,
            head_limits: HeadParserLimits::default(),
            body_limits: BodyDecoderLimits::default(),
        }
    }
}

struct InboundRequest {
    request: ProxyRequest,
    close_after_response: bool,
}

/// Serve one HTTP/1 connection. Requests may be read ahead into a bounded
/// pipeline, while responses are always emitted in request order.
pub async fn serve_connection<I, S>(
    io: I,
    mut service: S,
    config: ConnectionConfig,
) -> Result<(), ProtocolError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: HttpService,
{
    let (reader, mut writer) = split(io);
    let (request_tx, mut request_rx) = mpsc::channel(config.pipeline_capacity.max(1));
    let reader_task = tokio::spawn(read_server_requests(reader, request_tx, config));
    let coordinator = async {
        while let Some(inbound) = request_rx.recv().await {
            let inbound = inbound?;
            let method = inbound.request.head.method.clone();
            let version = inbound.request.head.version;
            let response = timeout(config.service_timeout, service.call(inbound.request))
                .await
                .map_err(|_| timeout_error("HTTP/1 service"))??;
            let close = write_response(
                &mut writer,
                response,
                &method,
                version,
                inbound.close_after_response,
                config,
            )
            .await?;
            if close {
                return Ok::<_, ProtocolError>(true);
            }
        }
        Ok(false)
    }
    .await;

    if coordinator.as_ref().is_err() || coordinator == Ok(true) {
        reader_task.abort();
        let _ = reader_task.await;
    } else {
        reader_task.await.map_err(|error| {
            ProtocolError::new(ErrorKind::Io, format!("HTTP/1 reader task failed: {error}"))
        })??;
    }
    coordinator.map(|_| ())
}

async fn read_server_requests<R>(
    mut reader: ReadHalf<R>,
    request_tx: mpsc::Sender<Result<InboundRequest, ProtocolError>>,
    config: ConnectionConfig,
) -> Result<(), ProtocolError>
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    let parser = HeadParser::new(config.head_limits);
    let mut buffer = BytesMut::with_capacity(8 * 1024);
    loop {
        let parsed = loop {
            match parser.parse_request(&buffer).map_err(protocol_error)? {
                ParseStatus::Complete(parsed) => break parsed,
                ParseStatus::Incomplete => {
                    if !read_more(&mut reader, &mut buffer, config.read_timeout).await? {
                        if buffer.is_empty() {
                            return Ok(());
                        }
                        return Err(ProtocolError::new(
                            ErrorKind::MalformedMessage,
                            "connection ended during an HTTP/1 request head",
                        ));
                    }
                }
            }
        };

        buffer.advance(parsed.consumed);
        let close_after_response = !request_keep_alive(&parsed.head.headers, parsed.head.version);
        let framing = BodyFraming::for_request(parsed.semantics);
        let (body_tx, body_rx) = mpsc::channel(config.body_channel_capacity.max(1));
        let mut body = ProxyBody::new(BodyChannel { receiver: body_rx });
        if let BodyFraming::ContentLength(length) = framing {
            body = body.with_exact_length(length);
        }
        let inbound = InboundRequest {
            request: ProxyRequest::new(parsed.head, body),
            close_after_response,
        };
        if request_tx.send(Ok(inbound)).await.is_err() {
            return Ok(());
        }

        if let Err(error) = read_body(&mut reader, &mut buffer, framing, body_tx, config).await {
            let _ = request_tx.send(Err(error.clone())).await;
            return Err(error);
        }
        if close_after_response {
            return Ok(());
        }
    }
}

async fn read_body<R>(
    reader: &mut ReadHalf<R>,
    buffer: &mut BytesMut,
    framing: BodyFraming,
    body_tx: mpsc::Sender<BodyResult>,
    config: ConnectionConfig,
) -> Result<(), ProtocolError>
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    let result = read_body_inner(reader, buffer, framing, &body_tx, config).await;
    if let Err(error) = &result {
        let _ = body_tx.send(Err(error.clone())).await;
    }
    result
}

async fn read_body_inner<R>(
    reader: &mut ReadHalf<R>,
    buffer: &mut BytesMut,
    framing: BodyFraming,
    body_tx: &mpsc::Sender<BodyResult>,
    config: ConnectionConfig,
) -> Result<(), ProtocolError>
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    let mut decoder = BodyDecoder::with_limits(framing, config.body_limits);
    loop {
        match decoder.decode(buffer).map_err(protocol_error)? {
            BodyDecodeStatus::Incomplete { consumed } => {
                buffer.advance(consumed);
                if !read_more(reader, buffer, config.read_timeout).await? {
                    match decoder.decode_eof().map_err(protocol_error)? {
                        BodyDecodeStatus::Complete { .. } => return Ok(()),
                        _ => {
                            return Err(ProtocolError::new(
                                ErrorKind::ProtocolViolation,
                                "HTTP/1 body did not complete at EOF",
                            ));
                        }
                    }
                }
            }
            BodyDecodeStatus::Frame(frame) => {
                buffer.advance(frame.consumed);
                let end_stream = frame.end_stream;
                let _ = body_tx.send(Ok(frame.frame)).await;
                if end_stream {
                    return Ok(());
                }
            }
            BodyDecodeStatus::Complete { consumed } => {
                buffer.advance(consumed);
                return Ok(());
            }
        }
    }
}

async fn write_response<W>(
    writer: &mut WriteHalf<W>,
    mut response: ProxyResponse,
    request_method: &Method,
    request_version: Version,
    request_close: bool,
    config: ConnectionConfig,
) -> Result<bool, ProtocolError>
where
    W: AsyncRead + AsyncWrite + Unpin,
{
    response.head.version = request_version;
    let mut close = request_close || response_requests_close(&response.head.headers);
    let framing =
        prepare_response_framing(request_method, &mut response, request_version, &mut close)?;
    if close {
        set_header(&mut response.head.headers, "connection", "close")?;
    } else if request_version == Version::HTTP_10 {
        set_header(&mut response.head.headers, "connection", "keep-alive")?;
    }

    let head = encode_response_head(&response.head).map_err(protocol_error)?;
    write_bytes(writer, &head, config.write_timeout).await?;
    write_body(writer, response.body, framing, config.write_timeout).await?;
    flush(writer, config.write_timeout).await?;
    Ok(close || framing == BodyFraming::UntilEof || framing == BodyFraming::Tunnel)
}

fn prepare_response_framing(
    request_method: &Method,
    response: &mut ProxyResponse,
    version: Version,
    close: &mut bool,
) -> Result<BodyFraming, ProtocolError> {
    let status = response.head.status;
    let no_body = request_method == Method::HEAD
        || status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED;
    let tunnel = request_method == Method::CONNECT && status.is_success();
    if no_body || tunnel {
        response.head.headers.remove("transfer-encoding");
        if status.is_informational() || status == StatusCode::NO_CONTENT {
            response.head.headers.remove("content-length");
        }
        return Ok(if tunnel {
            BodyFraming::Tunnel
        } else {
            BodyFraming::None
        });
    }

    response.head.headers.remove("content-length");
    response.head.headers.remove("transfer-encoding");
    if response.body.may_have_trailers() || response.body.exact_length().is_none() {
        if version == Version::HTTP_11 {
            set_header(&mut response.head.headers, "transfer-encoding", "chunked")?;
            Ok(BodyFraming::Chunked)
        } else {
            *close = true;
            Ok(BodyFraming::UntilEof)
        }
    } else {
        let length = response.body.exact_length().unwrap_or(0);
        set_header(
            &mut response.head.headers,
            "content-length",
            length.to_string(),
        )?;
        Ok(BodyFraming::ContentLength(length))
    }
}

async fn write_body<W>(
    writer: &mut W,
    mut body: ProxyBody,
    framing: BodyFraming,
    write_timeout: Duration,
) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    if matches!(framing, BodyFraming::None | BodyFraming::Tunnel) {
        return Ok(());
    }
    let mut encoder = BodyEncoder::new(framing);
    while let Some(frame) = body.next().await {
        let encoded = encoder.encode(frame?).map_err(protocol_error)?;
        write_bytes(writer, &encoded, write_timeout).await?;
    }
    let terminal = encoder.finish().map_err(protocol_error)?;
    write_bytes(writer, &terminal, write_timeout).await
}

struct BodyChannel {
    receiver: mpsc::Receiver<BodyResult>,
}

impl Stream for BodyChannel {
    type Item = BodyResult;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.poll_recv(context)
    }
}

struct ClientCommand {
    request: ProxyRequest,
    response_tx: oneshot::Sender<Result<ProxyResponse, ProtocolError>>,
}

/// Cloneable handle to one ordered HTTP/1 client connection.
#[derive(Clone)]
pub struct Http1Client {
    command_tx: mpsc::Sender<ClientCommand>,
}

impl Http1Client {
    pub fn new<I>(io: I, config: ConnectionConfig) -> Self
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (command_tx, command_rx) = mpsc::channel(1);
        tokio::spawn(run_client(io, command_rx, config));
        Self { command_tx }
    }

    pub async fn send_request(
        &self,
        request: ProxyRequest,
    ) -> Result<ProxyResponse, ProtocolError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.command_tx
            .send(ClientCommand {
                request,
                response_tx,
            })
            .await
            .map_err(|_| ProtocolError::new(ErrorKind::Io, "HTTP/1 client connection is closed"))?;
        response_rx.await.map_err(|_| {
            ProtocolError::new(
                ErrorKind::Io,
                "HTTP/1 client closed before producing a response",
            )
        })?
    }
}

impl HttpClientTrait for Http1Client {
    fn send(
        &mut self,
        request: ProxyRequest,
    ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
        Box::pin(self.send_request(request))
    }
}

async fn run_client<I>(
    mut io: I,
    mut command_rx: mpsc::Receiver<ClientCommand>,
    config: ConnectionConfig,
) where
    I: AsyncRead + AsyncWrite + Unpin,
{
    let mut buffer = BytesMut::with_capacity(8 * 1024);
    while let Some(command) = command_rx.recv().await {
        let method = command.request.head.method.clone();
        let request_close =
            !request_keep_alive(&command.request.head.headers, command.request.head.version);
        if let Err(error) = write_request(&mut io, command.request, config).await {
            let _ = command.response_tx.send(Err(error));
            return;
        }

        let (head, semantics) = match read_final_response_head(&mut io, &mut buffer, config).await {
            Ok(parsed) => parsed,
            Err(error) => {
                let _ = command.response_tx.send(Err(error));
                return;
            }
        };
        let response_close = response_requests_close(&head.headers);
        let framing = BodyFraming::for_response(&method, head.status, semantics);
        let (body_tx, body_rx) = mpsc::channel(config.body_channel_capacity.max(1));
        let mut body = ProxyBody::new(BodyChannel { receiver: body_rx });
        if let BodyFraming::ContentLength(length) = framing {
            body = body.with_exact_length(length);
        }
        if command
            .response_tx
            .send(Ok(ProxyResponse::new(head, body)))
            .is_err()
        {
            // Continue draining the body so a cancelled caller does not poison
            // an otherwise reusable connection.
        }
        if let Err(error) = read_client_body(&mut io, &mut buffer, framing, body_tx, config).await {
            tracing_error(&error);
            return;
        }
        if request_close
            || response_close
            || framing == BodyFraming::UntilEof
            || framing == BodyFraming::Tunnel
        {
            return;
        }
    }
}

async fn write_request<I>(
    io: &mut I,
    mut request: ProxyRequest,
    config: ConnectionConfig,
) -> Result<(), ProtocolError>
where
    I: AsyncWrite + Unpin,
{
    let framing = prepare_request_framing(&mut request)?;
    let head = encode_request_head(&request.head).map_err(protocol_error)?;
    write_bytes(io, &head, config.write_timeout).await?;
    write_body(io, request.body, framing, config.write_timeout).await?;
    flush(io, config.write_timeout).await
}

fn prepare_request_framing(request: &mut ProxyRequest) -> Result<BodyFraming, ProtocolError> {
    request.head.headers.remove("content-length");
    request.head.headers.remove("transfer-encoding");
    if request.body.may_have_trailers() || request.body.exact_length().is_none() {
        if request.head.version != Version::HTTP_11 {
            return Err(ProtocolError::new(
                ErrorKind::Unsupported,
                "streaming HTTP/1.0 requests require a known Content-Length",
            ));
        }
        set_header(&mut request.head.headers, "transfer-encoding", "chunked")?;
        Ok(BodyFraming::Chunked)
    } else {
        let length = request.body.exact_length().unwrap_or(0);
        if length > 0 {
            set_header(
                &mut request.head.headers,
                "content-length",
                length.to_string(),
            )?;
            Ok(BodyFraming::ContentLength(length))
        } else {
            Ok(BodyFraming::None)
        }
    }
}

async fn read_final_response_head<I>(
    io: &mut I,
    buffer: &mut BytesMut,
    config: ConnectionConfig,
) -> Result<(crate::ResponseHead, super::HeaderSemantics), ProtocolError>
where
    I: AsyncRead + Unpin,
{
    let parser = HeadParser::new(config.head_limits);
    loop {
        match parser.parse_response(buffer).map_err(protocol_error)? {
            ParseStatus::Complete(parsed) => {
                buffer.advance(parsed.consumed);
                if parsed.head.status.is_informational()
                    && parsed.head.status != StatusCode::SWITCHING_PROTOCOLS
                {
                    continue;
                }
                return Ok((parsed.head, parsed.semantics));
            }
            ParseStatus::Incomplete => {
                if !read_more(io, buffer, config.read_timeout).await? {
                    return Err(ProtocolError::new(
                        ErrorKind::MalformedMessage,
                        "connection ended during an HTTP/1 response head",
                    ));
                }
            }
        }
    }
}

async fn read_client_body<I>(
    io: &mut I,
    buffer: &mut BytesMut,
    framing: BodyFraming,
    body_tx: mpsc::Sender<BodyResult>,
    config: ConnectionConfig,
) -> Result<(), ProtocolError>
where
    I: AsyncRead + Unpin,
{
    let result = read_client_body_inner(io, buffer, framing, &body_tx, config).await;
    if let Err(error) = &result {
        let _ = body_tx.send(Err(error.clone())).await;
    }
    result
}

async fn read_client_body_inner<I>(
    io: &mut I,
    buffer: &mut BytesMut,
    framing: BodyFraming,
    body_tx: &mpsc::Sender<BodyResult>,
    config: ConnectionConfig,
) -> Result<(), ProtocolError>
where
    I: AsyncRead + Unpin,
{
    let mut decoder = BodyDecoder::with_limits(framing, config.body_limits);
    loop {
        match decoder.decode(buffer).map_err(protocol_error)? {
            BodyDecodeStatus::Incomplete { consumed } => {
                buffer.advance(consumed);
                if !read_more(io, buffer, config.read_timeout).await? {
                    match decoder.decode_eof().map_err(protocol_error)? {
                        BodyDecodeStatus::Complete { .. } => return Ok(()),
                        _ => unreachable!("EOF decoder only returns Complete or an error"),
                    }
                }
            }
            BodyDecodeStatus::Frame(frame) => {
                buffer.advance(frame.consumed);
                let end_stream = frame.end_stream;
                let _ = body_tx.send(Ok(frame.frame)).await;
                if end_stream {
                    return Ok(());
                }
            }
            BodyDecodeStatus::Complete { consumed } => {
                buffer.advance(consumed);
                return Ok(());
            }
        }
    }
}

async fn read_more<R>(
    reader: &mut R,
    buffer: &mut BytesMut,
    duration: Duration,
) -> Result<bool, ProtocolError>
where
    R: AsyncRead + Unpin,
{
    let read = timeout(duration, reader.read_buf(buffer))
        .await
        .map_err(|_| timeout_error("HTTP/1 read"))?
        .map_err(io_error)?;
    Ok(read != 0)
}

async fn write_bytes<W>(
    writer: &mut W,
    bytes: &[u8],
    duration: Duration,
) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    if bytes.is_empty() {
        return Ok(());
    }
    timeout(duration, writer.write_all(bytes))
        .await
        .map_err(|_| timeout_error("HTTP/1 write"))?
        .map_err(io_error)
}

async fn flush<W>(writer: &mut W, duration: Duration) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    timeout(duration, writer.flush())
        .await
        .map_err(|_| timeout_error("HTTP/1 flush"))?
        .map_err(io_error)
}

fn request_keep_alive(headers: &proxyapi_models::HeaderBlock, version: Version) -> bool {
    if has_connection_token(headers, b"close") {
        return false;
    }
    version == Version::HTTP_11 || has_connection_token(headers, b"keep-alive")
}

fn response_requests_close(headers: &proxyapi_models::HeaderBlock) -> bool {
    has_connection_token(headers, b"close")
}

fn has_connection_token(headers: &proxyapi_models::HeaderBlock, expected: &[u8]) -> bool {
    headers.get_all("connection").any(|value| {
        value
            .split(|byte| *byte == b',')
            .any(|token| trim_ows(token).eq_ignore_ascii_case(expected))
    })
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

fn set_header(
    headers: &mut proxyapi_models::HeaderBlock,
    name: impl AsRef<[u8]>,
    value: impl AsRef<[u8]>,
) -> Result<(), ProtocolError> {
    headers.set(name, value).map_err(|error| {
        ProtocolError::new(
            ErrorKind::MalformedMessage,
            format!("invalid HTTP/1 framing header: {error}"),
        )
    })
}

fn protocol_error(error: Http1Error) -> ProtocolError {
    ProtocolError::new(ErrorKind::MalformedMessage, error.to_string())
}

fn io_error(error: std::io::Error) -> ProtocolError {
    ProtocolError::new(ErrorKind::Io, error.to_string())
}

fn timeout_error(operation: &str) -> ProtocolError {
    ProtocolError::new(ErrorKind::Timeout, format!("{operation} timed out"))
}

fn tracing_error(_error: &ProtocolError) {
    // The protocol core deliberately has no tracing dependency. Connection
    // owners receive synchronous request failures; background body failures
    // close the handle and surface on its next use.
}

/// Destination identity used by the generic HTTP/1 pool. Concrete connectors
/// decide how `tls` and `outbound_route` are implemented.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PoolKey {
    pub destination: String,
    pub tls: bool,
    pub outbound_route: Option<String>,
}

/// Trait object accepted from pool connectors.
pub trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxIo = Box<dyn AsyncIo>;

/// Route-aware connector used by [`Http1Pool`].
pub trait Http1Connector: Send + Sync + 'static {
    fn connect(&self, key: PoolKey) -> BoxFuture<'static, Result<BoxIo, ProtocolError>>;
}

/// Keep-alive pool keyed by destination, TLS mode, and outbound route.
pub struct Http1Pool<C> {
    connector: Arc<C>,
    config: ConnectionConfig,
    clients: Mutex<HashMap<PoolKey, Http1Client>>,
}

impl<C> Http1Pool<C>
where
    C: Http1Connector,
{
    pub fn new(connector: C, config: ConnectionConfig) -> Self {
        Self {
            connector: Arc::new(connector),
            config,
            clients: Mutex::new(HashMap::new()),
        }
    }

    pub async fn send(
        &self,
        key: PoolKey,
        request: ProxyRequest,
    ) -> Result<ProxyResponse, ProtocolError> {
        let client = {
            let mut clients = self.clients.lock().await;
            if let Some(client) = clients.get(&key) {
                client.clone()
            } else {
                let io = self.connector.connect(key.clone()).await?;
                let client = Http1Client::new(io, self.config);
                clients.insert(key.clone(), client.clone());
                client
            }
        };
        let result = client.send_request(request).await;
        if result.is_err() {
            self.clients.lock().await.remove(&key);
        }
        result
    }

    pub async fn len(&self) -> usize {
        self.clients.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.clients.lock().await.is_empty()
    }
}
