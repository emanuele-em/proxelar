use std::collections::HashMap;
use std::hash::Hash;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf as _, Bytes, BytesMut};
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
    BodyEncoder, BodyFraming, HeadParser, HeadParserLimits, Http1Error,
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
    upgrade_requested: bool,
}

enum ReaderExit<R>
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    Closed,
    Upgrade {
        reader: ReadHalf<R>,
        read_ahead: BytesMut,
    },
}

/// A connection returned after an accepted HTTP upgrade handshake.
pub struct UpgradedIo<I> {
    pub io: I,
    pub read_ahead: Bytes,
}

/// Final state of an HTTP/1 server connection.
pub enum ServerConnection<I> {
    Closed,
    Upgraded(UpgradedIo<I>),
}

/// Serve one HTTP/1 connection. Requests may be read ahead into a bounded
/// pipeline, while responses are always emitted in request order.
pub async fn serve_connection<I, S>(
    io: I,
    service: S,
    config: ConnectionConfig,
) -> Result<(), ProtocolError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: HttpService,
{
    match serve_connection_with_upgrades(io, service, config).await? {
        ServerConnection::Closed | ServerConnection::Upgraded(_) => Ok(()),
    }
}

/// Serve until close or return ownership of an accepted CONNECT/Upgrade stream.
pub async fn serve_connection_with_upgrades<I, S>(
    io: I,
    mut service: S,
    config: ConnectionConfig,
) -> Result<ServerConnection<I>, ProtocolError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: HttpService,
{
    let (reader, mut writer) = split(io);
    let (request_tx, mut request_rx) = mpsc::channel(config.pipeline_capacity.max(1));
    let reader_task = tokio::spawn(read_server_requests(reader, request_tx, config));

    enum CoordinatorExit {
        Closed,
        Stop,
        Upgrade { accepted: bool },
    }

    let coordinator = async {
        while let Some(inbound) = request_rx.recv().await {
            let inbound = match inbound {
                Ok(inbound) => inbound,
                Err(error) if error.kind() == ErrorKind::MalformedMessage => {
                    write_bad_request(&mut writer, &error, config).await?;
                    return Ok::<_, ProtocolError>(CoordinatorExit::Stop);
                }
                Err(error) => return Err(error),
            };
            let method = inbound.request.head.method.clone();
            let version = inbound.request.head.version;
            let response = timeout(config.service_timeout, service.call(inbound.request))
                .await
                .map_err(|_| timeout_error("HTTP/1 service"))??;
            let status = response.head.status;
            let close = write_response(
                &mut writer,
                response,
                &method,
                version,
                inbound.close_after_response,
                config,
            )
            .await?;
            if inbound.upgrade_requested {
                let accepted = (method == Method::CONNECT && status.is_success())
                    || status == StatusCode::SWITCHING_PROTOCOLS;
                return Ok::<_, ProtocolError>(CoordinatorExit::Upgrade { accepted });
            }
            if close {
                return Ok::<_, ProtocolError>(CoordinatorExit::Stop);
            }
        }
        Ok(CoordinatorExit::Closed)
    }
    .await;

    match coordinator {
        Err(error) => {
            reader_task.abort();
            let _ = reader_task.await;
            Err(error)
        }
        Ok(CoordinatorExit::Stop) => {
            reader_task.abort();
            let _ = reader_task.await;
            Ok(ServerConnection::Closed)
        }
        Ok(CoordinatorExit::Closed) => match reader_task.await.map_err(join_error)?? {
            ReaderExit::Closed => Ok(ServerConnection::Closed),
            ReaderExit::Upgrade { .. } => Err(ProtocolError::new(
                ErrorKind::ProtocolViolation,
                "HTTP/1 reader stopped for an unmatched upgrade",
            )),
        },
        Ok(CoordinatorExit::Upgrade { accepted }) => {
            let reader_exit = reader_task.await.map_err(join_error)??;
            match (accepted, reader_exit) {
                (true, ReaderExit::Upgrade { reader, read_ahead }) => {
                    Ok(ServerConnection::Upgraded(UpgradedIo {
                        io: reader.unsplit(writer),
                        read_ahead: read_ahead.freeze(),
                    }))
                }
                _ => Ok(ServerConnection::Closed),
            }
        }
    }
}

async fn write_bad_request<W>(
    writer: &mut WriteHalf<W>,
    error: &ProtocolError,
    config: ConnectionConfig,
) -> Result<(), ProtocolError>
where
    W: AsyncRead + AsyncWrite + Unpin,
{
    let message = if error.message().contains("missing Host") {
        "Bad Request: missing Host header"
    } else {
        "Bad Request"
    };
    let response = ProxyResponse::new(
        crate::ResponseHead::new(
            StatusCode::BAD_REQUEST,
            Version::HTTP_11,
            proxyapi_models::HeaderBlock::new(),
        ),
        ProxyBody::full(Bytes::copy_from_slice(message.as_bytes())),
    );
    write_response(
        writer,
        response,
        &Method::GET,
        Version::HTTP_11,
        true,
        config,
    )
    .await?;
    Ok(())
}

async fn read_server_requests<R>(
    reader: ReadHalf<R>,
    request_tx: mpsc::Sender<Result<InboundRequest, ProtocolError>>,
    config: ConnectionConfig,
) -> Result<ReaderExit<R>, ProtocolError>
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    let result = read_server_requests_inner(reader, request_tx.clone(), config).await;
    if let Err(error) = &result {
        let _ = request_tx.send(Err(error.clone())).await;
    }
    result
}

async fn read_server_requests_inner<R>(
    mut reader: ReadHalf<R>,
    request_tx: mpsc::Sender<Result<InboundRequest, ProtocolError>>,
    config: ConnectionConfig,
) -> Result<ReaderExit<R>, ProtocolError>
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    let parser = HeadParser::new(config.head_limits);
    let mut buffer = BytesMut::with_capacity(8 * 1024);
    loop {
        let parsed = loop {
            match parser.request_head_len(&buffer).map_err(protocol_error)? {
                Some(consumed) => {
                    let head = buffer.split_to(consumed).freeze();
                    break parser.parse_request_bytes(head).map_err(protocol_error)?;
                }
                None => {
                    if !read_more(&mut reader, &mut buffer, config.read_timeout).await? {
                        if buffer.is_empty() {
                            return Ok(ReaderExit::Closed);
                        }
                        return Err(ProtocolError::new(
                            ErrorKind::MalformedMessage,
                            "connection ended during an HTTP/1 request head",
                        ));
                    }
                }
            }
        };

        let close_after_response = !request_keep_alive(&parsed.head.headers, parsed.head.version);
        let upgrade_requested = request_wants_upgrade(&parsed.head.method, &parsed.head.headers);
        let framing = BodyFraming::for_request(parsed.semantics);
        let (body_tx, body_rx) = mpsc::channel(config.body_channel_capacity.max(1));
        let mut body = ProxyBody::new(BodyChannel { receiver: body_rx });
        if let BodyFraming::ContentLength(length) = framing {
            body = body.with_exact_length(length).with_trailer_hint(false);
        }
        let inbound = InboundRequest {
            request: ProxyRequest::new(parsed.head, body),
            close_after_response,
            upgrade_requested,
        };
        if request_tx.send(Ok(inbound)).await.is_err() {
            return Ok(ReaderExit::Closed);
        }

        read_body(&mut reader, &mut buffer, framing, body_tx, config).await?;
        if upgrade_requested {
            return Ok(ReaderExit::Upgrade {
                reader,
                read_ahead: buffer,
            });
        }
        if close_after_response {
            return Ok(ReaderExit::Closed);
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
        match decoder.decode_buffer(buffer).map_err(protocol_error)? {
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
    response_tx: oneshot::Sender<ClientOutcome>,
}

enum ClientOutcome {
    Response(Result<Http1ClientResponse, ProtocolError>),
    NotSent(ProxyRequest),
}

enum ClientSendError {
    Failed(ProtocolError),
    NotSent(Box<ProxyRequest>),
}

/// Receiver for a raw stream accepted by CONNECT or `101 Switching Protocols`.
pub struct UpgradeReceiver {
    receiver: oneshot::Receiver<UpgradedIo<BoxIo>>,
}

impl UpgradeReceiver {
    pub async fn wait(self) -> Result<UpgradedIo<BoxIo>, ProtocolError> {
        self.receiver.await.map_err(|_| {
            ProtocolError::new(
                ErrorKind::Io,
                "HTTP/1 connection closed before completing the upgrade",
            )
        })
    }
}

/// A client response with optional ownership transfer for protocol upgrades.
pub struct Http1ClientResponse {
    pub response: ProxyResponse,
    pub upgrade: Option<UpgradeReceiver>,
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
        tokio::spawn(run_client(Box::new(io), command_rx, config));
        Self { command_tx }
    }

    pub async fn send_request(
        &self,
        request: ProxyRequest,
    ) -> Result<ProxyResponse, ProtocolError> {
        Ok(self.send_request_with_upgrade(request).await?.response)
    }

    pub async fn send_request_with_upgrade(
        &self,
        request: ProxyRequest,
    ) -> Result<Http1ClientResponse, ProtocolError> {
        self.send_request_recoverable(request)
            .await
            .map_err(ClientSendError::into_protocol_error)
    }

    async fn send_request_recoverable(
        &self,
        request: ProxyRequest,
    ) -> Result<Http1ClientResponse, ClientSendError> {
        let (response_tx, response_rx) = oneshot::channel();
        if let Err(error) = self
            .command_tx
            .send(ClientCommand {
                request,
                response_tx,
            })
            .await
        {
            return Err(ClientSendError::NotSent(Box::new(error.0.request)));
        }
        match response_rx.await {
            Ok(ClientOutcome::Response(result)) => result.map_err(ClientSendError::Failed),
            Ok(ClientOutcome::NotSent(request)) => Err(ClientSendError::NotSent(Box::new(request))),
            Err(_) => Err(ClientSendError::Failed(ProtocolError::new(
                ErrorKind::Io,
                "HTTP/1 client closed before producing a response",
            ))),
        }
    }

    fn same_connection(&self, other: &Self) -> bool {
        self.command_tx.same_channel(&other.command_tx)
    }
}

impl ClientSendError {
    fn into_protocol_error(self) -> ProtocolError {
        match self {
            Self::Failed(error) => error,
            Self::NotSent(_) => ProtocolError::new(
                ErrorKind::Io,
                "HTTP/1 client connection closed before accepting the request",
            ),
        }
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

async fn run_client(
    mut io: BoxIo,
    mut command_rx: mpsc::Receiver<ClientCommand>,
    config: ConnectionConfig,
) {
    let mut buffer = BytesMut::with_capacity(8 * 1024);
    while let Some(command) = command_rx.recv().await {
        let method = command.request.head.method.clone();
        let request_close =
            !request_keep_alive(&command.request.head.headers, command.request.head.version);
        if let Err(error) = write_request(&mut io, command.request, config).await {
            let _ = command
                .response_tx
                .send(ClientOutcome::Response(Err(error)));
            break;
        }

        let (head, semantics) = match read_final_response_head(&mut io, &mut buffer, config).await {
            Ok(parsed) => parsed,
            Err(error) => {
                let _ = command
                    .response_tx
                    .send(ClientOutcome::Response(Err(error)));
                break;
            }
        };
        let response_close = response_requests_close(&head.headers);
        let framing = BodyFraming::for_response(&method, head.status, semantics);
        let upgraded =
            framing == BodyFraming::Tunnel || head.status == StatusCode::SWITCHING_PROTOCOLS;
        if upgraded {
            let (upgrade_tx, upgrade_rx) = oneshot::channel();
            let response = ProxyResponse::new(head, ProxyBody::empty());
            let _ = command
                .response_tx
                .send(ClientOutcome::Response(Ok(Http1ClientResponse {
                    response,
                    upgrade: Some(UpgradeReceiver {
                        receiver: upgrade_rx,
                    }),
                })));
            let _ = upgrade_tx.send(UpgradedIo {
                io,
                read_ahead: buffer.split().freeze(),
            });
            break;
        }
        let (body_tx, body_rx) = mpsc::channel(config.body_channel_capacity.max(1));
        let mut body = ProxyBody::new(BodyChannel { receiver: body_rx });
        if let BodyFraming::ContentLength(length) = framing {
            body = body.with_exact_length(length).with_trailer_hint(false);
        }
        if command
            .response_tx
            .send(ClientOutcome::Response(Ok(Http1ClientResponse {
                response: ProxyResponse::new(head, body),
                upgrade: None,
            })))
            .is_err()
        {
            // Continue draining the body so a cancelled caller does not poison
            // an otherwise reusable connection.
        }
        if let Err(error) = read_client_body(&mut io, &mut buffer, framing, body_tx, config).await {
            tracing_error(&error);
            break;
        }
        if request_close
            || response_close
            || framing == BodyFraming::UntilEof
            || framing == BodyFraming::Tunnel
        {
            break;
        }
    }

    // Prevent new commands from entering, then return ownership of every
    // request that was queued but never written. The pool may safely retry
    // only this explicit state; write/read failures remain non-retryable.
    command_rx.close();
    while let Some(command) = command_rx.recv().await {
        let _ = command
            .response_tx
            .send(ClientOutcome::NotSent(command.request));
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
        match parser.response_head_len(buffer).map_err(protocol_error)? {
            Some(consumed) => {
                let head = buffer.split_to(consumed).freeze();
                let parsed = parser.parse_response_bytes(head).map_err(protocol_error)?;
                if parsed.head.status.is_informational()
                    && parsed.head.status != StatusCode::SWITCHING_PROTOCOLS
                {
                    continue;
                }
                return Ok((parsed.head, parsed.semantics));
            }
            None => {
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
        match decoder.decode_buffer(buffer).map_err(protocol_error)? {
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

fn request_wants_upgrade(method: &Method, headers: &proxyapi_models::HeaderBlock) -> bool {
    method == Method::CONNECT
        || (headers.contains_key("upgrade") && has_connection_token(headers, b"upgrade"))
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

fn join_error(error: tokio::task::JoinError) -> ProtocolError {
    ProtocolError::new(ErrorKind::Io, format!("HTTP/1 reader task failed: {error}"))
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
        Ok(self.send_with_upgrade(key, request).await?.response)
    }

    pub async fn send_with_upgrade(
        &self,
        key: PoolKey,
        mut request: ProxyRequest,
    ) -> Result<Http1ClientResponse, ProtocolError> {
        loop {
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
            match client.send_request_recoverable(request).await {
                Ok(response) => return Ok(response),
                Err(ClientSendError::Failed(error)) => {
                    self.remove_if_current(&key, &client).await;
                    return Err(error);
                }
                Err(ClientSendError::NotSent(returned_request)) => {
                    self.remove_if_current(&key, &client).await;
                    request = *returned_request;
                }
            }
        }
    }

    async fn remove_if_current(&self, key: &PoolKey, failed: &Http1Client) {
        let mut clients = self.clients.lock().await;
        if clients
            .get(key)
            .is_some_and(|current| current.same_connection(failed))
        {
            clients.remove(key);
        }
    }

    pub async fn len(&self) -> usize {
        self.clients.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.clients.lock().await.is_empty()
    }
}
