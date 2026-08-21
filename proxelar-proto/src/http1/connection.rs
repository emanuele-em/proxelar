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
use tokio::sync::{mpsc, oneshot, Mutex, OwnedSemaphorePermit, Semaphore};
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
    upgrade_decision: Option<oneshot::Sender<bool>>,
    expect_continue: bool,
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
        Upgrade,
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
            if inbound.expect_continue {
                write_bytes(
                    &mut writer,
                    b"HTTP/1.1 100 Continue\r\n\r\n",
                    config.write_timeout,
                )
                .await?;
                flush(&mut writer, config.write_timeout).await?;
            }
            let method = inbound.request.head.method.clone();
            let version = inbound.request.head.version;
            let upgrade_decision = inbound.upgrade_decision;
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
            if let Some(upgrade_decision) = upgrade_decision {
                let accepted = (method == Method::CONNECT && status.is_success())
                    || status == StatusCode::SWITCHING_PROTOCOLS;
                let _ = upgrade_decision.send(accepted);
                if accepted {
                    return Ok::<_, ProtocolError>(CoordinatorExit::Upgrade);
                }
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
        Ok(CoordinatorExit::Upgrade) => {
            let reader_exit = reader_task.await.map_err(join_error)??;
            match reader_exit {
                ReaderExit::Upgrade { reader, read_ahead } => {
                    Ok(ServerConnection::Upgraded(UpgradedIo {
                        io: reader.unsplit(writer),
                        read_ahead: read_ahead.freeze(),
                    }))
                }
                ReaderExit::Closed => Ok(ServerConnection::Closed),
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

        let mut head = parsed.head;
        let expect_continue = head.version == Version::HTTP_11 && {
            let mut values = head.headers.get_all("expect");
            values
                .next()
                .is_some_and(|value| trim_ows(value).eq_ignore_ascii_case(b"100-continue"))
                && values.next().is_none()
        };
        if expect_continue {
            head.headers.remove("expect");
        }
        let close_after_response = !request_keep_alive(&head.headers, head.version);
        let upgrade_requested = request_wants_upgrade(&head.method, &head.headers);
        let (upgrade_decision, upgrade_result) = if upgrade_requested {
            let (tx, rx) = oneshot::channel();
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let framing = BodyFraming::for_request(parsed.semantics);
        let (body_tx, body_rx) = mpsc::channel(config.body_channel_capacity.max(1));
        let mut body = ProxyBody::new(BodyChannel { receiver: body_rx });
        match framing {
            BodyFraming::None => {
                body = body.with_exact_length(0).with_trailer_hint(false);
            }
            BodyFraming::ContentLength(length) => {
                body = body.with_exact_length(length).with_trailer_hint(false);
            }
            _ => {}
        }
        let inbound = InboundRequest {
            request: ProxyRequest::new(head, body),
            close_after_response,
            upgrade_decision,
            expect_continue,
        };
        if request_tx.send(Ok(inbound)).await.is_err() {
            return Ok(ReaderExit::Closed);
        }

        read_body(&mut reader, &mut buffer, framing, body_tx, config).await?;
        if let Some(upgrade_result) = upgrade_result {
            match upgrade_result.await {
                Ok(true) => {
                    return Ok(ReaderExit::Upgrade {
                        reader,
                        read_ahead: buffer,
                    });
                }
                Ok(false) => {}
                Err(_) => return Ok(ReaderExit::Closed),
            }
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
    for mut informational in std::mem::take(&mut response.informational) {
        if !informational.status.is_informational()
            || informational.status == StatusCode::SWITCHING_PROTOCOLS
        {
            return Err(ProtocolError::new(
                ErrorKind::ProtocolViolation,
                "HTTP/1 informational response must be 1xx other than 101",
            ));
        }
        informational.version = request_version;
        let head = encode_response_head(&informational).map_err(protocol_error)?;
        write_bytes(writer, &head, config.write_timeout).await?;
    }
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
    permit: OwnedSemaphorePermit,
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
    availability: Arc<Semaphore>,
}

impl Http1Client {
    pub fn new<I>(io: I, config: ConnectionConfig) -> Self
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (command_tx, command_rx) = mpsc::channel(1);
        let availability = Arc::new(Semaphore::new(1));
        tokio::spawn(run_client(
            Box::new(io),
            command_rx,
            config,
            Arc::clone(&availability),
        ));
        Self {
            command_tx,
            availability,
        }
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
        let permit = match Arc::clone(&self.availability).acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => return Err(ClientSendError::NotSent(Box::new(request))),
        };
        self.send_reserved(request, permit).await
    }

    async fn send_reserved(
        &self,
        request: ProxyRequest,
        permit: OwnedSemaphorePermit,
    ) -> Result<Http1ClientResponse, ClientSendError> {
        let (response_tx, response_rx) = oneshot::channel();
        if let Err(error) = self
            .command_tx
            .send(ClientCommand {
                request,
                response_tx,
                permit,
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
    availability: Arc<Semaphore>,
) {
    let mut buffer = BytesMut::with_capacity(8 * 1024);
    while let Some(command) = command_rx.recv().await {
        let ClientCommand {
            mut request,
            response_tx,
            permit,
        } = command;
        let method = request.head.method.clone();
        let request_close = !request_keep_alive(&request.head.headers, request.head.version);
        let request_framing = match prepare_request_framing(&mut request) {
            Ok(framing) => framing,
            Err(error) => {
                let _ = response_tx.send(ClientOutcome::Response(Err(error)));
                break;
            }
        };
        let request_head = match encode_request_head(&request.head).map_err(protocol_error) {
            Ok(head) => head,
            Err(error) => {
                let _ = response_tx.send(ClientOutcome::Response(Err(error)));
                break;
            }
        };
        if let Err(error) = write_bytes(&mut io, &request_head, config.write_timeout).await {
            let _ = response_tx.send(ClientOutcome::Response(Err(error)));
            break;
        }
        if let Err(error) = flush(&mut io, config.write_timeout).await {
            let _ = response_tx.send(ClientOutcome::Response(Err(error)));
            break;
        }

        let (mut reader, mut writer) = split(&mut io);
        let mut write_request = Box::pin(write_request_body(
            &mut writer,
            request.body,
            request_framing,
            config,
        ));
        let mut write_result = None;

        let parsed = {
            let mut read_head =
                Box::pin(read_final_response_head(&mut reader, &mut buffer, config));
            tokio::select! {
                result = read_head.as_mut() => result,
                result = write_request.as_mut() => {
                    write_result = Some(result);
                    read_head.await
                }
            }
        };
        let (informational, head, semantics) = match parsed {
            Ok(parsed) => parsed,
            Err(read_error) => {
                let error = write_result.and_then(Result::err).unwrap_or(read_error);
                drop(write_request);
                drop(reader);
                drop(writer);
                let _ = response_tx.send(ClientOutcome::Response(Err(error)));
                break;
            }
        };
        let response_close = response_requests_close(&head.headers);
        let framing = BodyFraming::for_response(&method, head.status, semantics);
        let upgraded =
            framing == BodyFraming::Tunnel || head.status == StatusCode::SWITCHING_PROTOCOLS;
        if upgraded {
            drop(write_request);
            drop(reader);
            drop(writer);
            let (upgrade_tx, upgrade_rx) = oneshot::channel();
            let response =
                ProxyResponse::new(head, ProxyBody::empty()).with_informational(informational);
            let _ = response_tx.send(ClientOutcome::Response(Ok(Http1ClientResponse {
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
        if response_tx
            .send(ClientOutcome::Response(Ok(Http1ClientResponse {
                response: ProxyResponse::new(head, body).with_informational(informational),
                upgrade: None,
            })))
            .is_err()
        {
            // Continue draining the body so a cancelled caller does not poison
            // an otherwise reusable connection.
        }

        let mut read_body = Box::pin(read_client_body(
            &mut reader,
            &mut buffer,
            framing,
            &body_tx,
            config,
        ));
        let mut finish_request_after_response = false;
        let read_result = if response_close || write_result.is_some() {
            read_body.as_mut().await
        } else {
            tokio::select! {
                result = read_body.as_mut() => {
                    finish_request_after_response = result.is_ok();
                    result
                }
                result = write_request.as_mut() => {
                    write_result = Some(result);
                    read_body.as_mut().await
                }
            }
        };
        drop(read_body);
        drop(body_tx);
        if finish_request_after_response {
            write_result = Some(write_request.as_mut().await);
        }
        drop(write_request);
        drop(reader);
        drop(writer);

        if let Err(error) = read_result {
            tracing_error(&error);
            break;
        }
        let request_complete = matches!(write_result, Some(Ok(())));
        if let Some(Err(error)) = &write_result {
            tracing_error(error);
        }
        drop(permit);
        if !request_complete
            || request_close
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
    availability.close();
    while let Some(command) = command_rx.recv().await {
        let _ = command
            .response_tx
            .send(ClientOutcome::NotSent(command.request));
    }
}

async fn write_request_body<I>(
    io: &mut I,
    body: ProxyBody,
    framing: BodyFraming,
    config: ConnectionConfig,
) -> Result<(), ProtocolError>
where
    I: AsyncWrite + Unpin,
{
    write_body(io, body, framing, config.write_timeout).await?;
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
) -> Result<
    (
        Vec<crate::ResponseHead>,
        crate::ResponseHead,
        super::HeaderSemantics,
    ),
    ProtocolError,
>
where
    I: AsyncRead + Unpin,
{
    let parser = HeadParser::new(config.head_limits);
    let mut informational = Vec::new();
    loop {
        match parser.response_head_len(buffer).map_err(protocol_error)? {
            Some(consumed) => {
                let head = buffer.split_to(consumed).freeze();
                let parsed = parser.parse_response_bytes(head).map_err(protocol_error)?;
                if parsed.head.status.is_informational()
                    && parsed.head.status != StatusCode::SWITCHING_PROTOCOLS
                {
                    informational.push(parsed.head);
                    continue;
                }
                return Ok((informational, parsed.head, parsed.semantics));
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
    body_tx: &mpsc::Sender<BodyResult>,
    config: ConnectionConfig,
) -> Result<(), ProtocolError>
where
    I: AsyncRead + Unpin,
{
    let result = read_client_body_inner(io, buffer, framing, body_tx, config).await;
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
    entries: Mutex<HashMap<PoolKey, PoolEntry>>,
}

const MAX_CONNECTIONS_PER_KEY: usize = 5;

struct PoolEntry {
    clients: Vec<Http1Client>,
    next: usize,
    connect_lock: Arc<Mutex<()>>,
}

impl Default for PoolEntry {
    fn default() -> Self {
        Self {
            clients: Vec::new(),
            next: 0,
            connect_lock: Arc::new(Mutex::new(())),
        }
    }
}

struct ClientReservation {
    client: Http1Client,
    permit: OwnedSemaphorePermit,
}

enum PoolChoice {
    Reserved(ClientReservation),
    Wait(Http1Client),
    Connect(Arc<Mutex<()>>),
}

impl<C> Http1Pool<C>
where
    C: Http1Connector,
{
    pub fn new(connector: C, config: ConnectionConfig) -> Self {
        Self {
            connector: Arc::new(connector),
            config,
            entries: Mutex::new(HashMap::new()),
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
            let choice = self.acquire(&key).await?;

            let (client, outcome) = match choice {
                PoolChoice::Reserved(reservation) => {
                    let client = reservation.client.clone();
                    let outcome = client.send_reserved(request, reservation.permit).await;
                    (client, outcome)
                }
                PoolChoice::Wait(client) => {
                    let outcome = client.send_request_recoverable(request).await;
                    (client, outcome)
                }
                PoolChoice::Connect(_) => unreachable!("acquire resolves connection choices"),
            };

            match outcome {
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

    async fn acquire(&self, key: &PoolKey) -> Result<PoolChoice, ProtocolError> {
        let choice = {
            let mut entries = self.entries.lock().await;
            choose_pool_client(entries.entry(key.clone()).or_default())
        };
        let PoolChoice::Connect(connect_lock) = choice else {
            return Ok(choice);
        };

        let _connect_guard = connect_lock.lock().await;
        {
            let mut entries = self.entries.lock().await;
            let choice = choose_pool_client(entries.entry(key.clone()).or_default());
            if !matches!(choice, PoolChoice::Connect(_)) {
                return Ok(choice);
            }
        }

        let io = self.connector.connect(key.clone()).await?;
        let client = Http1Client::new(io, self.config);
        let permit = Arc::clone(&client.availability)
            .try_acquire_owned()
            .expect("new HTTP/1 client is available");
        self.entries
            .lock()
            .await
            .entry(key.clone())
            .or_default()
            .clients
            .push(client.clone());
        Ok(PoolChoice::Reserved(ClientReservation { client, permit }))
    }

    async fn remove_if_current(&self, key: &PoolKey, failed: &Http1Client) {
        let mut entries = self.entries.lock().await;
        if let Some(entry) = entries.get_mut(key) {
            entry
                .clients
                .retain(|client| !client.same_connection(failed));
        }
    }

    pub async fn len(&self) -> usize {
        self.entries
            .lock()
            .await
            .values()
            .filter(|entry| !entry.clients.is_empty())
            .count()
    }

    pub async fn is_empty(&self) -> bool {
        self.entries
            .lock()
            .await
            .values()
            .all(|entry| entry.clients.is_empty())
    }
}

fn choose_pool_client(entry: &mut PoolEntry) -> PoolChoice {
    entry
        .clients
        .retain(|client| !client.command_tx.is_closed());
    if let Some(reservation) = entry.clients.iter().find_map(|client| {
        Arc::clone(&client.availability)
            .try_acquire_owned()
            .ok()
            .map(|permit| ClientReservation {
                client: client.clone(),
                permit,
            })
    }) {
        return PoolChoice::Reserved(reservation);
    }
    if entry.clients.len() < MAX_CONNECTIONS_PER_KEY {
        return PoolChoice::Connect(Arc::clone(&entry.connect_lock));
    }
    let client = entry.clients[entry.next % entry.clients.len()].clone();
    entry.next = entry.next.wrapping_add(1);
    PoolChoice::Wait(client)
}
