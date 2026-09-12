use std::collections::HashMap;
use std::future::{poll_fn, Future as _};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_core::Stream;
use futures_util::StreamExt as _;
use h2::{Ping, PingPong, Reason, RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, DuplexStream};
use tokio::sync::{mpsc, oneshot, Mutex};

use super::{
    from_h2_request, from_h2_response, from_h2_trailers, map_h2_error, to_h2_request,
    to_h2_response, to_h2_trailers,
};
use crate::http1::BoxIo;
use crate::{
    response_body_is_forbidden, BodyFrame, BoxFuture, ErrorKind, HttpClient as HttpClientTrait,
    HttpService, ProtocolError, ProxyBody, ProxyRequest, ProxyResponse,
};

/// HTTP/2 settings shared by client and server drivers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionConfig {
    pub initial_stream_window_size: u32,
    pub initial_connection_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
    pub max_concurrent_streams: u32,
    pub enable_extended_connect: bool,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            initial_stream_window_size: 65_535,
            initial_connection_window_size: 1_048_576,
            max_frame_size: 16_384,
            max_header_list_size: 64 * 1024,
            max_concurrent_streams: 100,
            enable_extended_connect: false,
        }
    }
}

/// Serve a prior-knowledge or ALPN-selected HTTP/2 connection directly with
/// `h2`. Independent streams run concurrently and share the engine's flow
/// control and GOAWAY lifecycle.
pub async fn serve_connection<I, S>(
    io: I,
    service: S,
    config: ConnectionConfig,
) -> Result<(), ProtocolError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: HttpService + Clone + Send + 'static,
{
    let mut builder = h2::server::Builder::new();
    builder
        .initial_window_size(config.initial_stream_window_size)
        .initial_connection_window_size(config.initial_connection_window_size)
        .max_frame_size(config.max_frame_size)
        .max_header_list_size(config.max_header_list_size)
        .max_concurrent_streams(config.max_concurrent_streams);
    if config.enable_extended_connect {
        builder.enable_connect_protocol();
    }
    let mut connection = builder.handshake(io).await.map_err(map_h2_error)?;
    while let Some(stream) = connection.accept().await {
        let (request, respond) = stream.map_err(map_h2_error)?;
        let mut service = service.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_stream(request, respond, &mut service).await {
                tracing_error(&error);
            }
        });
    }
    Ok(())
}

/// Adapt an accepted CONNECT body pair into one bounded bidirectional byte
/// stream. Bytes read from the returned stream come from the request DATA
/// frames; bytes written to it become response DATA frames.
pub fn body_tunnel(mut inbound: ProxyBody, capacity: usize) -> (DuplexStream, ProxyBody) {
    let capacity = capacity.max(1);
    let (application, bridge) = tokio::io::duplex(capacity);
    let (mut bridge_reader, mut bridge_writer) = tokio::io::split(bridge);
    let (outbound_tx, outbound_rx) = mpsc::channel(capacity.div_ceil(16 * 1024).max(1));
    // The receive pump must not keep the response body open after the
    // application's write half closes. Upgrade only to report an error.
    let error_tx = outbound_tx.downgrade();
    tokio::spawn(async move {
        let receive = async move {
            let result = async {
                while let Some(frame) = inbound.next().await {
                    match frame? {
                        BodyFrame::Data(data) => {
                            bridge_writer.write_all(&data).await.map_err(|error| {
                                ProtocolError::new(ErrorKind::Io, error.to_string())
                            })?
                        }
                        BodyFrame::Trailers(_) => {
                            return Err(ProtocolError::new(
                                ErrorKind::ProtocolViolation,
                                "CONNECT byte stream received trailers",
                            ));
                        }
                    }
                }
                bridge_writer
                    .shutdown()
                    .await
                    .map_err(|error| ProtocolError::new(ErrorKind::Io, error.to_string()))
            }
            .await;
            if let Err(error) = result {
                if let Some(sender) = error_tx.upgrade() {
                    let _ = sender.send(Err(error)).await;
                }
                return Err(());
            }
            Ok(())
        };
        let transmit = async move {
            let mut output = vec![0_u8; capacity.min(16 * 1024)];
            loop {
                let read = tokio::select! {
                    read = bridge_reader.read(&mut output) => read,
                    () = outbound_tx.closed() => return Err(()),
                };
                let frame = match read {
                    Ok(0) => return Ok(()),
                    Ok(read) => Ok(BodyFrame::Data(Bytes::copy_from_slice(&output[..read]))),
                    Err(error) => Err(ProtocolError::new(ErrorKind::Io, error.to_string())),
                };
                let failed = frame.is_err();
                outbound_tx.send(frame).await.map_err(|_| ())?;
                if failed {
                    return Err(());
                }
            }
        };
        // A normal half-close leaves the opposite pump running; a failure
        // cancels it. Neither direction waits for the other's buffer to drain.
        let _ = tokio::try_join!(receive, transmit);
    });
    (
        application,
        ProxyBody::new(BodyChannel {
            receiver: outbound_rx,
        }),
    )
}

/// Bridge a bidirectional byte stream to an outbound request body and a later
/// inbound response body. This is the shape used by extended CONNECT.
pub fn websocket_body_tunnel(
    capacity: usize,
) -> (DuplexStream, ProxyBody, oneshot::Sender<ProxyBody>) {
    let capacity = capacity.max(1);
    let (application, bridge) = tokio::io::duplex(capacity);
    let (mut bridge_reader, mut bridge_writer) = tokio::io::split(bridge);
    let (outbound_tx, outbound_rx) = mpsc::channel(capacity.div_ceil(16 * 1024).max(1));
    let (inbound_tx, inbound_rx) = oneshot::channel::<ProxyBody>();

    tokio::spawn(async move {
        let mut output = vec![0_u8; capacity.min(16 * 1024)];
        loop {
            match bridge_reader.read(&mut output).await {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    if outbound_tx
                        .send(Ok(BodyFrame::Data(Bytes::copy_from_slice(&output[..read]))))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });
    tokio::spawn(async move {
        if let Ok(mut inbound) = inbound_rx.await {
            while let Some(frame) = inbound.next().await {
                match frame {
                    Ok(BodyFrame::Data(data)) => {
                        if bridge_writer.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    Ok(BodyFrame::Trailers(_)) | Err(_) => break,
                }
            }
        }
        let _ = bridge_writer.shutdown().await;
    });

    (
        application,
        ProxyBody::new(BodyChannel {
            receiver: outbound_rx,
        })
        .with_trailer_hint(false),
        inbound_tx,
    )
}

async fn serve_stream<S>(
    request: http::Request<RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    service: &mut S,
) -> Result<(), ProtocolError>
where
    S: HttpService,
{
    let head = match from_h2_request(&request) {
        Ok(head) => head,
        Err(error) => {
            respond.send_reset(Reason::PROTOCOL_ERROR);
            return Err(error);
        }
    };
    let request_method = head.method.clone();
    let body = recv_body(request.into_body());
    let response = match service.call(ProxyRequest::new(head, body)).await {
        Ok(response) => response,
        Err(error) => {
            respond.send_reset(reason_for_error(&error));
            return Err(error);
        }
    };
    let (informational, head, body) = response.into_parts();
    for head in informational {
        if !head.status.is_informational() || head.status == http::StatusCode::SWITCHING_PROTOCOLS {
            return Err(ProtocolError::new(
                ErrorKind::ProtocolViolation,
                "HTTP/2 informational response must be 1xx other than 101",
            ));
        }
        respond
            .send_informational(to_h2_response(&head)?)
            .map_err(map_h2_error)?;
    }
    let response = to_h2_response(&head)?;
    let end_stream =
        response_body_is_forbidden(&request_method, head.status) || body_is_known_empty(&body);
    let mut send = respond
        .send_response(response, end_stream)
        .map_err(map_h2_error)?;
    if !end_stream {
        send_body(&mut send, body).await?;
    }
    Ok(())
}

/// Cloneable multiplexed client connection.
#[derive(Clone)]
pub struct H2Client {
    sender: h2::client::SendRequest<Bytes>,
    ping_pong: Arc<Mutex<PingPong>>,
    identity: Arc<()>,
}

enum H2SendError {
    NotSent(Box<ProxyRequest>, ProtocolError),
    Failed(ProtocolError),
}

impl H2Client {
    pub async fn handshake<I>(io: I, config: ConnectionConfig) -> Result<Self, ProtocolError>
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut builder = h2::client::Builder::new();
        builder
            .initial_window_size(config.initial_stream_window_size)
            .initial_connection_window_size(config.initial_connection_window_size)
            .max_frame_size(config.max_frame_size)
            .max_header_list_size(config.max_header_list_size)
            .max_concurrent_streams(config.max_concurrent_streams);
        let (sender, mut connection) = builder.handshake(io).await.map_err(map_h2_error)?;
        let ping_pong = connection.ping_pong().ok_or_else(|| {
            ProtocolError::new(ErrorKind::Io, "HTTP/2 ping handle is unavailable")
        })?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing_error(&map_h2_error(error));
            }
        });
        Ok(Self {
            sender,
            ping_pong: Arc::new(Mutex::new(ping_pong)),
            identity: Arc::new(()),
        })
    }

    /// Return whether the peer has acknowledged RFC 8441 extended CONNECT.
    pub fn is_extended_connect_enabled(&self) -> bool {
        self.sender.is_extended_connect_protocol_enabled()
    }

    /// Wait for the peer's initial settings and require RFC 8441 support.
    pub async fn ensure_extended_connect(&self) -> Result<(), ProtocolError> {
        if self.is_extended_connect_enabled() {
            return Ok(());
        }
        self.ping_pong
            .lock()
            .await
            .ping(Ping::opaque())
            .await
            .map_err(map_h2_error)?;
        if self.is_extended_connect_enabled() {
            Ok(())
        } else {
            Err(ProtocolError::new(
                ErrorKind::Unsupported,
                "HTTP/2 peer did not enable extended CONNECT",
            ))
        }
    }

    pub async fn send_request(
        &self,
        request: ProxyRequest,
    ) -> Result<ProxyResponse, ProtocolError> {
        self.send_request_recoverable(request)
            .await
            .map_err(H2SendError::into_protocol_error)
    }

    async fn send_request_recoverable(
        &self,
        request: ProxyRequest,
    ) -> Result<ProxyResponse, H2SendError> {
        let encoded = to_h2_request(&request.head).map_err(H2SendError::Failed)?;
        let mut sender = match self.sender.clone().ready().await {
            Ok(sender) => sender,
            Err(error) => {
                return Err(H2SendError::NotSent(Box::new(request), map_h2_error(error)));
            }
        };
        let (_, body) = request.into_parts();
        let end_stream = body_is_known_empty(&body);
        let (response, mut send) = sender
            .send_request(encoded, end_stream)
            .map_err(map_h2_error)
            .map_err(H2SendError::Failed)?;
        if !end_stream {
            tokio::spawn(async move {
                if let Err(error) = send_body(&mut send, body).await {
                    send.send_reset(reason_for_error(&error));
                    tracing_error(&error);
                }
            });
        }
        let mut response = response;
        let mut informational = Vec::new();
        let response = poll_fn(|context| {
            loop {
                match response.poll_informational(context) {
                    Poll::Ready(Some(Ok(head))) => match from_h2_response(&head) {
                        Ok(head) => informational.push(head),
                        Err(error) => return Poll::Ready(Err(error)),
                    },
                    Poll::Ready(Some(Err(error))) => {
                        return Poll::Ready(Err(map_h2_error(error)));
                    }
                    Poll::Ready(None) | Poll::Pending => break,
                }
            }
            Pin::new(&mut response).poll(context).map_err(map_h2_error)
        })
        .await
        .map_err(H2SendError::Failed)?;
        let head = from_h2_response(&response).map_err(H2SendError::Failed)?;
        Ok(ProxyResponse::new(head, recv_body(response.into_body()))
            .with_informational(informational))
    }

    fn same_connection(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.identity, &other.identity)
    }
}

impl H2SendError {
    fn into_protocol_error(self) -> ProtocolError {
        match self {
            Self::NotSent(_, error) | Self::Failed(error) => error,
        }
    }
}

impl HttpClientTrait for H2Client {
    fn send(
        &mut self,
        request: ProxyRequest,
    ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
        Box::pin(self.send_request(request))
    }
}

/// The route identity for a multiplexed HTTP/2 connection.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct H2PoolKey {
    pub destination: String,
    pub tls: bool,
    pub outbound_route: Option<String>,
}

/// Establishes one h2c or ALPN-selected HTTP/2 transport for a pool key.
pub trait H2Connector: Clone + Send + Sync + 'static {
    fn connect(&self, key: H2PoolKey) -> BoxFuture<'static, Result<BoxIo, ProtocolError>>;
}

/// Destination-keyed HTTP/2 pool. Each entry is a single multiplexed
/// connection; an h2 reset or GOAWAY evicts it before the next request.
#[derive(Clone)]
pub struct H2Pool<C> {
    connector: C,
    config: ConnectionConfig,
    clients: Arc<Mutex<HashMap<H2PoolKey, H2Client>>>,
}

impl<C> H2Pool<C>
where
    C: H2Connector,
{
    pub fn new(connector: C, config: ConnectionConfig) -> Self {
        Self {
            connector,
            config,
            clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn send(
        &self,
        key: H2PoolKey,
        mut request: ProxyRequest,
    ) -> Result<ProxyResponse, ProtocolError> {
        let mut retried = false;
        loop {
            let existing = {
                let clients = self.clients.lock().await;
                clients.get(&key).cloned()
            };
            let client = if let Some(client) = existing {
                client
            } else {
                let io = self.connector.connect(key.clone()).await?;
                let client = H2Client::handshake(io, self.config).await?;
                self.clients
                    .lock()
                    .await
                    .entry(key.clone())
                    .or_insert_with(|| client.clone())
                    .clone()
            };
            match client.send_request_recoverable(request).await {
                Ok(response) => return Ok(response),
                Err(H2SendError::Failed(error)) => return Err(error),
                Err(H2SendError::NotSent(returned, error)) => {
                    self.remove_if_current(&key, &client).await;
                    if retried {
                        return Err(error);
                    }
                    retried = true;
                    request = *returned;
                }
            }
        }
    }

    async fn remove_if_current(&self, key: &H2PoolKey, failed: &H2Client) {
        let mut clients = self.clients.lock().await;
        if clients
            .get(key)
            .is_some_and(|current| current.same_connection(failed))
        {
            clients.remove(key);
        }
    }

    pub async fn connection_count(&self) -> usize {
        self.clients.lock().await.len()
    }
}

fn recv_body(stream: RecvStream) -> ProxyBody {
    ProxyBody::new(H2RecvBody {
        stream,
        data_done: false,
        trailers_done: false,
    })
}

struct H2RecvBody {
    stream: RecvStream,
    data_done: bool,
    trailers_done: bool,
}

struct BodyChannel {
    receiver: mpsc::Receiver<Result<BodyFrame, ProtocolError>>,
}

impl Stream for BodyChannel {
    type Item = Result<BodyFrame, ProtocolError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.poll_recv(context)
    }
}

impl Stream for H2RecvBody {
    type Item = Result<BodyFrame, ProtocolError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if !self.data_done {
            match self.stream.poll_data(context) {
                Poll::Ready(Some(Ok(data))) => {
                    if let Err(error) = self.stream.flow_control().release_capacity(data.len()) {
                        self.data_done = true;
                        self.trailers_done = true;
                        return Poll::Ready(Some(Err(map_h2_error(error))));
                    }
                    return Poll::Ready(Some(Ok(BodyFrame::Data(data))));
                }
                Poll::Ready(Some(Err(error))) => {
                    self.data_done = true;
                    self.trailers_done = true;
                    return Poll::Ready(Some(Err(map_h2_error(error))));
                }
                Poll::Ready(None) => self.data_done = true,
                Poll::Pending => return Poll::Pending,
            }
        }
        if self.trailers_done {
            return Poll::Ready(None);
        }
        match self.stream.poll_trailers(context) {
            Poll::Ready(Ok(Some(trailers))) => {
                self.trailers_done = true;
                Poll::Ready(Some(from_h2_trailers(&trailers).map(BodyFrame::Trailers)))
            }
            Poll::Ready(Ok(None)) => {
                self.trailers_done = true;
                Poll::Ready(None)
            }
            Poll::Ready(Err(error)) => {
                self.trailers_done = true;
                Poll::Ready(Some(Err(map_h2_error(error))))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

async fn send_body(send: &mut SendStream<Bytes>, mut body: ProxyBody) -> Result<(), ProtocolError> {
    let mut trailers_sent = false;
    while let Some(frame) = body.next().await {
        if trailers_sent {
            return Err(ProtocolError::new(
                ErrorKind::ProtocolViolation,
                "HTTP/2 body emitted a frame after trailers",
            ));
        }
        match frame? {
            BodyFrame::Data(data) => send_data(send, data).await?,
            BodyFrame::Trailers(trailers) => {
                send.send_trailers(to_h2_trailers(&trailers)?)
                    .map_err(map_h2_error)?;
                trailers_sent = true;
            }
        }
    }
    if !trailers_sent {
        send.send_data(Bytes::new(), true).map_err(map_h2_error)?;
    }
    Ok(())
}

async fn send_data(send: &mut SendStream<Bytes>, mut data: Bytes) -> Result<(), ProtocolError> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let capacity = poll_fn(|context| send.poll_capacity(context))
            .await
            .ok_or_else(|| ProtocolError::new(ErrorKind::Reset, "HTTP/2 stream closed"))?
            .map_err(map_h2_error)?;
        let length = capacity.min(data.len());
        send.send_data(data.split_to(length), false)
            .map_err(map_h2_error)?;
    }
    Ok(())
}

fn body_is_known_empty(body: &ProxyBody) -> bool {
    body.exact_length() == Some(0) && !body.may_have_trailers()
}

fn reason_for_error(error: &ProtocolError) -> Reason {
    match error.kind() {
        ErrorKind::MalformedMessage | ErrorKind::ProtocolViolation => Reason::PROTOCOL_ERROR,
        ErrorKind::Reset => Reason::CANCEL,
        _ => Reason::INTERNAL_ERROR,
    }
}

fn tracing_error(error: &ProtocolError) {
    // Protocol core intentionally has no logging dependency. Connection-level
    // failures are observable through returned errors; detached stream failures
    // close/reset their h2 stream and require no process-global side effect.
    let _ = error;
}
