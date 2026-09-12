//! Tokio I/O for quiche's sans-I/O QUIC and HTTP/3 state machines.
//!
//! Only this task touches a connection. Body queues and UDP dispatch are bounded;
//! stream backpressure never awaits inside the shared listener.
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf as _, Bytes};
use futures_util::future::poll_fn;
use quiche::h3::{Event, Header};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::PollSender;

use super::*;

const PACKET_SIZE: usize = 1350;
const BODY_CHUNK: usize = 16 * 1024;
const MAX_CONNECTIONS: usize = 1024;
const REQUEST_CANCELLED: u64 = 0x10c;
const MESSAGE_ERROR: u64 = 0x10e;
const INTERNAL_ERROR: u64 = 0x102;

pub(super) enum OutboundFrame {
    Headers(Vec<Header>),
    Body(Bytes, bool),
    Trailers(Vec<Header>),
    PeerStreamError,
}

pub(super) enum InboundFrame {
    Body(Bytes, bool),
    Trailers(HeaderBlock),
    Error(ProtocolError),
}

pub(super) struct IncomingH3Headers {
    pub headers: Vec<Header>,
    pub send: OutboundFrameSender,
    pub recv: InboundFrameStream,
}

pub(super) struct ClientRequest {
    pub request: ProxyRequest,
    pub response: oneshot::Sender<Result<ProxyResponse, ProtocolError>>,
}

pub(super) fn connection_id() -> Result<quiche::ConnectionId<'static>, ProtocolError> {
    let mut id = vec![0; quiche::MAX_CONN_ID_LEN];
    getrandom::fill(&mut id).map_err(|e| protocol(ErrorKind::Io, e))?;
    Ok(quiche::ConnectionId::from_vec(id))
}

pub(super) fn transport_config(
    tls: boring::ssl::SslContextBuilder,
) -> Result<quiche::Config, ProtocolError> {
    let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, tls)
        .map_err(|e| protocol(ErrorKind::Io, e))?;
    config
        .set_application_protos(&[b"h3"])
        .map_err(|e| protocol(ErrorKind::Io, e))?;
    config.set_max_idle_timeout(30_000);
    config.set_max_recv_udp_payload_size(65_527);
    config.set_max_send_udp_payload_size(PACKET_SIZE);
    config.set_initial_max_data(4 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_local(256 * 1024);
    config.set_initial_max_stream_data_bidi_remote(256 * 1024);
    config.set_initial_max_stream_data_uni(64 * 1024);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(3);
    config.set_disable_active_migration(true);
    // Early data and QUIC datagrams remain disabled. This endpoint serves h3 only.
    Ok(config)
}

struct Datagram {
    bytes: Vec<u8>,
    peer: SocketAddr,
}

pub(in crate::proxy) struct H3Listener {
    socket: Arc<UdpSocket>,
    config: quiche::Config,
}

impl H3Listener {
    pub(in crate::proxy) async fn bind(
        address: SocketAddr,
        config: quiche::Config,
    ) -> io::Result<Self> {
        Ok(Self {
            socket: Arc::new(UdpSocket::bind(address).await?),
            config,
        })
    }

    pub(in crate::proxy) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub(in crate::proxy) async fn serve<S, F>(mut self, service: F) -> Result<(), ProtocolError>
    where
        S: HttpService + Clone + 'static,
        F: Fn(SocketAddr) -> S,
    {
        let local = self.local_addr().map_err(|e| protocol(ErrorKind::Io, e))?;
        let mut routes: HashMap<Vec<u8>, mpsc::Sender<Datagram>> = HashMap::new();
        let mut tasks = JoinSet::new();
        let mut buffer = vec![0; 65_535];
        loop {
            tokio::select! {
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Ok((initial, id))) = completed {
                        routes.remove(&initial);
                        routes.remove(&id);
                    }
                }
                packet = self.socket.recv_from(&mut buffer) => {
                    let (length, peer) = packet.map_err(|e| protocol(ErrorKind::Io, e))?;
                    let Ok(header) = quiche::Header::from_slice(&mut buffer[..length], quiche::MAX_CONN_ID_LEN) else { continue; };
                    let dcid = header.dcid.to_vec();
                    if let Some(route) = routes.get(&dcid) {
                        // QUIC retransmits packets dropped by a saturated flow.
                        let _ = route.try_send(Datagram { bytes: buffer[..length].to_vec(), peer });
                        continue;
                    }
                    if header.ty != quiche::Type::Initial || length < 1200 || tasks.len() >= MAX_CONNECTIONS {
                        continue;
                    }
                    if !quiche::version_is_supported(header.version) {
                        let mut output = [0; PACKET_SIZE];
                        if let Ok(length) = quiche::negotiate_version(&header.scid, &header.dcid, &mut output) {
                            // Never hold up the shared receive loop on UDP send pressure.
                            let _ = self.socket.try_send_to(&output[..length], peer);
                        }
                        continue;
                    }
                    let id = connection_id()?;
                    let connection = quiche::accept(&id, None, local, peer, &mut self.config)
                        .map_err(|e| protocol(ErrorKind::Io, e))?;
                    let (send, receive) = mpsc::channel(128);
                    let _ = send.try_send(Datagram { bytes: buffer[..length].to_vec(), peer });
                    routes.insert(dcid.clone(), send.clone());
                    routes.insert(id.to_vec(), send);
                    let socket = Arc::clone(&self.socket);
                    let service = service(peer);
                    tasks.spawn(async move {
                        let mut driver = Driver::new(connection, socket, Some(receive));
                        if let Err(error) = driver.run(Some(service), None, None).await {
                            tracing::debug!("HTTP/3 connection failed: {error}");
                        }
                        (dcid, id.to_vec())
                    });
                }
            }
        }
    }
}

pub(super) async fn connect(
    socket: UdpSocket,
    connection: quiche::Connection,
) -> Result<H3Client, ProtocolError> {
    let (requests, receiver) = mpsc::channel(32);
    let (ready, received) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut driver = Driver::new(connection, Arc::new(socket), None);
        if let Err(error) = driver
            .run::<NoService>(None, Some(receiver), Some(ready))
            .await
        {
            tracing::debug!("HTTP/3 upstream connection failed: {error}");
        }
    });
    match tokio::time::timeout(DEFAULT_HANDSHAKE_TIMEOUT, received).await {
        Ok(Ok(())) => Ok(H3Client { requests }),
        result => {
            task.abort();
            Err(protocol(
                if result.is_err() {
                    ErrorKind::Timeout
                } else {
                    ErrorKind::Io
                },
                "HTTP/3 handshake failed",
            ))
        }
    }
}

#[derive(Clone)]
struct NoService;
impl HttpService for NoService {
    fn call(&mut self, _: ProxyRequest) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
        Box::pin(async {
            Err(protocol(
                ErrorKind::Unsupported,
                "client cannot serve requests",
            ))
        })
    }
}

struct StreamState {
    inbound: PollSender<InboundFrame>,
    inbound_closed: BoxFuture<'static, ()>,
    is_client: bool,
    outbound: mpsc::Receiver<OutboundFrame>,
    pending_out: Option<OutboundFrame>,
    pending_in: VecDeque<InboundFrame>,
    readable: bool,
    read_finished: bool,
    write_finished: bool,
    headers_sent: bool,
    response: Option<oneshot::Sender<Result<ProxyResponse, ProtocolError>>>,
    response_body: Option<InboundFrameStream>,
    informational: Vec<proxelar_proto::ResponseHead>,
    task: Option<tokio::task::AbortHandle>,
}

impl StreamState {
    fn new(headers_sent: bool) -> (Self, OutboundFrameSender, InboundFrameStream) {
        let (incoming, body) = mpsc::channel(4);
        let (outgoing, outbound) = mpsc::channel(4);
        let closed = incoming.clone();
        (
            Self {
                inbound: PollSender::new(incoming),
                inbound_closed: Box::pin(async move { closed.closed().await }),
                is_client: headers_sent,
                outbound,
                pending_out: None,
                pending_in: VecDeque::new(),
                readable: false,
                read_finished: false,
                write_finished: false,
                headers_sent,
                response: None,
                response_body: None,
                informational: Vec::new(),
                task: None,
            },
            PollSender::new(outgoing),
            body,
        )
    }
}

impl Drop for StreamState {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

struct Packet {
    bytes: Vec<u8>,
    info: quiche::SendInfo,
}

struct Driver {
    connection: quiche::Connection,
    http3: Option<quiche::h3::Connection>,
    socket: Arc<UdpSocket>,
    datagrams: Option<mpsc::Receiver<Datagram>>,
    streams: HashMap<u64, StreamState>,
    pending_request: Option<ClientRequest>,
    packets: VecDeque<Packet>,
    tasks: JoinSet<()>,
    requests_seen: u64,
    goaway: bool,
}

impl Driver {
    fn new(
        connection: quiche::Connection,
        socket: Arc<UdpSocket>,
        datagrams: Option<mpsc::Receiver<Datagram>>,
    ) -> Self {
        Self {
            connection,
            http3: None,
            socket,
            datagrams,
            streams: HashMap::new(),
            pending_request: None,
            packets: VecDeque::new(),
            tasks: JoinSet::new(),
            requests_seen: 0,
            goaway: false,
        }
    }

    async fn run<S: HttpService + Clone + 'static>(
        &mut self,
        service: Option<S>,
        mut requests: Option<mpsc::Receiver<ClientRequest>>,
        mut ready: Option<oneshot::Sender<()>>,
    ) -> Result<(), ProtocolError> {
        let local = self
            .socket
            .local_addr()
            .map_err(|e| protocol(ErrorKind::Io, e))?;
        let socket = Arc::clone(&self.socket);
        let mut datagrams = self.datagrams.take();
        let handshake_deadline = Instant::now() + DEFAULT_HANDSHAKE_TIMEOUT;
        let mut buffer = vec![0; 65_535];
        loop {
            if self.http3.is_none() && self.connection.is_established() {
                if self.connection.application_proto() != b"h3" {
                    return Err(protocol(
                        ErrorKind::ProtocolViolation,
                        "HTTP/3 ALPN was not negotiated",
                    ));
                }
                self.http3 = Some(
                    quiche::h3::Connection::with_transport(
                        &mut self.connection,
                        &default_http3_settings()?,
                    )
                    .map_err(|e| protocol(ErrorKind::ProtocolViolation, e))?,
                );
                if let Some(ready) = ready.take() {
                    let _ = ready.send(());
                }
            }
            self.events(service.as_ref())?;
            if self.goaway {
                if let Some(requests) = requests.as_mut() {
                    requests.close();
                }
            }
            self.queue_packets()?;
            if self.connection.is_closed() {
                return Ok(());
            }
            let deadline = self
                .connection
                .timeout()
                .map(|timeout| Instant::now() + timeout);
            let deadline = if self.http3.is_none() {
                Some(deadline.map_or(handshake_deadline, |d| d.min(handshake_deadline)))
            } else {
                deadline
            };
            let send_at = self
                .packets
                .front()
                .map(|packet| Instant::from_std(packet.info.at));
            tokio::select! {
                ready = writable_at(&socket, send_at), if send_at.is_some() => {
                    ready.map_err(|e| protocol(ErrorKind::Io, e))?;
                    self.send_packets()?;
                }
                packet = receive(&socket, &mut datagrams, &mut buffer) => {
                    let Some(mut packet) = packet.map_err(|e| protocol(ErrorKind::Io, e))? else { return Ok(()); };
                    match self.connection.recv(&mut packet.bytes, quiche::RecvInfo { from: packet.peer, to: local }) {
                        Ok(_) | Err(quiche::Error::Done) => {},
                        Err(error) => tracing::trace!("Discarding QUIC packet: {error}"),
                    }
                }
                () = wait_deadline(deadline) => {
                    if self.http3.is_none() && Instant::now() >= handshake_deadline {
                        return Err(protocol(ErrorKind::Timeout, "HTTP/3 handshake timed out"));
                    }
                    self.connection.on_timeout();
                }
                progress = poll_fn(|cx| self.poll_application(cx)), if self.http3.is_some() => { progress?; }
                request = async { requests.as_mut().expect("guarded request receiver").recv().await }, if requests.is_some() && self.pending_request.is_none() => {
                    match request {
                        Some(request) => self.pending_request = Some(request),
                        None => {
                            requests = None;
                            if self.streams.is_empty() { return Ok(()); }
                        }
                    }
                }
            }
            if service.is_none() && requests.is_none() && self.streams.is_empty() {
                return Ok(());
            }
        }
    }

    fn queue_packets(&mut self) -> Result<(), ProtocolError> {
        let mut bytes = [0; PACKET_SIZE];
        while self.packets.len() < 64 {
            match self.connection.send(&mut bytes) {
                Ok((length, info)) => self.packets.push_back(Packet {
                    bytes: bytes[..length].to_vec(),
                    info,
                }),
                Err(quiche::Error::Done) => break,
                Err(error) => return Err(protocol(ErrorKind::Io, error)),
            }
        }
        Ok(())
    }

    fn send_packets(&mut self) -> Result<(), ProtocolError> {
        while let Some(packet) = self.packets.front() {
            if Instant::from_std(packet.info.at) > Instant::now() {
                break;
            }
            match self.socket.try_send_to(&packet.bytes, packet.info.to) {
                Ok(_) => {
                    self.packets.pop_front();
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(protocol(ErrorKind::Io, error)),
            }
        }
        Ok(())
    }

    fn events<S: HttpService + Clone + 'static>(
        &mut self,
        service: Option<&S>,
    ) -> Result<(), ProtocolError> {
        let Some(http3) = self.http3.as_mut() else {
            return Ok(());
        };
        loop {
            let (id, event) = match http3.poll(&mut self.connection) {
                Ok(event) => event,
                Err(quiche::h3::Error::Done) => break,
                Err(error) => return Err(protocol(ErrorKind::ProtocolViolation, error)),
            };
            match event {
                Event::Headers { list, .. } => {
                    if let Some(stream) = self.streams.get_mut(&id) {
                        if let Err(error) = receive_headers(stream, &list) {
                            reset(&mut self.connection, id, MESSAGE_ERROR);
                            if let Some(response) = stream.response.take() {
                                let _ = response.send(Err(protocol(ErrorKind::Reset, &error)));
                            }
                            self.streams.remove(&id);
                            tracing::debug!("Rejected HTTP/3 headers on stream {id}: {error}");
                        }
                    } else if let Some(service) = service {
                        if self.requests_seen >= DEFAULT_MAX_REQUESTS_PER_CONNECTION {
                            reset(&mut self.connection, id, 0x10b);
                            continue;
                        }
                        self.requests_seen += 1;
                        let (mut state, send, recv) = StreamState::new(false);
                        let service = service.clone();
                        state.task = Some(self.tasks.spawn(async move {
                            handle_server_request(
                                service,
                                IncomingH3Headers {
                                    headers: list,
                                    send,
                                    recv,
                                },
                            )
                            .await;
                        }));
                        self.streams.insert(id, state);
                        if self.requests_seen == DEFAULT_MAX_REQUESTS_PER_CONNECTION {
                            http3
                                .send_goaway(&mut self.connection, id + 4)
                                .map_err(|e| protocol(ErrorKind::ProtocolViolation, e))?;
                        }
                    }
                }
                Event::Data => {
                    if let Some(stream) = self.streams.get_mut(&id) {
                        stream.readable = true;
                    } else {
                        reset(&mut self.connection, id, REQUEST_CANCELLED);
                    }
                }
                Event::Finished => {
                    if let Some(stream) = self.streams.get_mut(&id) {
                        stream.read_finished = true;
                        stream
                            .pending_in
                            .push_back(InboundFrame::Body(Bytes::new(), true));
                    }
                }
                Event::Reset(code) => {
                    if let Some(mut stream) = self.streams.remove(&id) {
                        if let Some(response) = stream.response.take() {
                            let _ = response.send(Err(protocol(
                                ErrorKind::Reset,
                                format!("HTTP/3 stream reset: {code}"),
                            )));
                        }
                        let _ = self
                            .connection
                            .stream_shutdown(id, quiche::Shutdown::Write, code);
                    }
                }
                Event::GoAway => self.goaway = true,
                Event::PriorityUpdate => {
                    let _ = http3.take_last_priority_update(id);
                }
            }
        }
        Ok(())
    }

    fn poll_application(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ProtocolError>> {
        let http3 = self.http3.as_mut().expect("established HTTP/3");
        let mut progress = false;
        while let Poll::Ready(Some(_)) = self.tasks.poll_join_next(cx) {
            progress = true;
        }
        let awaiting_settings = self
            .pending_request
            .as_ref()
            .is_some_and(|r| is_extended_websocket(&r.request))
            && http3.peer_settings_raw().is_none();
        if let Some(request) = self.pending_request.take_if(|_| !awaiting_settings) {
            if request.response.is_closed() {
                progress = true;
            } else if is_extended_websocket(&request.request)
                && !http3.extended_connect_enabled_by_peer()
            {
                let _ = request.response.send(Err(protocol(
                    ErrorKind::Unsupported,
                    "HTTP/3 peer did not enable extended CONNECT",
                )));
                progress = true;
            } else if self.goaway {
                let _ = request
                    .response
                    .send(Err(protocol(ErrorKind::Io, "HTTP/3 peer is draining")));
                progress = true;
            } else {
                let headers = match encode_request_headers(&request.request.head) {
                    Ok(headers) => headers,
                    Err(error) => {
                        let _ = request.response.send(Err(error));
                        return Poll::Ready(Ok(()));
                    }
                };
                match http3.send_request(&mut self.connection, &headers, false) {
                    Ok(id) => {
                        let (mut stream, sender, body) = StreamState::new(true);
                        stream.response = Some(request.response);
                        stream.response_body = Some(body);
                        stream.task = Some(self.tasks.spawn(async move {
                            let reset_sender = sender.clone();
                            if let Err(error) = send_body(sender, request.request.body).await {
                                tracing::debug!("HTTP/3 request body failed: {error}");
                                send_stream_error(reset_sender).await;
                            }
                        }));
                        self.streams.insert(id, stream);
                        progress = true;
                    }
                    Err(
                        quiche::h3::Error::StreamBlocked
                        | quiche::h3::Error::TransportError(quiche::Error::StreamLimit),
                    ) => self.pending_request = Some(request),
                    Err(error) => {
                        let _ = request.response.send(Err(protocol(ErrorKind::Io, error)));
                        progress = true;
                    }
                }
            }
        }
        let mut finished = Vec::new();
        for (&id, stream) in &mut self.streams {
            if !stream.read_finished && stream.inbound_closed.as_mut().poll(cx).is_ready() {
                if stream.is_client {
                    reset(&mut self.connection, id, REQUEST_CANCELLED);
                    finished.push(id);
                    progress = true;
                    continue;
                }
                let _ =
                    self.connection
                        .stream_shutdown(id, quiche::Shutdown::Read, REQUEST_CANCELLED);
                stream.read_finished = true;
                stream.readable = false;
                stream.pending_in.clear();
                progress = true;
            }
            if stream
                .response
                .as_mut()
                .is_some_and(|response| response.poll_closed(cx).is_ready())
            {
                reset(&mut self.connection, id, REQUEST_CANCELLED);
                finished.push(id);
                progress = true;
                continue;
            }
            if !stream.write_finished {
                if stream.pending_out.is_none() {
                    match stream.outbound.poll_recv(cx) {
                        Poll::Ready(Some(frame)) => stream.pending_out = Some(frame),
                        Poll::Ready(None) => {
                            reset(&mut self.connection, id, INTERNAL_ERROR);
                            finished.push(id);
                            progress = true;
                            continue;
                        }
                        Poll::Pending => {}
                    }
                }
                if let Some(frame) = stream.pending_out.as_mut() {
                    let result = match frame {
                        OutboundFrame::Headers(headers) => {
                            if stream.headers_sent {
                                http3.send_additional_headers(
                                    &mut self.connection,
                                    id,
                                    headers,
                                    false,
                                    false,
                                )
                            } else {
                                http3.send_response(&mut self.connection, id, headers, false)
                            }
                        }
                        OutboundFrame::Trailers(headers) => http3.send_additional_headers(
                            &mut self.connection,
                            id,
                            headers,
                            true,
                            true,
                        ),
                        OutboundFrame::Body(data, fin) => http3
                            .send_body(&mut self.connection, id, data, *fin)
                            .map(|written| {
                                data.advance(written);
                            }),
                        OutboundFrame::PeerStreamError => {
                            reset(&mut self.connection, id, INTERNAL_ERROR);
                            finished.push(id);
                            progress = true;
                            continue;
                        }
                    };
                    match result {
                        Ok(()) => {
                            let complete =
                                !matches!(frame, OutboundFrame::Body(data, _) if !data.is_empty());
                            if complete {
                                stream.write_finished = matches!(
                                    frame,
                                    OutboundFrame::Trailers(_) | OutboundFrame::Body(_, true)
                                );
                                stream.headers_sent = true;
                                stream.pending_out = None;
                            }
                            progress = true;
                        }
                        Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => {}
                        Err(error) => {
                            tracing::debug!("HTTP/3 send failed on stream {id}: {error}");
                            reset(&mut self.connection, id, INTERNAL_ERROR);
                            finished.push(id);
                            progress = true;
                            continue;
                        }
                    }
                }
            }
            if stream.readable || !stream.pending_in.is_empty() || !stream.read_finished {
                match stream.inbound.poll_reserve(cx) {
                    Poll::Ready(Ok(())) => {
                        // DATA must be drained before delivering trailers or FIN.
                        if stream.readable {
                            let mut buffer = [0; BODY_CHUNK];
                            match http3.recv_body(&mut self.connection, id, &mut buffer) {
                                Ok(length) => {
                                    let _ = stream.inbound.send_item(InboundFrame::Body(
                                        Bytes::copy_from_slice(&buffer[..length]),
                                        false,
                                    ));
                                    progress = true;
                                    continue;
                                }
                                Err(quiche::h3::Error::Done) => stream.readable = false,
                                Err(error) => {
                                    stream.pending_in.clear();
                                    stream.pending_in.push_back(InboundFrame::Error(protocol(
                                        ErrorKind::Reset,
                                        error,
                                    )));
                                    stream.readable = false;
                                    stream.read_finished = true;
                                }
                            }
                        }
                        if let Some(frame) = stream.pending_in.pop_front() {
                            let _ = stream.inbound.send_item(frame);
                            progress = true;
                        }
                    }
                    Poll::Ready(Err(_)) => {
                        let _ = self.connection.stream_shutdown(
                            id,
                            quiche::Shutdown::Read,
                            REQUEST_CANCELLED,
                        );
                        stream.read_finished = true;
                        stream.readable = false;
                        stream.pending_in.clear();
                        progress = true;
                    }
                    Poll::Pending => {}
                }
            }
            if stream.read_finished
                && stream.write_finished
                && stream.pending_in.is_empty()
                && !stream.readable
            {
                finished.push(id);
            }
        }
        for id in finished {
            if let Some(mut stream) = self.streams.remove(&id) {
                if let Some(response) = stream.response.take() {
                    let _ = response.send(Err(protocol(
                        ErrorKind::Reset,
                        "HTTP/3 stream ended before response headers",
                    )));
                }
            }
        }
        if progress {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

fn reset(connection: &mut quiche::Connection, id: u64, code: u64) {
    let _ = connection.stream_shutdown(id, quiche::Shutdown::Read, code);
    let _ = connection.stream_shutdown(id, quiche::Shutdown::Write, code);
}

async fn receive(
    socket: &UdpSocket,
    datagrams: &mut Option<mpsc::Receiver<Datagram>>,
    buffer: &mut [u8],
) -> io::Result<Option<Datagram>> {
    match datagrams {
        Some(datagrams) => Ok(datagrams.recv().await),
        None => {
            let (length, peer) = socket.recv_from(buffer).await?;
            Ok(Some(Datagram {
                bytes: buffer[..length].to_vec(),
                peer,
            }))
        }
    }
}

async fn wait_deadline(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) if deadline > Instant::now() => tokio::time::sleep_until(deadline).await,
        Some(_) => {}
        None => std::future::pending().await,
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        let _ = self.connection.close(true, 0x100, b"endpoint closed");
        let mut packet = [0; PACKET_SIZE];
        // Best effort, nonblocking close when a listener or request owner is dropped.
        while let Ok((length, info)) = self.connection.send(&mut packet) {
            if self.socket.try_send_to(&packet[..length], info.to).is_err() {
                break;
            }
        }
    }
}

fn receive_headers(stream: &mut StreamState, headers: &[Header]) -> Result<(), ProtocolError> {
    if stream.response.is_some() {
        let head = decode_response_headers(headers)?;
        if head.status.is_informational() {
            if head.status == StatusCode::SWITCHING_PROTOCOLS || stream.informational.len() >= 16 {
                return Err(protocol(
                    ErrorKind::ProtocolViolation,
                    "invalid or excessive HTTP/3 informational responses",
                ));
            }
            stream.informational.push(head);
        } else {
            let response = ProxyResponse::new(
                head,
                inbound_body(stream.response_body.take().expect("pending response body")),
            )
            .with_informational(std::mem::take(&mut stream.informational));
            let _ = stream
                .response
                .take()
                .expect("pending response")
                .send(Ok(response));
        }
    } else {
        let trailers = from_quiche_headers(headers)?;
        // Apply the common multiplexed-header trailer rules before delivery.
        proxelar_proto::http2::to_h2_trailers(&trailers)?;
        stream
            .pending_in
            .push_back(InboundFrame::Trailers(trailers));
    }
    Ok(())
}

async fn writable_at(socket: &UdpSocket, deadline: Option<Instant>) -> io::Result<()> {
    // Queue first, then wait once for the earliest packet. All packets due at
    // that wakeup can be sent together, avoiding a timer tick per datagram.
    wait_deadline(deadline).await;
    socket.writable().await
}
