//! Portable capture sessions and interoperable export formats.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::Path;

use base64::Engine as _;
use chrono::{TimeZone as _, Utc};
use proxyapi_models::{
    BodyMetadata, CapturedDnsExchange, CapturedFlow, CapturedTcpStream, CapturedWebSocket,
    ProxiedRequest, ProxiedResponse, TrafficSession, WsDirection, WsFrame, WsOpcode,
    SESSION_FORMAT_VERSION,
};
use rama::bytes::Bytes;
use rama::http::convert::curl::{
    cmd_string_for_request_parts_with_options,
    try_cmd_string_for_request_parts_and_payload_with_options, CurlExportOptions,
    CurlScriptCompatibility, CurlScriptPayloadMode,
};
use rama::http::layer::har::spec::{
    Request as HarRequest, Response as HarResponse, WebSocketMessage, WebSocketMessageType,
};
use rama::http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version,
};
use rama::net::uri::Uri;
use rama::net::Protocol;
use serde_json::{json, Value};
use thiserror::Error;

use crate::ProxyEvent;

/// Errors produced while reading, writing, importing, or exporting sessions.
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("session I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid session JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported session format version {found}; this build supports {supported}")]
    UnsupportedVersion { found: u32, supported: u32 },
    #[error("invalid HAR: {0}")]
    InvalidHar(String),
    #[error("invalid native session: {0}")]
    InvalidSession(String),
    #[error("invalid HTTP value in imported capture: {0}")]
    InvalidHttp(String),
}

/// Secret-removal policy applied to exports.
#[derive(Clone, Debug)]
pub struct RedactionPolicy {
    header_names: HashSet<HeaderName>,
    query_names: HashSet<String>,
    replacement: String,
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self::new(
            [
                "authorization",
                "proxy-authorization",
                "cookie",
                "set-cookie",
            ],
            [
                "access_token",
                "api_key",
                "apikey",
                "password",
                "secret",
                "token",
            ],
        )
    }
}

impl RedactionPolicy {
    pub fn new<H, Q, HS, QS>(headers: H, query: Q) -> Self
    where
        H: IntoIterator<Item = HS>,
        Q: IntoIterator<Item = QS>,
        HS: AsRef<str>,
        QS: AsRef<str>,
    {
        Self {
            header_names: headers
                .into_iter()
                .filter_map(|name| HeaderName::from_bytes(name.as_ref().as_bytes()).ok())
                .collect(),
            query_names: query
                .into_iter()
                .map(|name| name.as_ref().to_ascii_lowercase())
                .collect(),
            replacement: "[REDACTED]".to_owned(),
        }
    }

    pub fn with_replacement(mut self, replacement: impl Into<String>) -> Self {
        self.replacement = replacement.into();
        self
    }

    fn redact_headers(&self, headers: &HeaderMap) -> HeaderMap {
        let mut redacted = HeaderMap::new();
        for (name, value) in headers.ordered_iter() {
            let value = if self.header_names.contains(name) {
                HeaderValue::from_str(&self.replacement)
                    .unwrap_or_else(|_| HeaderValue::from_static("[REDACTED]"))
            } else {
                value.clone()
            };
            redacted.append(name.clone(), value);
        }
        redacted
    }

    fn redact_uri(&self, uri: &Uri) -> Uri {
        let query = uri.query_or_empty();
        if query.is_empty() {
            return uri.clone();
        }
        let mut changed = false;
        let redacted_query = query
            .split('&')
            .map(|pair| {
                let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                if self.query_names.contains(&name.to_ascii_lowercase()) {
                    changed = true;
                    format!("{name}={}", self.replacement)
                } else if value.is_empty() && !pair.contains('=') {
                    name.to_owned()
                } else {
                    format!("{name}={value}")
                }
            })
            .collect::<Vec<_>>()
            .join("&");
        if !changed {
            return uri.clone();
        }

        uri.clone().with_query_from_bytes(redacted_query)
    }

    fn redact_request(&self, request: &ProxiedRequest) -> ProxiedRequest {
        ProxiedRequest::new_with_body_metadata(
            request.method().clone(),
            self.redact_uri(request.uri()),
            request.version(),
            self.redact_headers(request.headers()),
            request.body().clone(),
            request.body_metadata(),
            request.time(),
        )
    }

    fn redact_response(&self, response: &ProxiedResponse) -> ProxiedResponse {
        ProxiedResponse::new_with_body_metadata(
            response.status(),
            response.version(),
            self.redact_headers(response.headers()),
            response.body().clone(),
            response.body_metadata(),
            response.time(),
        )
    }
}

/// In-memory collector used by interfaces, persistence, and the REST API.
#[derive(Debug)]
pub struct SessionRecorder {
    session: TrafficSession,
}

impl Default for SessionRecorder {
    fn default() -> Self {
        Self::new(Utc::now().timestamp_millis())
    }
}

impl SessionRecorder {
    pub const fn new(created_at: i64) -> Self {
        Self {
            session: TrafficSession::new(created_at),
        }
    }

    pub fn from_session(session: TrafficSession) -> Result<Self, SessionError> {
        let session = migrate_session(session)?;
        let largest_id = session
            .flows
            .iter()
            .map(|flow| flow.id)
            .chain(session.websockets.iter().map(|flow| flow.id))
            .chain(session.tcp_streams.iter().map(|stream| stream.id))
            .chain(session.dns_exchanges.iter().map(|exchange| exchange.id))
            .chain(session.udp_exchanges.iter().map(|exchange| exchange.id))
            .max()
            .unwrap_or(0);
        if largest_id == u64::MAX {
            return Err(SessionError::InvalidSession(
                "flow identifiers must be smaller than u64::MAX".to_owned(),
            ));
        }
        crate::event::reserve_ids_through(largest_id);
        Ok(Self { session })
    }

    pub const fn session(&self) -> &TrafficSession {
        &self.session
    }

    pub fn snapshot(&self) -> TrafficSession {
        self.session.clone()
    }

    pub fn clear(&mut self) {
        self.session.flows.clear();
        self.session.websockets.clear();
        self.session.tcp_streams.clear();
        self.session.dns_exchanges.clear();
        self.session.udp_exchanges.clear();
    }

    /// Apply a proxy event to the session. Pending and error events are not
    /// persisted because they do not represent replayable wire exchanges.
    pub fn record(&mut self, event: &ProxyEvent) {
        match event {
            ProxyEvent::RequestComplete {
                id,
                request,
                response,
            } => {
                let flow = CapturedFlow {
                    id: *id,
                    request: request.as_ref().clone(),
                    response: response.as_ref().clone(),
                };
                if let Some(existing) = self.session.flows.iter_mut().find(|flow| flow.id == *id) {
                    *existing = flow;
                } else {
                    self.session.flows.push(flow);
                }
            }
            ProxyEvent::WebSocketConnected {
                id,
                request,
                response,
            } => {
                let connection = CapturedWebSocket {
                    id: *id,
                    request: request.as_ref().clone(),
                    response: response.as_ref().clone(),
                    frames: Vec::new(),
                    closed: false,
                };
                if let Some(existing) = self
                    .session
                    .websockets
                    .iter_mut()
                    .find(|connection| connection.id == *id)
                {
                    *existing = connection;
                } else {
                    self.session.websockets.push(connection);
                }
            }
            ProxyEvent::WebSocketFrame { conn_id, frame } => {
                if let Some(connection) = self
                    .session
                    .websockets
                    .iter_mut()
                    .find(|connection| connection.id == *conn_id)
                {
                    connection.frames.push(frame.as_ref().clone());
                }
            }
            ProxyEvent::WebSocketClosed { conn_id } => {
                if let Some(connection) = self
                    .session
                    .websockets
                    .iter_mut()
                    .find(|connection| connection.id == *conn_id)
                {
                    connection.closed = true;
                }
            }
            ProxyEvent::TcpConnected {
                id,
                target,
                opened_at,
            } => {
                self.session.tcp_streams.push(CapturedTcpStream {
                    id: *id,
                    target: target.clone(),
                    opened_at: *opened_at,
                    chunks: Vec::new(),
                    closed: false,
                });
            }
            ProxyEvent::TcpData { stream_id, chunk } => {
                if let Some(stream) = self
                    .session
                    .tcp_streams
                    .iter_mut()
                    .find(|stream| stream.id == *stream_id)
                {
                    const MAX_CHUNKS_PER_STREAM: usize = 10_000;
                    if stream.chunks.len() < MAX_CHUNKS_PER_STREAM {
                        stream.chunks.push(chunk.as_ref().clone());
                    }
                }
            }
            ProxyEvent::TcpClosed { stream_id } => {
                if let Some(stream) = self
                    .session
                    .tcp_streams
                    .iter_mut()
                    .find(|stream| stream.id == *stream_id)
                {
                    stream.closed = true;
                }
            }
            ProxyEvent::DnsQuery {
                id,
                name,
                query_type,
                time,
            } => {
                self.session.dns_exchanges.push(CapturedDnsExchange {
                    id: *id,
                    name: name.clone(),
                    query_type: *query_type,
                    time: *time,
                    answers: Vec::new(),
                    overridden: false,
                    completed: false,
                });
            }
            ProxyEvent::DnsResponse {
                id,
                answers,
                overridden,
            } => {
                if let Some(exchange) = self
                    .session
                    .dns_exchanges
                    .iter_mut()
                    .find(|exchange| exchange.id == *id)
                {
                    exchange.answers.clone_from(answers);
                    exchange.overridden = *overridden;
                    exchange.completed = true;
                }
            }
            ProxyEvent::RequestIntercepted { .. } | ProxyEvent::Error { .. } => {}
            ProxyEvent::UdpExchange { exchange } => {
                if let Some(existing) = self
                    .session
                    .udp_exchanges
                    .iter_mut()
                    .find(|existing| existing.id == exchange.id)
                {
                    existing.clone_from(exchange);
                } else {
                    self.session.udp_exchanges.push(exchange.as_ref().clone());
                }
            }
        }
    }
}

pub fn save_session(path: impl AsRef<Path>, session: &TrafficSession) -> Result<(), SessionError> {
    validate_version(session)?;
    let bytes = serde_json::to_vec_pretty(session)?;
    write_private(path.as_ref(), &bytes)?;
    Ok(())
}

pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        options.mode(0o600);
        let mut file = options.open(path)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut file = options.open(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }
}

pub fn load_session(path: impl AsRef<Path>) -> Result<TrafficSession, SessionError> {
    let bytes = fs::read(path)?;
    let session = serde_json::from_slice(&bytes)?;
    migrate_session(session)
}

/// Recreate the public event stream represented by a stored session.
///
/// Interfaces use this to display imported history through the same code path
/// as live traffic.
pub fn session_events(session: &TrafficSession) -> Vec<ProxyEvent> {
    let http_events = session
        .flows
        .iter()
        .map(|flow| ProxyEvent::RequestComplete {
            id: flow.id,
            request: Box::new(flow.request.clone()),
            response: Box::new(flow.response.clone()),
        });
    let websocket_events = session.websockets.iter().flat_map(|connection| {
        let connected = std::iter::once(ProxyEvent::WebSocketConnected {
            id: connection.id,
            request: Box::new(connection.request.clone()),
            response: Box::new(connection.response.clone()),
        });
        let frames = connection
            .frames
            .iter()
            .cloned()
            .map(|frame| ProxyEvent::WebSocketFrame {
                conn_id: connection.id,
                frame: Box::new(frame),
            });
        let closed = connection
            .closed
            .then_some(ProxyEvent::WebSocketClosed {
                conn_id: connection.id,
            })
            .into_iter();
        connected.chain(frames).chain(closed)
    });
    let tcp_events = session.tcp_streams.iter().flat_map(|stream| {
        let connected = std::iter::once(ProxyEvent::TcpConnected {
            id: stream.id,
            target: stream.target.clone(),
            opened_at: stream.opened_at,
        });
        let chunks = stream
            .chunks
            .iter()
            .cloned()
            .map(|chunk| ProxyEvent::TcpData {
                stream_id: stream.id,
                chunk: Box::new(chunk),
            });
        let closed = stream
            .closed
            .then_some(ProxyEvent::TcpClosed {
                stream_id: stream.id,
            })
            .into_iter();
        connected.chain(chunks).chain(closed)
    });
    let dns_events = session.dns_exchanges.iter().flat_map(|exchange| {
        let query = std::iter::once(ProxyEvent::DnsQuery {
            id: exchange.id,
            name: exchange.name.clone(),
            query_type: exchange.query_type,
            time: exchange.time,
        });
        let response = exchange
            .completed
            .then(|| ProxyEvent::DnsResponse {
                id: exchange.id,
                answers: exchange.answers.clone(),
                overridden: exchange.overridden,
            })
            .into_iter();
        query.chain(response)
    });
    let udp_events =
        session
            .udp_exchanges
            .iter()
            .cloned()
            .map(|exchange| ProxyEvent::UdpExchange {
                exchange: Box::new(exchange),
            });
    http_events
        .chain(websocket_events)
        .chain(tcp_events)
        .chain(dns_events)
        .chain(udp_events)
        .collect()
}

fn validate_version(session: &TrafficSession) -> Result<(), SessionError> {
    if session.version != SESSION_FORMAT_VERSION {
        return Err(SessionError::UnsupportedVersion {
            found: session.version,
            supported: SESSION_FORMAT_VERSION,
        });
    }
    Ok(())
}

fn migrate_session(mut session: TrafficSession) -> Result<TrafficSession, SessionError> {
    match session.version {
        // Version 2 changed headers from name-keyed objects to ordered
        // [name, value] tuples. proxyapi_models accepts both representations,
        // so migration only needs to advance the version marker.
        1 => session.version = SESSION_FORMAT_VERSION,
        SESSION_FORMAT_VERSION => {}
        _ => {
            return Err(SessionError::UnsupportedVersion {
                found: session.version,
                supported: SESSION_FORMAT_VERSION,
            });
        }
    }
    Ok(session)
}

pub fn export_har(
    path: impl AsRef<Path>,
    session: &TrafficSession,
    redaction: Option<&RedactionPolicy>,
) -> Result<(), SessionError> {
    let mut entries: Vec<(i64, u64, Value)> = session
        .flows
        .iter()
        .map(|flow| (flow.request.time(), flow.id, har_entry(flow, redaction)))
        .chain(session.websockets.iter().map(|connection| {
            (
                connection.request.time(),
                connection.id,
                har_websocket_entry(connection, redaction),
            )
        }))
        .collect();
    entries.sort_by_key(|(time, id, _)| (*time, *id));
    let entries = entries
        .into_iter()
        .map(|(_, _, entry)| entry)
        .collect::<Vec<_>>();
    let har = json!({
        "log": {
            "version": "1.2",
            "creator": { "name": "Proxelar", "version": env!("CARGO_PKG_VERSION") },
            "entries": entries
        }
    });
    fs::write(path, serde_json::to_vec_pretty(&har)?)?;
    Ok(())
}

fn har_entry(flow: &CapturedFlow, redaction: Option<&RedactionPolicy>) -> Value {
    har_exchange_entry(&flow.request, &flow.response, redaction)
}

fn har_websocket_entry(
    connection: &CapturedWebSocket,
    redaction: Option<&RedactionPolicy>,
) -> Value {
    let mut uri = connection.request.uri().clone();
    match uri.scheme() {
        Some(scheme) if scheme == &Protocol::HTTP => {
            uri.set_scheme(Protocol::WS);
        }
        Some(scheme) if scheme == &Protocol::HTTPS => {
            uri.set_scheme(Protocol::WSS);
        }
        _ => {}
    }
    let request = ProxiedRequest::new_with_body_metadata(
        connection.request.method().clone(),
        uri,
        connection.request.version(),
        connection.request.headers().clone(),
        connection.request.body().clone(),
        connection.request.body_metadata(),
        connection.request.time(),
    );
    let mut entry = har_exchange_entry(&request, &connection.response, redaction);
    let object = entry
        .as_object_mut()
        .expect("HAR entries are always JSON objects");
    object.insert("_resourceType".to_owned(), json!("websocket"));
    object.insert(
        "_webSocketMessages".to_owned(),
        Value::Array(
            connection
                .frames
                .iter()
                .filter_map(har_websocket_message)
                .collect(),
        ),
    );
    entry
}

fn har_websocket_message(frame: &WsFrame) -> Option<Value> {
    let direction = match frame.direction {
        WsDirection::ClientToServer => WebSocketMessageType::Send,
        WsDirection::ServerToClient => WebSocketMessageType::Receive,
    };
    let time = frame.time as f64 / 1_000.0;
    let message = match frame.opcode {
        WsOpcode::Text => WebSocketMessage::text(
            direction,
            time,
            String::from_utf8_lossy(&frame.payload).into_owned(),
        ),
        WsOpcode::Binary => WebSocketMessage::binary(direction, time, &frame.payload),
        // Chromium's HAR extension stores complete data messages, not control
        // frames or fragmentation details. Keep those in the native session.
        WsOpcode::Continuation | WsOpcode::Close | WsOpcode::Ping | WsOpcode::Pong => return None,
    };
    let mut value = serde_json::to_value(message).expect("WebSocket HAR message serializes");
    if frame.truncated {
        value
            .as_object_mut()
            .expect("WebSocket HAR messages are JSON objects")
            .insert("_proxelarTruncated".to_owned(), Value::Bool(true));
    }
    Some(value)
}

fn har_exchange_entry(
    captured_request: &ProxiedRequest,
    captured_response: &ProxiedResponse,
    redaction: Option<&RedactionPolicy>,
) -> Value {
    let request = redaction
        .map(|policy| policy.redact_request(captured_request))
        .unwrap_or_else(|| captured_request.clone());
    let response = redaction
        .map(|policy| policy.redact_response(captured_response))
        .unwrap_or_else(|| captured_response.clone());
    let duration = response.time().saturating_sub(request.time()).max(0);
    let started = Utc
        .timestamp_millis_opt(request.time())
        .single()
        .unwrap_or_else(Utc::now)
        .to_rfc3339();
    let request = har_request(&request);
    let response = har_response(&response);

    json!({
        "startedDateTime": started,
        "time": duration,
        "request": request,
        "response": response,
        "cache": {},
        "timings": { "send": 0, "wait": duration, "receive": 0 }
    })
}

fn har_request(captured: &ProxiedRequest) -> HarRequest {
    let mut request = Request::builder()
        .method(captured.method().clone())
        .uri(captured.uri().clone())
        .version(captured.version())
        .body(())
        .expect("captured request parts remain valid");
    *request.headers_mut() = captured.headers().clone();
    let (parts, ()) = request.into_parts();
    let mut request = HarRequest::from_http_request_parts(&parts, captured.body(), true)
        .expect("captured request converts to HAR");
    request.body_size = i64::try_from(captured.body_metadata().total_seen).unwrap_or(i64::MAX);
    request.comment = truncation_comment(captured.body_metadata()).map(Into::into);
    if let Some(post_data) = request.post_data.as_mut() {
        post_data.comment = truncation_comment(captured.body_metadata()).map(Into::into);
    }
    request
}

fn har_response(captured: &ProxiedResponse) -> HarResponse {
    let mut response = Response::builder()
        .status(captured.status())
        .version(captured.version())
        .body(())
        .expect("captured response parts remain valid");
    *response.headers_mut() = captured.headers().clone();
    let (parts, ()) = response.into_parts();
    let mut response = HarResponse::from_http_response_parts(&parts, captured.body(), true)
        .expect("captured response converts to HAR");
    let total_seen = i64::try_from(captured.body_metadata().total_seen).unwrap_or(i64::MAX);
    response.body_size = total_seen;
    response.content.size = total_seen;
    response.comment = truncation_comment(captured.body_metadata()).map(Into::into);
    response.content.comment = truncation_comment(captured.body_metadata()).map(Into::into);
    response
}

fn truncation_comment(metadata: BodyMetadata) -> Option<String> {
    metadata.truncated.then(|| {
        format!(
            "Body truncated by Proxelar; captured prefix, observed {} wire bytes",
            metadata.total_seen
        )
    })
}

pub fn export_curl(
    path: impl AsRef<Path>,
    session: &TrafficSession,
    redaction: Option<&RedactionPolicy>,
) -> Result<(), SessionError> {
    let mut output = String::new();
    for flow in &session.flows {
        let request = redaction
            .map(|policy| policy.redact_request(&flow.request))
            .unwrap_or_else(|| flow.request.clone());
        writeln!(output, "# flow {}", flow.id).expect("writing to String cannot fail");

        // Delegate the curl command to rama. `Unix` script compatibility keeps
        // binary bodies replayable (base64-piped) in the generated shell script.
        let req = curl_request(&request)?;
        let options =
            CurlExportOptions::default().with_script_compatibility(CurlScriptCompatibility::Unix);
        let command = if request.body().is_empty() {
            cmd_string_for_request_parts_with_options(&req, options)
        } else {
            try_cmd_string_for_request_parts_and_payload_with_options(
                &req,
                request.body(),
                options,
                &CurlScriptPayloadMode::Inline,
            )
            .map_err(|error| SessionError::InvalidHttp(error.to_string()))?
        };
        output.push_str(&command);
        output.push_str("\n\n");
    }
    fs::write(path, output)?;
    Ok(())
}

/// Rebuild a bodyless rama request from a captured snapshot so rama's curl
/// exporter can read its method, URI, version and headers. The body is passed
/// to the exporter separately.
fn curl_request(request: &ProxiedRequest) -> Result<Request<()>, SessionError> {
    let mut req = Request::builder()
        .method(request.method().clone())
        .uri(request.uri().clone())
        .version(request.version())
        .body(())
        .map_err(|error| SessionError::InvalidHttp(error.to_string()))?;
    *req.headers_mut() = request.headers().clone();
    Ok(req)
}

pub fn export_raw(
    directory: impl AsRef<Path>,
    session: &TrafficSession,
    redaction: Option<&RedactionPolicy>,
) -> Result<(), SessionError> {
    let directory = directory.as_ref();
    fs::create_dir_all(directory)?;
    for flow in &session.flows {
        let request = redaction
            .map(|policy| policy.redact_request(&flow.request))
            .unwrap_or_else(|| flow.request.clone());
        let response = redaction
            .map(|policy| policy.redact_response(&flow.response))
            .unwrap_or_else(|| flow.response.clone());
        fs::write(
            directory.join(format!("{:08}-request.http", flow.id)),
            raw_request(&request),
        )?;
        fs::write(
            directory.join(format!("{:08}-response.http", flow.id)),
            raw_response(&response),
        )?;
    }
    Ok(())
}

fn raw_request(request: &ProxiedRequest) -> Vec<u8> {
    let path = request.uri().path_or_root();
    let raw_query = request.uri().query_or_empty();
    let target = if raw_query.is_empty() {
        path.into_owned()
    } else {
        format!("{path}?{raw_query}")
    };
    let mut output = format!(
        "{} {} {}\r\n",
        request.method(),
        target,
        version_string(request.version())
    )
    .into_bytes();
    append_headers_and_body(&mut output, request.headers(), request.body());
    output
}

fn raw_response(response: &ProxiedResponse) -> Vec<u8> {
    let mut output = format!(
        "{} {} {}\r\n",
        version_string(response.version()),
        response.status().as_u16(),
        response.status().canonical_reason().unwrap_or("")
    )
    .into_bytes();
    append_headers_and_body(&mut output, response.headers(), response.body());
    output
}

fn append_headers_and_body(output: &mut Vec<u8>, headers: &HeaderMap, body: &Bytes) {
    for (name, value) in headers.ordered_iter() {
        output.extend_from_slice(name.as_original_str().as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(body);
}

fn version_string(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
    }
}

/// Import the HTTP entries in a HAR 1.2 file into a Proxelar session.
pub fn import_har(path: impl AsRef<Path>) -> Result<TrafficSession, SessionError> {
    let data: Value = serde_json::from_slice(&fs::read(path)?)?;
    let entries = data
        .pointer("/log/entries")
        .and_then(Value::as_array)
        .ok_or_else(|| SessionError::InvalidHar("missing log.entries array".to_owned()))?;
    let mut session = TrafficSession::new(Utc::now().timestamp_millis());
    for (index, entry) in entries.iter().enumerate() {
        session.flows.push(import_har_entry(index, entry)?);
    }
    Ok(session)
}

fn import_har_entry(index: usize, entry: &Value) -> Result<CapturedFlow, SessionError> {
    let request = entry
        .get("request")
        .ok_or_else(|| SessionError::InvalidHar(format!("entry {index} missing request")))?;
    let response = entry
        .get("response")
        .ok_or_else(|| SessionError::InvalidHar(format!("entry {index} missing response")))?;
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("GET")
        .parse::<Method>()
        .map_err(|error| SessionError::InvalidHttp(error.to_string()))?;
    let uri = request
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| SessionError::InvalidHar(format!("entry {index} missing request.url")))?
        .parse::<Uri>()
        .map_err(|error| SessionError::InvalidHttp(error.to_string()))?;
    let status = StatusCode::from_u16(
        response
            .get("status")
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
            .unwrap_or(200),
    )
    .map_err(|error| SessionError::InvalidHttp(error.to_string()))?;
    let started = entry
        .get("startedDateTime")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map_or_else(
            || Utc::now().timestamp_millis(),
            |value| value.timestamp_millis(),
        );
    let duration = entry.get("time").and_then(Value::as_f64).unwrap_or(0.0) as i64;
    let request_headers = import_har_headers(request.get("headers"))?;
    let response_headers = import_har_headers(response.get("headers"))?;
    let request_body = import_har_body(request.get("postData"))?;
    let response_body = import_har_body(response.get("content"))?;

    Ok(CapturedFlow {
        id: u64::try_from(index + 1).unwrap_or(u64::MAX),
        request: ProxiedRequest::new(
            method,
            uri,
            parse_version(request.get("httpVersion")),
            request_headers,
            request_body,
            started,
        ),
        response: ProxiedResponse::new(
            status,
            parse_version(response.get("httpVersion")),
            response_headers,
            response_body,
            started.saturating_add(duration),
        ),
    })
}

fn import_har_headers(value: Option<&Value>) -> Result<HeaderMap, SessionError> {
    let mut headers = HeaderMap::new();
    for header in value.and_then(Value::as_array).into_iter().flatten() {
        let Some(name) = header.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(value) = header.get("value").and_then(Value::as_str) else {
            continue;
        };
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|error| SessionError::InvalidHttp(error.to_string()))?;
        let value = HeaderValue::from_str(value)
            .map_err(|error| SessionError::InvalidHttp(error.to_string()))?;
        headers.append(name, value);
    }
    Ok(headers)
}

fn import_har_body(value: Option<&Value>) -> Result<Bytes, SessionError> {
    let Some(value) = value else {
        return Ok(Bytes::new());
    };
    let Some(text) = value.get("text").and_then(Value::as_str) else {
        return Ok(Bytes::new());
    };
    if value.get("encoding").and_then(Value::as_str) == Some("base64") {
        return base64::engine::general_purpose::STANDARD
            .decode(text)
            .map(Bytes::from)
            .map_err(|error| SessionError::InvalidHar(error.to_string()));
    }
    Ok(Bytes::copy_from_slice(text.as_bytes()))
}

fn parse_version(value: Option<&Value>) -> Version {
    match value.and_then(Value::as_str).unwrap_or("HTTP/1.1") {
        "HTTP/0.9" => Version::HTTP_09,
        "HTTP/1.0" => Version::HTTP_10,
        "HTTP/2" | "HTTP/2.0" => Version::HTTP_2,
        "HTTP/3" | "HTTP/3.0" => Version::HTTP_3,
        _ => Version::HTTP_11,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn flow(id: u64) -> CapturedFlow {
        let mut request_headers = HeaderMap::new();
        request_headers.append("cookie", "secret=one".parse().unwrap());
        request_headers.append("x-repeat", "one".parse().unwrap());
        request_headers.append("x-repeat", "two".parse().unwrap());
        let mut response_headers = HeaderMap::new();
        response_headers.insert("content-type", "application/json".parse().unwrap());
        CapturedFlow {
            id,
            request: ProxiedRequest::new(
                Method::POST,
                "https://example.test/path?token=secret".parse().unwrap(),
                Version::HTTP_11,
                request_headers,
                Bytes::from_static(b"request"),
                1_000,
            ),
            response: ProxiedResponse::new(
                StatusCode::OK,
                Version::HTTP_11,
                response_headers,
                Bytes::from_static(br#"{"ok":true}"#),
                1_025,
            ),
        }
    }

    #[test]
    fn recorder_tracks_http_websocket_and_dns_lifecycle() {
        let captured = flow(7);
        let mut recorder = SessionRecorder::new(1);
        recorder.record(&ProxyEvent::RequestComplete {
            id: captured.id,
            request: Box::new(captured.request.clone()),
            response: Box::new(captured.response.clone()),
        });
        recorder.record(&ProxyEvent::WebSocketConnected {
            id: 8,
            request: Box::new(captured.request.clone()),
            response: Box::new(captured.response.clone()),
        });
        recorder.record(&ProxyEvent::WebSocketClosed { conn_id: 8 });
        recorder.record(&ProxyEvent::DnsQuery {
            id: 9,
            name: "api.example.test".to_owned(),
            query_type: 1,
            time: 1_000,
        });
        recorder.record(&ProxyEvent::DnsResponse {
            id: 9,
            answers: vec!["127.0.0.1".to_owned()],
            overridden: true,
        });
        recorder.record(&ProxyEvent::UdpExchange {
            exchange: Box::new(proxyapi_models::CapturedUdpExchange {
                id: 10,
                target: "127.0.0.1:9000".to_owned(),
                client: "127.0.0.1:50000".to_owned(),
                time: 1_001,
                request: Bytes::from_static(b"request"),
                response: Bytes::new(),
                response_received: true,
                request_truncated: false,
                response_truncated: false,
            }),
        });

        assert_eq!(recorder.session().flows.len(), 1);
        assert_eq!(recorder.session().websockets.len(), 1);
        assert!(recorder.session().websockets[0].closed);
        assert_eq!(recorder.session().dns_exchanges.len(), 1);
        assert_eq!(recorder.session().dns_exchanges[0].answers, ["127.0.0.1"]);
        assert!(recorder.session().dns_exchanges[0].overridden);
        assert!(recorder.session().dns_exchanges[0].completed);
        assert_eq!(recorder.session().udp_exchanges.len(), 1);
        assert!(recorder.session().udp_exchanges[0].response_received);
    }

    #[test]
    fn native_session_roundtrip_preserves_duplicate_headers() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("capture.pxsession");
        let mut session = TrafficSession::new(1);
        session.flows.push(flow(1));

        save_session(&path, &session).unwrap();
        let loaded = load_session(&path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let repeated = loaded.flows[0]
            .request
            .headers()
            .get_all("x-repeat")
            .iter()
            .count();
        assert_eq!(repeated, 2);
    }

    #[test]
    fn loading_history_reserves_new_ids_after_existing_flows() {
        let mut session = TrafficSession::new(1);
        session.flows.push(flow(2_000_000));

        SessionRecorder::from_session(session).unwrap();

        assert!(crate::event::next_id() > 2_000_000);
    }

    #[test]
    fn exports_har_curl_and_raw_with_redaction() {
        let dir = tempdir().unwrap();
        let mut session = TrafficSession::new(1);
        session.flows.push(flow(3));
        let policy = RedactionPolicy::default();

        let har = dir.path().join("capture.har");
        let curl = dir.path().join("capture.sh");
        let raw = dir.path().join("raw");
        export_har(&har, &session, Some(&policy)).unwrap();
        export_curl(&curl, &session, Some(&policy)).unwrap();
        export_raw(&raw, &session, Some(&policy)).unwrap();

        let har_text = fs::read_to_string(har).unwrap();
        assert!(har_text.contains("[REDACTED]"));
        assert!(!har_text.contains("secret=one"));
        assert_eq!(
            import_har(dir.path().join("capture.har"))
                .unwrap()
                .flows
                .len(),
            1
        );
        assert!(fs::read_to_string(curl).unwrap().contains("curl "));
        assert!(raw.join("00000003-request.http").exists());
        assert!(raw.join("00000003-response.http").exists());
    }

    #[test]
    fn exports_websockets_in_chromium_har_format() {
        let dir = tempdir().unwrap();
        let mut session = TrafficSession::new(1);
        session.flows.push(flow(3));

        let mut request_headers = HeaderMap::new();
        request_headers.insert("authorization", "Bearer secret".parse().unwrap());
        session.websockets.push(CapturedWebSocket {
            id: 2,
            request: ProxiedRequest::new(
                Method::GET,
                "https://example.test/socket?token=secret".parse().unwrap(),
                Version::HTTP_11,
                request_headers,
                Bytes::new(),
                500,
            ),
            response: ProxiedResponse::new(
                StatusCode::SWITCHING_PROTOCOLS,
                Version::HTTP_11,
                HeaderMap::new(),
                Bytes::new(),
                525,
            ),
            frames: vec![
                WsFrame::new(
                    WsDirection::ClientToServer,
                    WsOpcode::Text,
                    1_500,
                    Bytes::from_static(b"hello"),
                    false,
                ),
                WsFrame::new(
                    WsDirection::ServerToClient,
                    WsOpcode::Binary,
                    1_600,
                    Bytes::from_static(&[0, 1, 2, 0xaa]),
                    true,
                ),
                WsFrame::new(
                    WsDirection::ServerToClient,
                    WsOpcode::Ping,
                    1_700,
                    Bytes::from_static(b"ping"),
                    false,
                ),
            ],
            closed: true,
        });

        let path = dir.path().join("websocket.har");
        export_har(&path, &session, Some(&RedactionPolicy::default())).unwrap();
        let har: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let entries = har["log"]["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        let websocket = &entries[0];
        assert_eq!(websocket["_resourceType"], "websocket");
        assert_eq!(
            websocket["request"]["url"],
            "wss://example.test/socket?token=%5BREDACTED%5D"
        );
        assert_eq!(websocket["request"]["headers"][0]["value"], "[REDACTED]");

        let raw_messages = websocket["_webSocketMessages"].clone();
        assert_eq!(raw_messages[1]["_proxelarTruncated"], true);
        assert_eq!(raw_messages.as_array().unwrap().len(), 2);
        let messages: Vec<WebSocketMessage> = serde_json::from_value(raw_messages).unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].r#type, WebSocketMessageType::Send);
        assert_eq!(
            messages[0].opcode,
            rama::http::layer::har::spec::WebSocketMessageOpcode::TEXT
        );
        assert_eq!(messages[0].data.as_str(), "hello");
        assert!((messages[0].time - 1.5).abs() < f64::EPSILON);
        assert_eq!(messages[1].r#type, WebSocketMessageType::Receive);
        assert_eq!(
            messages[1]
                .binary_data()
                .expect("binary message")
                .expect("valid base64"),
            [0, 1, 2, 0xaa]
        );
    }

    #[test]
    fn exports_headers_in_wire_order_with_original_spelling() {
        let mut headers = HeaderMap::new();
        headers.append(
            HeaderName::from_bytes(b"X-Field").unwrap(),
            HeaderValue::from_static("one"),
        );
        headers.append(
            HeaderName::from_bytes(b"Host").unwrap(),
            HeaderValue::from_static("example.test"),
        );
        headers.append(
            HeaderName::from_bytes(b"X-Field").unwrap(),
            HeaderValue::from_static("two"),
        );
        let request = ProxiedRequest::new(
            Method::GET,
            "http://example.test/".parse().unwrap(),
            Version::HTTP_11,
            headers,
            Bytes::new(),
            1,
        );

        let redacted = RedactionPolicy::default().redact_request(&request);
        let raw = String::from_utf8(raw_request(&redacted)).unwrap();
        assert!(raw.contains("X-Field: one\r\nHost: example.test\r\nX-Field: two\r\n"));
        let har_fields = har_request(&redacted)
            .headers
            .into_iter()
            .map(|header| (header.name.to_string(), header.value.to_string()))
            .collect::<Vec<_>>();
        assert_eq!(
            har_fields,
            [
                ("X-Field".to_owned(), "one".to_owned()),
                ("Host".to_owned(), "example.test".to_owned()),
                ("X-Field".to_owned(), "two".to_owned()),
            ]
        );
    }

    #[test]
    fn recorder_updates_all_flow_types_and_replays_session_events() {
        let captured = flow(11);
        let mut recorder = SessionRecorder::new(1);
        for response_status in [StatusCode::OK, StatusCode::CREATED] {
            let response = ProxiedResponse::new_with_body_metadata(
                response_status,
                captured.response.version(),
                captured.response.headers().clone(),
                captured.response.body().clone(),
                captured.response.body_metadata(),
                captured.response.time(),
            );
            recorder.record(&ProxyEvent::RequestComplete {
                id: captured.id,
                request: Box::new(captured.request.clone()),
                response: Box::new(response),
            });
        }
        recorder.record(&ProxyEvent::WebSocketConnected {
            id: 12,
            request: Box::new(captured.request.clone()),
            response: Box::new(captured.response.clone()),
        });
        recorder.record(&ProxyEvent::WebSocketConnected {
            id: 12,
            request: Box::new(captured.request.clone()),
            response: Box::new(captured.response.clone()),
        });
        let frame = proxyapi_models::WsFrame::new(
            proxyapi_models::WsDirection::ClientToServer,
            proxyapi_models::WsOpcode::Text,
            2,
            Bytes::from_static(b"hello"),
            false,
        );
        recorder.record(&ProxyEvent::WebSocketFrame {
            conn_id: 12,
            frame: Box::new(frame.clone()),
        });
        recorder.record(&ProxyEvent::WebSocketFrame {
            conn_id: 999,
            frame: Box::new(frame),
        });
        recorder.record(&ProxyEvent::WebSocketClosed { conn_id: 12 });
        recorder.record(&ProxyEvent::WebSocketClosed { conn_id: 999 });

        recorder.record(&ProxyEvent::TcpConnected {
            id: 13,
            target: "127.0.0.1:9000".to_owned(),
            opened_at: 3,
        });
        let chunk = proxyapi_models::TcpChunk {
            direction: proxyapi_models::StreamDirection::ClientToServer,
            time: 4,
            payload: Bytes::from_static(b"payload"),
            truncated: false,
        };
        recorder.record(&ProxyEvent::TcpData {
            stream_id: 13,
            chunk: Box::new(chunk.clone()),
        });
        recorder.record(&ProxyEvent::TcpData {
            stream_id: 999,
            chunk: Box::new(chunk),
        });
        recorder.record(&ProxyEvent::TcpClosed { stream_id: 13 });
        recorder.record(&ProxyEvent::TcpClosed { stream_id: 999 });

        recorder.record(&ProxyEvent::DnsQuery {
            id: 14,
            name: "example.test".to_owned(),
            query_type: 1,
            time: 5,
        });
        recorder.record(&ProxyEvent::DnsResponse {
            id: 14,
            answers: vec!["127.0.0.1".to_owned()],
            overridden: false,
        });
        recorder.record(&ProxyEvent::DnsResponse {
            id: 999,
            answers: Vec::new(),
            overridden: false,
        });

        let udp = proxyapi_models::CapturedUdpExchange {
            id: 15,
            target: "127.0.0.1:9001".to_owned(),
            client: "127.0.0.1:50000".to_owned(),
            time: 6,
            request: Bytes::from_static(b"request"),
            response: Bytes::from_static(b"response"),
            response_received: true,
            request_truncated: false,
            response_truncated: false,
        };
        recorder.record(&ProxyEvent::UdpExchange {
            exchange: Box::new(udp.clone()),
        });
        recorder.record(&ProxyEvent::UdpExchange {
            exchange: Box::new(udp),
        });

        assert_eq!(recorder.session().flows.len(), 1);
        assert_eq!(
            recorder.session().flows[0].response.status(),
            StatusCode::CREATED
        );
        assert_eq!(recorder.session().websockets[0].frames.len(), 1);
        assert!(recorder.session().tcp_streams[0].closed);
        assert_eq!(recorder.session().tcp_streams[0].chunks.len(), 1);
        assert_eq!(recorder.session().udp_exchanges.len(), 1);

        let snapshot = recorder.snapshot();
        let events = session_events(&snapshot);
        assert_eq!(events.len(), 10);
        assert!(events
            .iter()
            .any(|event| matches!(event, ProxyEvent::WebSocketClosed { conn_id: 12 })));
        assert!(events
            .iter()
            .any(|event| matches!(event, ProxyEvent::TcpClosed { stream_id: 13 })));
        assert!(events
            .iter()
            .any(|event| matches!(event, ProxyEvent::DnsResponse { id: 14, .. })));

        recorder.clear();
        assert!(recorder.session().flows.is_empty());
        assert!(recorder.session().websockets.is_empty());
        assert!(recorder.session().tcp_streams.is_empty());
        assert!(recorder.session().dns_exchanges.is_empty());
        assert!(recorder.session().udp_exchanges.is_empty());

        let default_recorder = SessionRecorder::default();
        assert!(default_recorder.session().created_at > 0);
    }

    #[test]
    fn rejects_invalid_native_sessions_and_redacts_custom_values() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("capture.pxsession");

        let mut unsupported = TrafficSession::new(1);
        unsupported.version = SESSION_FORMAT_VERSION + 1;
        assert!(matches!(
            SessionRecorder::from_session(unsupported.clone()),
            Err(SessionError::UnsupportedVersion { .. })
        ));
        assert!(matches!(
            save_session(&path, &unsupported),
            Err(SessionError::UnsupportedVersion { .. })
        ));
        std::fs::write(&path, serde_json::to_vec(&unsupported).unwrap()).unwrap();
        assert!(matches!(
            load_session(&path),
            Err(SessionError::UnsupportedVersion { .. })
        ));

        let mut maximum = TrafficSession::new(1);
        maximum.flows.push(flow(u64::MAX));
        assert!(matches!(
            SessionRecorder::from_session(maximum),
            Err(SessionError::InvalidSession(_))
        ));

        std::fs::write(&path, "{invalid").unwrap();
        assert!(matches!(load_session(&path), Err(SessionError::Json(_))));
        assert!(matches!(
            load_session(directory.path().join("missing")),
            Err(SessionError::Io(_))
        ));

        let policy = RedactionPolicy::new(["authorization", "bad header"], ["secret"])
            .with_replacement("hidden");
        let request = ProxiedRequest::new(
            Method::GET,
            "https://example.test/path?secret=value&flag&other=visible"
                .parse()
                .unwrap(),
            Version::HTTP_11,
            HeaderMap::from_iter([(
                rama::http::header::AUTHORIZATION,
                HeaderValue::from_static("Bearer secret"),
            )]),
            Bytes::new(),
            1,
        );
        let redacted = policy.redact_request(&request);
        assert_eq!(
            redacted.headers()[rama::http::header::AUTHORIZATION],
            "hidden"
        );
        assert_eq!(
            redacted.uri().query().unwrap(),
            "secret=hidden&flag&other=visible"
        );

        let unchanged: Uri = "https://example.test/no-query".parse().unwrap();
        assert_eq!(policy.redact_uri(&unchanged), unchanged);
        let visible: Uri = "https://example.test/?other=value".parse().unwrap();
        assert_eq!(policy.redact_uri(&visible), visible);

        let invalid_replacement =
            RedactionPolicy::new(["authorization"], std::iter::empty::<&str>())
                .with_replacement("bad\nvalue");
        assert_eq!(
            invalid_replacement.redact_headers(request.headers())
                [rama::http::header::AUTHORIZATION],
            "[REDACTED]"
        );
    }

    #[test]
    fn loads_and_migrates_version_one_header_objects() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("legacy.pxsession");
        let mut value = serde_json::to_value(TrafficSession::new(123)).unwrap();
        value["version"] = json!(1);
        value["flows"] = json!([{
            "id": 7,
            "request": {
                "method": "GET",
                "uri": "http://example.test/",
                "version": "HTTP/1.1",
                "headers": {"x-repeat": ["one", "two"]},
                "body": [],
                "time": 123
            },
            "response": {
                "status": 200,
                "version": "HTTP/1.1",
                "headers": {"content-type": "text/plain"},
                "body": [111, 107],
                "time": 124
            }
        }]);
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        let session = load_session(&path).unwrap();

        assert_eq!(session.version, SESSION_FORMAT_VERSION);
        assert_eq!(
            session.flows[0]
                .request
                .headers()
                .get_all("x-repeat")
                .iter()
                .count(),
            2
        );
        assert_eq!(session.flows[0].response.body().as_ref(), b"ok");
    }

    #[test]
    fn imports_har_variants_and_reports_invalid_entries() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("capture.har");
        let write = |value: Value| {
            std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        };

        write(json!({}));
        assert!(matches!(
            import_har(&path),
            Err(SessionError::InvalidHar(_))
        ));
        write(json!({"log": {"entries": [{}]}}));
        assert!(matches!(
            import_har(&path),
            Err(SessionError::InvalidHar(_))
        ));
        write(json!({"log": {"entries": [{"request": {}}]}}));
        assert!(matches!(
            import_har(&path),
            Err(SessionError::InvalidHar(_))
        ));
        write(json!({"log": {"entries": [{
            "request": {"url": "https://example.test", "method": "bad method"},
            "response": {}
        }]}}));
        assert!(matches!(
            import_har(&path),
            Err(SessionError::InvalidHttp(_))
        ));
        write(json!({"log": {"entries": [{
            "request": {"method": "GET"},
            "response": {}
        }]}}));
        assert!(matches!(
            import_har(&path),
            Err(SessionError::InvalidHar(_))
        ));
        write(json!({"log": {"entries": [{
            "request": {"url": "http://[", "method": "GET"},
            "response": {}
        }]}}));
        assert!(matches!(
            import_har(&path),
            Err(SessionError::InvalidHttp(_))
        ));
        write(json!({"log": {"entries": [{
            "request": {"url": "https://example.test", "method": "GET"},
            "response": {"status": 99}
        }]}}));
        assert!(matches!(
            import_har(&path),
            Err(SessionError::InvalidHttp(_))
        ));
        write(json!({"log": {"entries": [{
            "request": {
                "url": "https://example.test",
                "headers": [{"name": "bad header", "value": "value"}]
            },
            "response": {}
        }]}}));
        assert!(matches!(
            import_har(&path),
            Err(SessionError::InvalidHttp(_))
        ));
        write(json!({"log": {"entries": [{
            "request": {
                "url": "https://example.test",
                "headers": [{"name": "x-test", "value": "bad\nvalue"}]
            },
            "response": {}
        }]}}));
        assert!(matches!(
            import_har(&path),
            Err(SessionError::InvalidHttp(_))
        ));
        write(json!({"log": {"entries": [{
            "request": {"url": "https://example.test"},
            "response": {"content": {"text": "***", "encoding": "base64"}}
        }]}}));
        assert!(matches!(
            import_har(&path),
            Err(SessionError::InvalidHar(_))
        ));

        write(json!({"log": {"entries": [{
            "startedDateTime": "2020-01-02T03:04:05Z",
            "time": 12.5,
            "request": {
                "method": "POST",
                "url": "https://example.test/upload",
                "httpVersion": "HTTP/2.0",
                "headers": [
                    {"name": "x-repeat", "value": "one"},
                    {"name": "x-repeat", "value": "two"},
                    {"name": "ignored"}
                ],
                "postData": {"text": "aGVsbG8=", "encoding": "base64"}
            },
            "response": {
                "status": 201,
                "httpVersion": "HTTP/3.0",
                "headers": [],
                "content": {"text": "created"}
            }
        }]}}));
        let imported = import_har(&path).unwrap();
        assert_eq!(imported.flows.len(), 1);
        assert_eq!(imported.flows[0].request.version(), Version::HTTP_2);
        assert_eq!(imported.flows[0].response.version(), Version::HTTP_3);
        assert_eq!(imported.flows[0].request.body().as_ref(), b"hello");
        assert_eq!(
            imported.flows[0]
                .request
                .headers()
                .get_all("x-repeat")
                .iter()
                .count(),
            2
        );
    }

    #[test]
    fn covers_har_raw_and_http_version_helpers() {
        let binary = Bytes::from_static(&[0, 159, 146, 150]);
        let metadata = BodyMetadata {
            total_seen: 100,
            truncated: true,
        };
        let response = ProxiedResponse::new_with_body_metadata(
            StatusCode::OK,
            Version::HTTP_11,
            HeaderMap::new(),
            binary,
            metadata,
            1,
        );
        let content = har_response(&response).content;
        assert_eq!(content.encoding.as_deref(), Some("base64"));
        assert!(content
            .comment
            .as_deref()
            .unwrap()
            .contains("observed 100 wire bytes"));
        assert!(truncation_comment(BodyMetadata::complete(0)).is_none());

        assert_eq!(import_har_body(None).unwrap(), Bytes::new());
        assert_eq!(import_har_body(Some(&json!({}))).unwrap(), Bytes::new());
        assert_eq!(
            import_har_body(Some(&json!({"text": "plain"})))
                .unwrap()
                .as_ref(),
            b"plain"
        );
        assert!(import_har_headers(Some(&json!([
            {"value": "missing-name"},
            {"name": "missing-value"}
        ])))
        .unwrap()
        .is_empty());

        for (text, expected, rendered) in [
            ("HTTP/0.9", Version::HTTP_09, "HTTP/0.9"),
            ("HTTP/1.0", Version::HTTP_10, "HTTP/1.0"),
            ("HTTP/1.1", Version::HTTP_11, "HTTP/1.1"),
            ("HTTP/2", Version::HTTP_2, "HTTP/2"),
            ("HTTP/2.0", Version::HTTP_2, "HTTP/2"),
            ("HTTP/3", Version::HTTP_3, "HTTP/3"),
            ("HTTP/3.0", Version::HTTP_3, "HTTP/3"),
            ("unknown", Version::HTTP_11, "HTTP/1.1"),
        ] {
            assert_eq!(parse_version(Some(&json!(text))), expected);
            assert_eq!(version_string(expected), rendered);
        }
        assert_eq!(parse_version(None), Version::HTTP_11);

        let captured = flow(1);
        let request = raw_request(&captured.request);
        let response = raw_response(&captured.response);
        assert!(request.starts_with(b"POST /path?token=secret HTTP/1.1\r\n"));
        assert!(request.ends_with(b"\r\n\r\nrequest"));
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with(br#"{"ok":true}"#));

        let policy = RedactionPolicy::default();
        let redacted = policy.redact_response(&captured.response);
        assert_eq!(redacted.status(), StatusCode::OK);
    }
}
