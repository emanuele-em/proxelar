//! Data models for captured HTTP requests and responses.

#![forbid(unsafe_code)]

use rama::bytes::Bytes;
use rama::http::{HeaderMap, Method, StatusCode, Version};
use rama::net::uri::Uri;
use serde::{Deserialize, Serialize};

/// Capture metadata for an HTTP message body.
///
/// A body can be shorter than the bytes seen on the wire when the configured
/// capture limit is reached. Keeping that distinction in the shared model
/// prevents UIs and exporters from silently presenting a partial body as
/// complete.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct BodyMetadata {
    /// Whether the captured bytes are only a prefix of the wire body.
    pub truncated: bool,
    /// Total body bytes observed on the wire.
    pub total_seen: usize,
}

impl BodyMetadata {
    /// Metadata for a fully captured body.
    pub const fn complete(body_len: usize) -> Self {
        Self {
            truncated: false,
            total_seen: body_len,
        }
    }
}

impl Default for BodyMetadata {
    fn default() -> Self {
        Self::complete(0)
    }
}

/// A captured HTTP request.
///
/// The `time` field stores the capture timestamp as milliseconds since the Unix epoch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxiedRequest {
    method: Method,
    uri: Uri,
    version: Version,
    headers: HeaderMap,
    body: Bytes,
    #[serde(default)]
    body_metadata: BodyMetadata,
    time: i64,
}

impl ProxiedRequest {
    /// Create a new captured request snapshot.
    pub const fn new(
        method: Method,
        uri: Uri,
        version: Version,
        headers: HeaderMap,
        body: Bytes,
        time: i64,
    ) -> Self {
        let body_metadata = BodyMetadata::complete(body.len());
        Self::new_with_body_metadata(method, uri, version, headers, body, body_metadata, time)
    }

    /// Create a request snapshot with explicit body-capture metadata.
    pub const fn new_with_body_metadata(
        method: Method,
        uri: Uri,
        version: Version,
        headers: HeaderMap,
        body: Bytes,
        body_metadata: BodyMetadata,
        time: i64,
    ) -> Self {
        Self {
            method,
            uri,
            version,
            headers,
            body,
            body_metadata,
            time,
        }
    }

    /// Returns the HTTP method (GET, POST, etc.).
    pub const fn method(&self) -> &Method {
        &self.method
    }

    /// Returns the request URI.
    pub const fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Returns the HTTP version.
    pub const fn version(&self) -> Version {
        self.version
    }

    /// Returns the request headers.
    pub const fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Returns the request body bytes.
    pub const fn body(&self) -> &Bytes {
        &self.body
    }

    /// Returns body capture metadata, including truncation and wire size.
    pub const fn body_metadata(&self) -> BodyMetadata {
        self.body_metadata
    }

    /// Returns the capture timestamp in milliseconds since the Unix epoch.
    pub const fn time(&self) -> i64 {
        self.time
    }
}

/// Direction of a WebSocket frame relative to the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WsDirection {
    /// Frame sent by the client to the server.
    ClientToServer,
    /// Frame sent by the server to the client.
    ServerToClient,
}

/// WebSocket frame opcode (RFC 6455).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WsOpcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

/// Direction of raw stream bytes relative to the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamDirection {
    ClientToServer,
    ServerToClient,
}

/// Captured chunk from a raw TCP stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpChunk {
    pub direction: StreamDirection,
    pub time: i64,
    pub payload: Bytes,
    pub truncated: bool,
}

/// A single captured WebSocket frame.
///
/// `payload` is the unmasked application data, capped at 100 MB (consistent
/// with `MAX_BODY_SIZE`). `time` is milliseconds since the Unix epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsFrame {
    pub direction: WsDirection,
    pub opcode: WsOpcode,
    pub time: i64,
    pub payload: Bytes,
    pub truncated: bool,
}

impl WsFrame {
    pub fn new(
        direction: WsDirection,
        opcode: WsOpcode,
        time: i64,
        payload: Bytes,
        truncated: bool,
    ) -> Self {
        Self {
            direction,
            opcode,
            time,
            payload,
            truncated,
        }
    }
}

/// A captured HTTP response.
///
/// The `time` field stores the capture timestamp as milliseconds since the Unix epoch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxiedResponse {
    status: StatusCode,
    version: Version,
    headers: HeaderMap,
    body: Bytes,
    #[serde(default)]
    body_metadata: BodyMetadata,
    time: i64,
}

impl ProxiedResponse {
    /// Create a new captured response snapshot.
    pub const fn new(
        status: StatusCode,
        version: Version,
        headers: HeaderMap,
        body: Bytes,
        time: i64,
    ) -> Self {
        let body_metadata = BodyMetadata::complete(body.len());
        Self::new_with_body_metadata(status, version, headers, body, body_metadata, time)
    }

    /// Create a response snapshot with explicit body-capture metadata.
    pub const fn new_with_body_metadata(
        status: StatusCode,
        version: Version,
        headers: HeaderMap,
        body: Bytes,
        body_metadata: BodyMetadata,
        time: i64,
    ) -> Self {
        Self {
            status,
            version,
            headers,
            body,
            body_metadata,
            time,
        }
    }

    /// Returns the HTTP status code.
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns the HTTP version.
    pub const fn version(&self) -> Version {
        self.version
    }

    /// Returns the response headers.
    pub const fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Returns the response body bytes.
    pub const fn body(&self) -> &Bytes {
        &self.body
    }

    /// Returns body capture metadata, including truncation and wire size.
    pub const fn body_metadata(&self) -> BodyMetadata {
        self.body_metadata
    }

    /// Returns the capture timestamp in milliseconds since the Unix epoch.
    pub const fn time(&self) -> i64 {
        self.time
    }
}

/// Current version of Proxelar's portable session format.
pub const SESSION_FORMAT_VERSION: u32 = 1;

/// A completed HTTP request/response exchange stored in a session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapturedFlow {
    pub id: u64,
    pub request: ProxiedRequest,
    pub response: ProxiedResponse,
}

/// A captured WebSocket connection and its frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedWebSocket {
    pub id: u64,
    pub request: ProxiedRequest,
    pub response: ProxiedResponse,
    pub frames: Vec<WsFrame>,
    pub closed: bool,
}

/// Versioned, portable capture session shared by the CLI, API, and exporters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficSession {
    pub version: u32,
    pub created_at: i64,
    #[serde(default)]
    pub flows: Vec<CapturedFlow>,
    #[serde(default)]
    pub websockets: Vec<CapturedWebSocket>,
    #[serde(default)]
    pub tcp_streams: Vec<CapturedTcpStream>,
    #[serde(default)]
    pub dns_exchanges: Vec<CapturedDnsExchange>,
    #[serde(default)]
    pub udp_exchanges: Vec<CapturedUdpExchange>,
}

impl TrafficSession {
    pub const fn new(created_at: i64) -> Self {
        Self {
            version: SESSION_FORMAT_VERSION,
            created_at,
            flows: Vec::new(),
            websockets: Vec::new(),
            tcp_streams: Vec::new(),
            dns_exchanges: Vec::new(),
            udp_exchanges: Vec::new(),
        }
    }
}

/// A raw TCP stream captured when HTTP/WebSocket decoding does not apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedTcpStream {
    pub id: u64,
    pub target: String,
    pub opened_at: i64,
    #[serde(default)]
    pub chunks: Vec<TcpChunk>,
    pub closed: bool,
}

/// A DNS query and its eventual response from DNS proxy mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedDnsExchange {
    pub id: u64,
    pub name: String,
    pub query_type: u16,
    pub time: i64,
    #[serde(default)]
    pub answers: Vec<String>,
    pub overridden: bool,
    pub completed: bool,
}

/// A request/response datagram pair observed by raw UDP proxy mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedUdpExchange {
    pub id: u64,
    pub target: String,
    pub client: String,
    pub time: i64,
    pub request: Bytes,
    pub response: Bytes,
    #[serde(default)]
    pub response_received: bool,
    pub request_truncated: bool,
    pub response_truncated: bool,
}
