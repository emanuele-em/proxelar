//! Data models for captured HTTP requests and responses.

#![forbid(unsafe_code)]

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri, Version};
use serde::{Deserialize, Serialize};

/// A captured HTTP request.
///
/// The `time` field stores the capture timestamp as milliseconds since the Unix epoch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxiedRequest {
    #[serde(with = "http_serde::method")]
    method: Method,
    #[serde(with = "http_serde::uri")]
    uri: Uri,
    #[serde(with = "http_serde::version")]
    version: Version,
    #[serde(with = "http_serde::header_map")]
    headers: HeaderMap,
    body: Bytes,
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
        Self {
            method,
            uri,
            version,
            headers,
            body,
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
        Self { direction, opcode, time, payload, truncated }
    }
}

/// A captured HTTP response.
///
/// The `time` field stores the capture timestamp as milliseconds since the Unix epoch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxiedResponse {
    #[serde(with = "http_serde::status_code")]
    status: StatusCode,
    #[serde(with = "http_serde::version")]
    version: Version,
    #[serde(with = "http_serde::header_map")]
    headers: HeaderMap,
    body: Bytes,
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
        Self {
            status,
            version,
            headers,
            body,
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

    /// Returns the capture timestamp in milliseconds since the Unix epoch.
    pub const fn time(&self) -> i64 {
        self.time
    }
}
