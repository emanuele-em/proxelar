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
