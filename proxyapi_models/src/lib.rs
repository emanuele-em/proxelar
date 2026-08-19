//! Data models for captured HTTP requests and responses.

#![forbid(unsafe_code)]

use std::fmt;

use base64::Engine as _;
use bytes::Bytes;
use http::{Method, StatusCode, Uri, Version};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

/// A validation error for an HTTP header field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderFieldError {
    /// Header names must contain at least one token character.
    EmptyName,
    /// A byte is not valid in an RFC 9110 field name.
    InvalidName { index: usize, byte: u8 },
    /// A byte is not valid in an RFC 9110 field value.
    InvalidValue { index: usize, byte: u8 },
}

impl fmt::Display for HeaderFieldError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyName => formatter.write_str("HTTP header name is empty"),
            Self::InvalidName { index, byte } => write!(
                formatter,
                "invalid byte 0x{byte:02x} at HTTP header name offset {index}"
            ),
            Self::InvalidValue { index, byte } => write!(
                formatter,
                "invalid byte 0x{byte:02x} at HTTP header value offset {index}"
            ),
        }
    }
}

impl std::error::Error for HeaderFieldError {}

/// One ordered, byte-safe HTTP header field.
///
/// Names retain the casing received on HTTP/1 connections. An initial colon is
/// accepted for native HTTP/2 and HTTP/3 pseudo-headers; protocol adapters are
/// responsible for enforcing where pseudo-headers are legal and for lowercasing
/// names on protocols that require it. Values accept visible ASCII, horizontal
/// tabs, and RFC 9110 `obs-text`, so non-UTF-8 wire values remain lossless.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct HeaderField {
    name: Bytes,
    value: Bytes,
}

impl HeaderField {
    /// Construct and validate a header field.
    pub fn new(name: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> Result<Self, HeaderFieldError> {
        let name = name.as_ref();
        let value = value.as_ref();
        validate_name(name)?;
        validate_value(value)?;
        Ok(Self {
            name: Bytes::copy_from_slice(name),
            value: Bytes::copy_from_slice(value),
        })
    }

    /// Return the original, case-preserving field name bytes.
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Return the field value bytes.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Return whether this field has the supplied name, using HTTP's ASCII
    /// case-insensitive comparison rules.
    pub fn name_eq(&self, name: impl AsRef<[u8]>) -> bool {
        self.name.eq_ignore_ascii_case(name.as_ref())
    }
}

impl fmt::Debug for HeaderField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeaderField")
            .field("name", &String::from_utf8_lossy(&self.name))
            .field("value", &String::from_utf8_lossy(&self.value))
            .finish()
    }
}

impl Serialize for HeaderField {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct as _;

        let mut state = serializer.serialize_struct("HeaderField", 2)?;
        let name = std::str::from_utf8(&self.name).expect("validated header names are ASCII");
        state.serialize_field("name", name)?;
        if let Ok(value) = std::str::from_utf8(&self.value) {
            state.serialize_field("value", value)?;
        } else {
            state.serialize_field(
                "value_base64",
                &base64::engine::general_purpose::STANDARD.encode(&self.value),
            )?;
        }
        state.end()
    }
}

impl<'de> Deserialize<'de> for HeaderField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireHeaderField {
            name: String,
            #[serde(default)]
            value: Option<String>,
            #[serde(default)]
            value_base64: Option<String>,
        }

        let field = WireHeaderField::deserialize(deserializer)?;
        let value = match (field.value, field.value_base64) {
            (Some(value), None) => value.into_bytes(),
            (None, Some(value)) => base64::engine::general_purpose::STANDARD
                .decode(value)
                .map_err(de::Error::custom)?,
            (Some(_), Some(_)) => {
                return Err(de::Error::custom(
                    "header field must not contain both value and value_base64",
                ));
            }
            (None, None) => {
                return Err(de::Error::custom(
                    "header field must contain value or value_base64",
                ));
            }
        };
        Self::new(field.name, value).map_err(de::Error::custom)
    }
}

/// An ordered HTTP header block that preserves duplicates and field casing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HeaderBlock(Vec<HeaderField>);

impl HeaderBlock {
    /// Construct an empty header block.
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Construct a header block from fields without reordering them.
    pub fn from_fields(fields: impl IntoIterator<Item = HeaderField>) -> Self {
        Self(fields.into_iter().collect())
    }

    /// Return the number of fields, including duplicates.
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Return whether the block contains no fields.
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate through fields in wire order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &HeaderField> {
        self.0.iter()
    }

    /// Append a field after all existing fields.
    pub fn push(&mut self, field: HeaderField) {
        self.0.push(field);
    }

    /// Validate and append a field after all existing fields.
    pub fn add(
        &mut self,
        name: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<(), HeaderFieldError> {
        self.push(HeaderField::new(name, value)?);
        Ok(())
    }

    /// Return the first value for a name, using ASCII case-insensitive matching.
    pub fn get(&self, name: impl AsRef<[u8]>) -> Option<&[u8]> {
        let name = name.as_ref();
        self.0
            .iter()
            .find(|field| field.name_eq(name))
            .map(HeaderField::value)
    }

    /// Return whether the block contains at least one field with this name.
    pub fn contains_key(&self, name: impl AsRef<[u8]>) -> bool {
        self.get(name).is_some()
    }

    /// Iterate through every value for a name in wire order.
    pub fn get_all(&self, name: impl AsRef<[u8]>) -> impl Iterator<Item = &[u8]> {
        let name = Bytes::copy_from_slice(name.as_ref());
        self.0
            .iter()
            .filter(move |field| field.name_eq(&name))
            .map(HeaderField::value)
    }

    /// Replace all fields with a name at the position of their first
    /// occurrence. If the name is absent, append the new field.
    pub fn set(
        &mut self,
        name: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<(), HeaderFieldError> {
        let replacement = HeaderField::new(name, value)?;
        let first = self
            .0
            .iter()
            .position(|field| field.name_eq(replacement.name()));
        self.0.retain(|field| !field.name_eq(replacement.name()));
        let index = first.unwrap_or(self.0.len()).min(self.0.len());
        self.0.insert(index, replacement);
        Ok(())
    }

    /// Remove every field with the supplied name and return the number removed.
    pub fn remove(&mut self, name: impl AsRef<[u8]>) -> usize {
        let name = name.as_ref();
        let previous_len = self.0.len();
        self.0.retain(|field| !field.name_eq(name));
        previous_len - self.0.len()
    }
}

impl FromIterator<HeaderField> for HeaderBlock {
    fn from_iter<T: IntoIterator<Item = HeaderField>>(iter: T) -> Self {
        Self::from_fields(iter)
    }
}

impl IntoIterator for HeaderBlock {
    type Item = HeaderField;
    type IntoIter = std::vec::IntoIter<HeaderField>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a HeaderBlock {
    type Item = &'a HeaderField;
    type IntoIter = std::slice::Iter<'a, HeaderField>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

fn validate_name(name: &[u8]) -> Result<(), HeaderFieldError> {
    let token = if let Some(token) = name.strip_prefix(b":") {
        token
    } else {
        name
    };
    if token.is_empty() {
        return Err(HeaderFieldError::EmptyName);
    }
    for (index, byte) in token.iter().copied().enumerate() {
        if !is_token(byte) {
            let pseudo_offset = usize::from(name.starts_with(b":"));
            return Err(HeaderFieldError::InvalidName {
                index: index + pseudo_offset,
                byte,
            });
        }
    }
    Ok(())
}

const fn is_token(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#'..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'0'..=b'9' | b'A'..=b'Z'
            | b'^'..=b'z' | b'|' | b'~'
    )
}

fn validate_value(value: &[u8]) -> Result<(), HeaderFieldError> {
    for (index, byte) in value.iter().copied().enumerate() {
        if !matches!(byte, b'\t' | b' '..=b'~' | 0x80..=0xff) {
            return Err(HeaderFieldError::InvalidValue { index, byte });
        }
    }
    Ok(())
}

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
    #[serde(with = "http_serde::method")]
    method: Method,
    #[serde(with = "http_serde::uri")]
    uri: Uri,
    #[serde(with = "http_serde::version")]
    version: Version,
    headers: HeaderBlock,
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
        headers: HeaderBlock,
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
        headers: HeaderBlock,
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
    pub const fn headers(&self) -> &HeaderBlock {
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
    #[serde(with = "http_serde::status_code")]
    status: StatusCode,
    #[serde(with = "http_serde::version")]
    version: Version,
    headers: HeaderBlock,
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
        headers: HeaderBlock,
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
        headers: HeaderBlock,
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
    pub const fn headers(&self) -> &HeaderBlock {
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
pub const SESSION_FORMAT_VERSION: u32 = 2;

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
