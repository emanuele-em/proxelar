//! HTTP/2 header adaptation built directly on the `h2` engine's `http` API.
//!
//! The transport-neutral model keeps an ordered byte-safe block. This adapter
//! validates native HTTP/2 pseudo-headers, lowercases fields translated from
//! HTTP/1, and keeps duplicate values in their original order.

mod connection;

use std::collections::HashSet;

use h2::ext::Protocol;
use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri, Version};
use proxyapi_models::{HeaderBlock, HeaderField};

use crate::{ErrorKind, ProtocolError, RequestHead, ResponseHead};

pub use connection::{
    body_tunnel, serve_connection, ConnectionConfig, H2Client, H2Connector, H2Pool, H2PoolKey,
};

const CONNECTION_SPECIFIC: [&[u8]; 5] = [
    b"connection",
    b"keep-alive",
    b"proxy-connection",
    b"transfer-encoding",
    b"upgrade",
];

/// Translate a request head into a native ordered HTTP/2 header block.
///
/// Standard pseudo-headers are derived from the structured request fields.
/// The RFC 8441 `:protocol` pseudo-header, when present, remains represented in
/// `RequestHead::headers` because it has no transport-neutral counterpart yet.
pub fn encode_request_head(head: &RequestHead) -> Result<HeaderBlock, ProtocolError> {
    let protocol = unique_protocol(&head.headers)?;
    let authority = authority_for_request(head)?;
    let standard_connect = head.method == Method::CONNECT && protocol.is_none();
    let mut output = HeaderBlock::new();

    add(&mut output, b":method", head.method.as_str().as_bytes())?;
    if standard_connect {
        add(&mut output, b":authority", authority.as_bytes())?;
    } else {
        let scheme = head
            .uri
            .scheme_str()
            .ok_or_else(|| malformed("HTTP/2 request URI has no scheme"))?;
        let path = head
            .uri
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str);
        add(&mut output, b":scheme", scheme.as_bytes())?;
        add(&mut output, b":authority", authority.as_bytes())?;
        add(&mut output, b":path", path.as_bytes())?;
        if let Some(protocol) = protocol {
            add(&mut output, b":protocol", protocol)?;
        }
    }

    let connection_tokens = connection_tokens(&head.headers)?;
    for field in &head.headers {
        if field.name().starts_with(b":") || field.name_eq("host") {
            continue;
        }
        let name = field.name().to_ascii_lowercase();
        if is_connection_specific(&name) || connection_tokens.contains(name.as_slice()) {
            continue;
        }
        validate_te(&name, field.value())?;
        add(&mut output, &name, field.value())?;
    }
    Ok(output)
}

/// Decode and strictly validate a native ordered HTTP/2 request block.
pub fn decode_request_head(block: &HeaderBlock) -> Result<RequestHead, ProtocolError> {
    let mut method = None;
    let mut scheme = None;
    let mut authority = None;
    let mut path = None;
    let mut protocol = None;
    let mut headers = HeaderBlock::new();
    let mut saw_regular = false;

    for field in block {
        validate_lowercase(field.name())?;
        if field.name().starts_with(b":") {
            if saw_regular {
                return Err(violation("HTTP/2 pseudo-header follows a regular header"));
            }
            match field.name() {
                b":method" => set_once(&mut method, field.value(), b":method")?,
                b":scheme" => set_once(&mut scheme, field.value(), b":scheme")?,
                b":authority" => set_once(&mut authority, field.value(), b":authority")?,
                b":path" => set_once(&mut path, field.value(), b":path")?,
                b":protocol" => set_once(&mut protocol, field.value(), b":protocol")?,
                name => {
                    return Err(violation(format!(
                        "unknown HTTP/2 request pseudo-header {}",
                        String::from_utf8_lossy(name)
                    )));
                }
            }
            continue;
        }

        saw_regular = true;
        validate_inbound_regular(field)?;
        headers.push(field.clone());
    }

    let method = required(method, b":method")?;
    let method = Method::from_bytes(&method).map_err(|error| malformed(error.to_string()))?;
    let protocol = protocol.as_deref();
    if protocol.is_some() && method != Method::CONNECT {
        return Err(violation(":protocol is only valid with CONNECT"));
    }

    let uri = if method == Method::CONNECT && protocol.is_none() {
        if scheme.is_some() || path.is_some() {
            return Err(violation(
                "a standard CONNECT request must omit :scheme and :path",
            ));
        }
        let authority = required(authority, b":authority")?;
        let authority = text(&authority, b":authority")?;
        Uri::builder()
            .authority(authority)
            .build()
            .map_err(|error| malformed(error.to_string()))?
    } else {
        let scheme = required(scheme, b":scheme")?;
        let authority = required(authority, b":authority")?;
        let path = required(path, b":path")?;
        let scheme = text(&scheme, b":scheme")?;
        let authority = text(&authority, b":authority")?;
        let path = text(&path, b":path")?;
        Uri::builder()
            .scheme(scheme)
            .authority(authority)
            .path_and_query(path)
            .build()
            .map_err(|error| malformed(error.to_string()))?
    };

    if let Some(protocol) = protocol {
        add(&mut headers, b":protocol", protocol)?;
    }
    Ok(RequestHead::new(method, uri, Version::HTTP_2, headers))
}

/// Translate a response head into a native ordered HTTP/2 header block.
pub fn encode_response_head(head: &ResponseHead) -> Result<HeaderBlock, ProtocolError> {
    let mut output = HeaderBlock::new();
    add(&mut output, b":status", head.status.as_str().as_bytes())?;
    let connection_tokens = connection_tokens(&head.headers)?;
    for field in &head.headers {
        if field.name().starts_with(b":") {
            return Err(violation(
                "response headers must not contain caller-supplied pseudo-headers",
            ));
        }
        let name = field.name().to_ascii_lowercase();
        if is_connection_specific(&name) || connection_tokens.contains(name.as_slice()) {
            continue;
        }
        validate_te(&name, field.value())?;
        add(&mut output, &name, field.value())?;
    }
    Ok(output)
}

/// Decode and strictly validate a native ordered HTTP/2 response block.
pub fn decode_response_head(block: &HeaderBlock) -> Result<ResponseHead, ProtocolError> {
    let mut status = None;
    let mut headers = HeaderBlock::new();
    let mut saw_regular = false;
    for field in block {
        validate_lowercase(field.name())?;
        if field.name().starts_with(b":") {
            if saw_regular {
                return Err(violation("HTTP/2 pseudo-header follows a regular header"));
            }
            if field.name() != b":status" {
                return Err(violation("invalid HTTP/2 response pseudo-header"));
            }
            set_once(&mut status, field.value(), b":status")?;
        } else {
            saw_regular = true;
            validate_inbound_regular(field)?;
            headers.push(field.clone());
        }
    }
    let status = required(status, b":status")?;
    let status = StatusCode::from_bytes(&status).map_err(|error| malformed(error.to_string()))?;
    Ok(ResponseHead::new(status, Version::HTTP_2, headers))
}

/// Build the `http::Request` consumed directly by `h2::client`.
pub fn to_h2_request(head: &RequestHead) -> Result<Request<()>, ProtocolError> {
    let block = encode_request_head(head)?;
    let normalized = decode_request_head(&block)?;
    let mut request = Request::builder()
        .method(normalized.method)
        .uri(normalized.uri)
        .version(Version::HTTP_2)
        .body(())
        .map_err(|error| malformed(error.to_string()))?;
    for field in &normalized.headers {
        if field.name() == b":protocol" {
            let value = text(field.value(), b":protocol")?;
            request.extensions_mut().insert(Protocol::from(value));
        } else {
            append_http(request.headers_mut(), field)?;
        }
    }
    Ok(request)
}

/// Recover the transport-neutral head from an `h2` request.
pub fn from_h2_request<B>(request: &Request<B>) -> Result<RequestHead, ProtocolError> {
    let mut block = request_pseudo_block(request.method(), request.uri())?;
    if let Some(protocol) = request.extensions().get::<Protocol>() {
        add(&mut block, b":protocol", protocol.as_ref())?;
    }
    append_header_map(&mut block, request.headers())?;
    decode_request_head(&block)
}

/// Build the `http::Response` consumed directly by `h2::server`.
pub fn to_h2_response(head: &ResponseHead) -> Result<Response<()>, ProtocolError> {
    let block = encode_response_head(head)?;
    let normalized = decode_response_head(&block)?;
    let mut response = Response::builder()
        .status(normalized.status)
        .version(Version::HTTP_2)
        .body(())
        .map_err(|error| malformed(error.to_string()))?;
    for field in &normalized.headers {
        append_http(response.headers_mut(), field)?;
    }
    Ok(response)
}

/// Recover the transport-neutral head from an `h2` response.
pub fn from_h2_response<B>(response: &Response<B>) -> Result<ResponseHead, ProtocolError> {
    let mut block = HeaderBlock::new();
    add(
        &mut block,
        b":status",
        response.status().as_str().as_bytes(),
    )?;
    append_header_map(&mut block, response.headers())?;
    decode_response_head(&block)
}

/// Convert ordered trailers for `h2::SendStream`, preserving duplicate order.
pub fn to_h2_trailers(trailers: &HeaderBlock) -> Result<HeaderMap, ProtocolError> {
    let mut output = HeaderMap::with_capacity(trailers.len());
    for field in trailers {
        if field.name().starts_with(b":") {
            return Err(violation("HTTP/2 trailers must not contain pseudo-headers"));
        }
        let normalized = HeaderField::new(field.name().to_ascii_lowercase(), field.value())
            .map_err(|error| malformed(error.to_string()))?;
        validate_inbound_regular(&normalized)?;
        append_http(&mut output, &normalized)?;
    }
    Ok(output)
}

/// Convert trailers received from `h2::RecvStream` to the canonical model.
pub fn from_h2_trailers(trailers: &HeaderMap) -> Result<HeaderBlock, ProtocolError> {
    let mut output = HeaderBlock::new();
    append_header_map(&mut output, trailers)?;
    for field in &output {
        validate_inbound_regular(field)?;
    }
    Ok(output)
}

/// Hide engine-specific error types behind the shared protocol boundary.
pub fn map_h2_error(error: h2::Error) -> ProtocolError {
    let kind = if error.is_io() {
        ErrorKind::Io
    } else if error.is_reset() {
        ErrorKind::Reset
    } else {
        ErrorKind::ProtocolViolation
    };
    ProtocolError::new(kind, error.to_string())
}

fn request_pseudo_block(method: &Method, uri: &Uri) -> Result<HeaderBlock, ProtocolError> {
    let mut block = HeaderBlock::new();
    add(&mut block, b":method", method.as_str().as_bytes())?;
    if method == Method::CONNECT && uri.scheme().is_none() {
        let authority = uri
            .authority()
            .ok_or_else(|| malformed("CONNECT request URI has no authority"))?;
        add(&mut block, b":authority", authority.as_str().as_bytes())?;
    } else {
        let scheme = uri
            .scheme_str()
            .ok_or_else(|| malformed("HTTP/2 request URI has no scheme"))?;
        let authority = uri
            .authority()
            .ok_or_else(|| malformed("HTTP/2 request URI has no authority"))?;
        let path = uri
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str);
        add(&mut block, b":scheme", scheme.as_bytes())?;
        add(&mut block, b":authority", authority.as_str().as_bytes())?;
        add(&mut block, b":path", path.as_bytes())?;
    }
    Ok(block)
}

fn authority_for_request(head: &RequestHead) -> Result<String, ProtocolError> {
    if let Some(authority) = head.uri.authority() {
        return Ok(authority.to_string());
    }
    if let Some(host) = head.headers.get("host") {
        return Ok(text(host, b"host")?.to_owned());
    }
    Err(malformed("HTTP/2 request has no authority"))
}

fn unique_protocol(headers: &HeaderBlock) -> Result<Option<&[u8]>, ProtocolError> {
    let mut values = headers.get_all(":protocol");
    let first = values.next();
    if values.next().is_some() {
        return Err(violation("duplicate :protocol pseudo-header"));
    }
    if first.is_some()
        && headers
            .iter()
            .any(|field| field.name().starts_with(b":") && !field.name_eq(":protocol"))
    {
        return Err(violation(
            "request headers contain caller-supplied standard pseudo-headers",
        ));
    }
    if first.is_none() && headers.iter().any(|field| field.name().starts_with(b":")) {
        return Err(violation(
            "request headers contain an unknown pseudo-header",
        ));
    }
    Ok(first)
}

fn connection_tokens(headers: &HeaderBlock) -> Result<HashSet<Vec<u8>>, ProtocolError> {
    let mut output = HashSet::new();
    for value in headers.get_all("connection") {
        let value = text(value, b"connection")?;
        for token in value
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
        {
            let bytes = token.as_bytes().to_ascii_lowercase();
            HeaderName::from_bytes(&bytes).map_err(|error| malformed(error.to_string()))?;
            output.insert(bytes);
        }
    }
    Ok(output)
}

fn validate_inbound_regular(field: &HeaderField) -> Result<(), ProtocolError> {
    validate_lowercase(field.name())?;
    if is_connection_specific(field.name()) {
        return Err(violation(format!(
            "connection-specific field {} is forbidden in HTTP/2",
            String::from_utf8_lossy(field.name())
        )));
    }
    validate_te(field.name(), field.value())
}

fn validate_te(name: &[u8], value: &[u8]) -> Result<(), ProtocolError> {
    if name == b"te" && !value.eq_ignore_ascii_case(b"trailers") {
        return Err(violation("HTTP/2 TE field value must be trailers"));
    }
    Ok(())
}

fn validate_lowercase(name: &[u8]) -> Result<(), ProtocolError> {
    if name.iter().any(u8::is_ascii_uppercase) {
        return Err(violation("HTTP/2 header field names must be lowercase"));
    }
    Ok(())
}

fn is_connection_specific(name: &[u8]) -> bool {
    CONNECTION_SPECIFIC.contains(&name)
}

fn append_header_map(block: &mut HeaderBlock, headers: &HeaderMap) -> Result<(), ProtocolError> {
    for (name, value) in headers {
        add(block, name.as_str().as_bytes(), value.as_bytes())?;
    }
    Ok(())
}

fn append_http(headers: &mut HeaderMap, field: &HeaderField) -> Result<(), ProtocolError> {
    let name =
        HeaderName::from_bytes(field.name()).map_err(|error| malformed(error.to_string()))?;
    let value =
        HeaderValue::from_bytes(field.value()).map_err(|error| malformed(error.to_string()))?;
    headers.append(name, value);
    Ok(())
}

fn add(block: &mut HeaderBlock, name: &[u8], value: &[u8]) -> Result<(), ProtocolError> {
    block
        .add(name, value)
        .map_err(|error| malformed(error.to_string()))
}

fn set_once(slot: &mut Option<Vec<u8>>, value: &[u8], name: &[u8]) -> Result<(), ProtocolError> {
    if slot.replace(value.to_vec()).is_some() {
        return Err(violation(format!(
            "duplicate {} pseudo-header",
            String::from_utf8_lossy(name)
        )));
    }
    Ok(())
}

fn required(value: Option<Vec<u8>>, name: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    value.ok_or_else(|| {
        violation(format!(
            "missing required {} pseudo-header",
            String::from_utf8_lossy(name)
        ))
    })
}

fn text<'a>(value: &'a [u8], name: &[u8]) -> Result<&'a str, ProtocolError> {
    std::str::from_utf8(value).map_err(|_| {
        malformed(format!(
            "{} value is not UTF-8",
            String::from_utf8_lossy(name)
        ))
    })
}

fn malformed(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ErrorKind::MalformedMessage, message)
}

fn violation(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ErrorKind::ProtocolViolation, message)
}
