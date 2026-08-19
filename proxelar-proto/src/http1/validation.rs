use std::fmt;

use http::{uri::Authority, Method, StatusCode, Uri, Version};
use proxyapi_models::HeaderBlock;

/// Stable HTTP/1 parse and validation error categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http1ErrorKind {
    HeadTooLarge,
    StartLineTooLarge,
    TooManyHeaders,
    MalformedStartLine,
    MalformedHeader,
    InvalidLineEnding,
    ObsoleteLineFolding,
    MissingHost,
    DuplicateHost,
    InvalidHost,
    InvalidRequestTarget,
    InvalidContentLength,
    ConflictingContentLength,
    InvalidTransferEncoding,
    InvalidConnection,
    AmbiguousFraming,
    InvalidChunkSize,
    InvalidChunkExtension,
    InvalidChunkTerminator,
    InvalidTrailer,
    BodyTooLarge,
    BodyLengthMismatch,
    UnexpectedBodyFrame,
}

/// A protocol error rejected before any HTTP/1 message is forwarded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Http1Error {
    kind: Http1ErrorKind,
    message: String,
}

impl Http1Error {
    pub(crate) fn new(kind: Http1ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub const fn kind(&self) -> Http1ErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Http1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Http1Error {}

/// Framing-relevant fields after strict RFC 9110/9112 validation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HeaderSemantics {
    pub content_length: Option<u64>,
    pub transfer_encoded: bool,
    pub chunked: bool,
}

pub(crate) fn validate_request(
    raw_head: &[u8],
    method: &Method,
    raw_target: &str,
    uri: &Uri,
    version: Version,
    headers: &HeaderBlock,
) -> Result<HeaderSemantics, Http1Error> {
    validate_wire_lines(raw_head)?;
    validate_request_target(method, raw_target, uri)?;
    validate_host(version, headers)?;
    validate_framing(version, headers, true)
}

pub(crate) fn validate_response(
    raw_head: &[u8],
    status: StatusCode,
    version: Version,
    headers: &HeaderBlock,
) -> Result<HeaderSemantics, Http1Error> {
    validate_wire_lines(raw_head)?;
    let semantics = validate_framing(version, headers, false)?;
    if (status.is_informational() || status == StatusCode::NO_CONTENT)
        && (semantics.content_length.is_some() || semantics.transfer_encoded)
    {
        return Err(Http1Error::new(
            Http1ErrorKind::AmbiguousFraming,
            "informational and 204 responses cannot carry framing fields",
        ));
    }
    Ok(semantics)
}

fn validate_wire_lines(raw_head: &[u8]) -> Result<(), Http1Error> {
    for (index, byte) in raw_head.iter().copied().enumerate() {
        if byte == b'\n' && (index == 0 || raw_head[index - 1] != b'\r') {
            return Err(Http1Error::new(
                Http1ErrorKind::InvalidLineEnding,
                "HTTP/1 head contains a bare line feed",
            ));
        }
        if byte == b'\r' && raw_head.get(index + 1).copied() != Some(b'\n') {
            return Err(Http1Error::new(
                Http1ErrorKind::InvalidLineEnding,
                "HTTP/1 head contains a carriage return not followed by line feed",
            ));
        }
    }

    for line in raw_head.split(|byte| *byte == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        if matches!(line.first(), Some(b' ' | b'\t')) {
            return Err(Http1Error::new(
                Http1ErrorKind::ObsoleteLineFolding,
                "obsolete folded header lines are rejected",
            ));
        }
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            return Err(Http1Error::new(
                Http1ErrorKind::MalformedHeader,
                "header line is missing a colon",
            ));
        };
        if colon == 0 || matches!(line.get(colon - 1), Some(b' ' | b'\t')) {
            return Err(Http1Error::new(
                Http1ErrorKind::MalformedHeader,
                "whitespace before a header colon is rejected",
            ));
        }
    }
    Ok(())
}

fn validate_request_target(method: &Method, raw_target: &str, uri: &Uri) -> Result<(), Http1Error> {
    if method == Method::CONNECT {
        if raw_target.contains('/')
            || raw_target.contains('?')
            || raw_target.contains('#')
            || raw_target.parse::<Authority>().is_err()
        {
            return Err(Http1Error::new(
                Http1ErrorKind::InvalidRequestTarget,
                "CONNECT requires an authority-form request target",
            ));
        }
        return Ok(());
    }

    if raw_target == "*" {
        return if method == Method::OPTIONS {
            Ok(())
        } else {
            Err(Http1Error::new(
                Http1ErrorKind::InvalidRequestTarget,
                "asterisk-form is only valid for OPTIONS",
            ))
        };
    }

    if raw_target.starts_with('/') {
        return Ok(());
    }

    if uri.scheme().is_some() && uri.authority().is_some() {
        return Ok(());
    }

    Err(Http1Error::new(
        Http1ErrorKind::InvalidRequestTarget,
        "request target is not origin-form, absolute-form, authority-form, or asterisk-form",
    ))
}

fn validate_host(version: Version, headers: &HeaderBlock) -> Result<(), Http1Error> {
    if version != Version::HTTP_11 {
        return Ok(());
    }

    let mut hosts = headers.get_all("host");
    let Some(host) = hosts.next() else {
        return Err(Http1Error::new(
            Http1ErrorKind::MissingHost,
            "HTTP/1.1 request is missing Host",
        ));
    };
    if hosts.next().is_some() {
        return Err(Http1Error::new(
            Http1ErrorKind::DuplicateHost,
            "HTTP/1.1 request contains more than one Host field",
        ));
    }
    let host = trim_ows(host);
    let valid_authority = std::str::from_utf8(host)
        .ok()
        .and_then(|host| host.parse::<Authority>().ok())
        .is_some();
    if host.is_empty() || !valid_authority {
        return Err(Http1Error::new(
            Http1ErrorKind::InvalidHost,
            "HTTP/1.1 Host field is not a valid authority",
        ));
    }
    Ok(())
}

fn validate_framing(
    version: Version,
    headers: &HeaderBlock,
    request: bool,
) -> Result<HeaderSemantics, Http1Error> {
    validate_connection(headers)?;
    let content_length = parse_content_length(headers)?;
    let (transfer_encoded, chunked) = parse_transfer_encoding(version, headers, request)?;
    if content_length.is_some() && transfer_encoded {
        return Err(Http1Error::new(
            Http1ErrorKind::AmbiguousFraming,
            "Content-Length and Transfer-Encoding cannot appear together",
        ));
    }
    Ok(HeaderSemantics {
        content_length,
        transfer_encoded,
        chunked,
    })
}

fn validate_connection(headers: &HeaderBlock) -> Result<(), Http1Error> {
    for value in headers.get_all("connection") {
        for token in value.split(|byte| *byte == b',') {
            let token = trim_ows(token);
            if token.is_empty() || !token.iter().copied().all(is_token_byte) {
                return Err(Http1Error::new(
                    Http1ErrorKind::InvalidConnection,
                    "Connection contains an invalid field-name token",
                ));
            }
            if [
                b"content-length".as_slice(),
                b"transfer-encoding".as_slice(),
                b"host".as_slice(),
                b"connection".as_slice(),
                b"trailer".as_slice(),
            ]
            .iter()
            .any(|critical| token.eq_ignore_ascii_case(critical))
            {
                return Err(Http1Error::new(
                    Http1ErrorKind::InvalidConnection,
                    "Connection cannot nominate a routing or framing field",
                ));
            }
        }
    }
    Ok(())
}

fn parse_content_length(headers: &HeaderBlock) -> Result<Option<u64>, Http1Error> {
    let mut parsed = None;
    for value in headers.get_all("content-length") {
        for item in value.split(|byte| *byte == b',') {
            let item = trim_ows(item);
            if item.is_empty() || !item.iter().all(u8::is_ascii_digit) {
                return Err(Http1Error::new(
                    Http1ErrorKind::InvalidContentLength,
                    "Content-Length must contain only decimal digits",
                ));
            }
            let value = std::str::from_utf8(item)
                .ok()
                .and_then(|item| item.parse::<u64>().ok())
                .ok_or_else(|| {
                    Http1Error::new(
                        Http1ErrorKind::InvalidContentLength,
                        "Content-Length exceeds the supported range",
                    )
                })?;
            if parsed.is_some_and(|previous| previous != value) {
                return Err(Http1Error::new(
                    Http1ErrorKind::ConflictingContentLength,
                    "multiple Content-Length values disagree",
                ));
            }
            parsed = Some(value);
        }
    }
    Ok(parsed)
}

fn parse_transfer_encoding(
    version: Version,
    headers: &HeaderBlock,
    request: bool,
) -> Result<(bool, bool), Http1Error> {
    let values = headers.get_all("transfer-encoding").collect::<Vec<_>>();
    if values.is_empty() {
        return Ok((false, false));
    }
    if version != Version::HTTP_11 {
        return Err(Http1Error::new(
            Http1ErrorKind::InvalidTransferEncoding,
            "Transfer-Encoding is not valid in HTTP/1.0",
        ));
    }

    let mut codings = Vec::new();
    for value in values {
        for item in value.split(|byte| *byte == b',') {
            let item = trim_ows(item);
            let mut parts = item.splitn(2, |byte| *byte == b';');
            let coding = trim_ows(parts.next().unwrap_or_default());
            if coding.is_empty() || !coding.iter().copied().all(is_token_byte) {
                return Err(Http1Error::new(
                    Http1ErrorKind::InvalidTransferEncoding,
                    "Transfer-Encoding contains an invalid coding",
                ));
            }
            if coding.eq_ignore_ascii_case(b"chunked") && parts.next().is_some() {
                return Err(Http1Error::new(
                    Http1ErrorKind::InvalidTransferEncoding,
                    "chunked transfer coding parameters are rejected",
                ));
            }
            codings.push(coding);
        }
    }

    let chunked_count = codings
        .iter()
        .filter(|coding| coding.eq_ignore_ascii_case(b"chunked"))
        .count();
    let chunked_is_final = codings
        .last()
        .is_some_and(|coding| coding.eq_ignore_ascii_case(b"chunked"));
    if chunked_count > 1
        || (request && (chunked_count != 1 || !chunked_is_final))
        || (!request && chunked_count == 1 && !chunked_is_final)
    {
        return Err(Http1Error::new(
            Http1ErrorKind::InvalidTransferEncoding,
            "chunked must occur exactly once and as the final request coding",
        ));
    }
    Ok((true, chunked_is_final))
}

pub(crate) fn trim_ows(mut bytes: &[u8]) -> &[u8] {
    while matches!(bytes.first(), Some(b' ' | b'\t')) {
        bytes = &bytes[1..];
    }
    while matches!(bytes.last(), Some(b' ' | b'\t')) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

pub(crate) fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}
