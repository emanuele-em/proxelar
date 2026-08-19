use http::{Method, StatusCode, Uri, Version};
use proxyapi_models::{HeaderBlock, HeaderField};

use crate::{RequestHead, ResponseHead};

use super::validation::{self, HeaderSemantics, Http1Error, Http1ErrorKind};

/// Resource limits applied before a head reaches a handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeadParserLimits {
    pub max_head_bytes: usize,
    pub max_start_line_bytes: usize,
    pub max_headers: usize,
}

impl Default for HeadParserLimits {
    fn default() -> Self {
        Self {
            max_head_bytes: 64 * 1024,
            max_start_line_bytes: 8 * 1024,
            max_headers: 128,
        }
    }
}

/// A complete parsed value or a request for more caller-owned bytes.
#[derive(Debug)]
pub enum ParseStatus<T> {
    Incomplete,
    Complete(T),
}

#[derive(Debug)]
pub struct ParsedRequestHead {
    pub head: RequestHead,
    pub semantics: HeaderSemantics,
    pub consumed: usize,
}

#[derive(Debug)]
pub struct ParsedResponseHead {
    pub head: ResponseHead,
    pub semantics: HeaderSemantics,
    pub consumed: usize,
}

/// Reusable strict parser configuration with no socket or runtime dependency.
#[derive(Clone, Copy, Debug, Default)]
pub struct HeadParser {
    limits: HeadParserLimits,
}

impl HeadParser {
    pub const fn new(limits: HeadParserLimits) -> Self {
        Self { limits }
    }

    pub const fn limits(&self) -> HeadParserLimits {
        self.limits
    }

    pub fn parse_request(
        &self,
        input: &[u8],
    ) -> Result<ParseStatus<ParsedRequestHead>, Http1Error> {
        self.check_prefix_limits(input)?;
        let mut headers = vec![httparse::EMPTY_HEADER; self.limits.max_headers];
        let mut request = httparse::Request::new(&mut headers);
        let consumed = match request.parse(input).map_err(map_httparse_error)? {
            httparse::Status::Partial => return Ok(ParseStatus::Incomplete),
            httparse::Status::Complete(consumed) => consumed,
        };

        let method = request.method.ok_or_else(|| {
            Http1Error::new(
                Http1ErrorKind::MalformedStartLine,
                "request method is missing",
            )
        })?;
        let method = Method::from_bytes(method.as_bytes()).map_err(|error| {
            Http1Error::new(
                Http1ErrorKind::MalformedStartLine,
                format!("invalid request method: {error}"),
            )
        })?;
        let target = request.path.ok_or_else(|| {
            Http1Error::new(
                Http1ErrorKind::MalformedStartLine,
                "request target is missing",
            )
        })?;
        let uri = target.parse::<Uri>().map_err(|error| {
            Http1Error::new(
                Http1ErrorKind::InvalidRequestTarget,
                format!("invalid request target: {error}"),
            )
        })?;
        let version = parse_version(request.version)?;
        let headers = parse_headers(request.headers)?;
        let semantics = validation::validate_request(
            &input[..consumed],
            &method,
            target,
            &uri,
            version,
            &headers,
        )?;

        Ok(ParseStatus::Complete(ParsedRequestHead {
            head: RequestHead::new(method, uri, version, headers),
            semantics,
            consumed,
        }))
    }

    pub fn parse_response(
        &self,
        input: &[u8],
    ) -> Result<ParseStatus<ParsedResponseHead>, Http1Error> {
        self.check_prefix_limits(input)?;
        let mut headers = vec![httparse::EMPTY_HEADER; self.limits.max_headers];
        let mut response = httparse::Response::new(&mut headers);
        let consumed = match response.parse(input).map_err(map_httparse_error)? {
            httparse::Status::Partial => return Ok(ParseStatus::Incomplete),
            httparse::Status::Complete(consumed) => consumed,
        };
        let version = parse_version(response.version)?;
        let status = response.code.ok_or_else(|| {
            Http1Error::new(
                Http1ErrorKind::MalformedStartLine,
                "response status is missing",
            )
        })?;
        let status = StatusCode::from_u16(status).map_err(|error| {
            Http1Error::new(
                Http1ErrorKind::MalformedStartLine,
                format!("invalid response status: {error}"),
            )
        })?;
        let headers = parse_headers(response.headers)?;
        let semantics =
            validation::validate_response(&input[..consumed], status, version, &headers)?;

        Ok(ParseStatus::Complete(ParsedResponseHead {
            head: ResponseHead::new(status, version, headers),
            semantics,
            consumed,
        }))
    }

    fn check_prefix_limits(&self, input: &[u8]) -> Result<(), Http1Error> {
        let head_too_large = match find_head_end(input) {
            Some(head_end) => head_end > self.limits.max_head_bytes,
            None => input.len() > self.limits.max_head_bytes,
        };
        if head_too_large {
            return Err(Http1Error::new(
                Http1ErrorKind::HeadTooLarge,
                "HTTP/1 head exceeds the configured byte limit",
            ));
        }
        let start_line_len = input
            .windows(2)
            .position(|window| window == b"\r\n")
            .unwrap_or(input.len());
        if start_line_len > self.limits.max_start_line_bytes {
            return Err(Http1Error::new(
                Http1ErrorKind::StartLineTooLarge,
                "HTTP/1 start line exceeds the configured byte limit",
            ));
        }
        Ok(())
    }
}

fn parse_headers(headers: &[httparse::Header<'_>]) -> Result<HeaderBlock, Http1Error> {
    headers
        .iter()
        .map(|header| {
            HeaderField::new(header.name.as_bytes(), header.value).map_err(|error| {
                Http1Error::new(
                    Http1ErrorKind::MalformedHeader,
                    format!("invalid header field: {error}"),
                )
            })
        })
        .collect::<Result<HeaderBlock, _>>()
}

fn parse_version(version: Option<u8>) -> Result<Version, Http1Error> {
    match version {
        Some(0) => Ok(Version::HTTP_10),
        Some(1) => Ok(Version::HTTP_11),
        _ => Err(Http1Error::new(
            Http1ErrorKind::MalformedStartLine,
            "unsupported HTTP/1 version",
        )),
    }
}

fn map_httparse_error(error: httparse::Error) -> Http1Error {
    let kind = match error {
        httparse::Error::TooManyHeaders => Http1ErrorKind::TooManyHeaders,
        httparse::Error::HeaderName | httparse::Error::HeaderValue | httparse::Error::NewLine => {
            Http1ErrorKind::MalformedHeader
        }
        httparse::Error::Status | httparse::Error::Token | httparse::Error::Version => {
            Http1ErrorKind::MalformedStartLine
        }
    };
    Http1Error::new(kind, format!("malformed HTTP/1 head: {error}"))
}

fn find_head_end(input: &[u8]) -> Option<usize> {
    input
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}
