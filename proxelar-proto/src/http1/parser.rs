use bytes::Bytes;
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
        if self.limits.max_headers <= 128 {
            let mut headers = [httparse::EMPTY_HEADER; 128];
            return self.parse_request_with_headers(
                input,
                &mut headers[..self.limits.max_headers],
                None,
            );
        }
        let mut headers = vec![httparse::EMPTY_HEADER; self.limits.max_headers];
        self.parse_request_with_headers(input, &mut headers, None)
    }

    pub(crate) fn request_head_len(&self, input: &[u8]) -> Result<Option<usize>, Http1Error> {
        self.check_prefix_limits(input)?;
        if self.limits.max_headers <= 128 {
            let mut headers = [httparse::EMPTY_HEADER; 128];
            return probe_request(input, &mut headers[..self.limits.max_headers]);
        }
        let mut headers = vec![httparse::EMPTY_HEADER; self.limits.max_headers];
        probe_request(input, &mut headers)
    }

    pub(crate) fn parse_request_bytes(
        &self,
        input: Bytes,
    ) -> Result<ParsedRequestHead, Http1Error> {
        self.check_prefix_limits(&input)?;
        let status = if self.limits.max_headers <= 128 {
            let mut headers = [httparse::EMPTY_HEADER; 128];
            self.parse_request_with_headers(
                &input,
                &mut headers[..self.limits.max_headers],
                Some(&input),
            )?
        } else {
            let mut headers = vec![httparse::EMPTY_HEADER; self.limits.max_headers];
            self.parse_request_with_headers(&input, &mut headers, Some(&input))?
        };
        match status {
            ParseStatus::Complete(parsed) => Ok(parsed),
            ParseStatus::Incomplete => Err(Http1Error::new(
                Http1ErrorKind::MalformedStartLine,
                "owned HTTP/1 request head is incomplete",
            )),
        }
    }

    fn parse_request_with_headers<'a>(
        &self,
        input: &'a [u8],
        headers: &mut [httparse::Header<'a>],
        source: Option<&Bytes>,
    ) -> Result<ParseStatus<ParsedRequestHead>, Http1Error> {
        let mut request = httparse::Request::new(headers);
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
        let headers = parse_headers(request.headers, source)?;
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
        if self.limits.max_headers <= 128 {
            let mut headers = [httparse::EMPTY_HEADER; 128];
            return self.parse_response_with_headers(
                input,
                &mut headers[..self.limits.max_headers],
                None,
            );
        }
        let mut headers = vec![httparse::EMPTY_HEADER; self.limits.max_headers];
        self.parse_response_with_headers(input, &mut headers, None)
    }

    pub(crate) fn response_head_len(&self, input: &[u8]) -> Result<Option<usize>, Http1Error> {
        self.check_prefix_limits(input)?;
        if self.limits.max_headers <= 128 {
            let mut headers = [httparse::EMPTY_HEADER; 128];
            return probe_response(input, &mut headers[..self.limits.max_headers]);
        }
        let mut headers = vec![httparse::EMPTY_HEADER; self.limits.max_headers];
        probe_response(input, &mut headers)
    }

    pub(crate) fn parse_response_bytes(
        &self,
        input: Bytes,
    ) -> Result<ParsedResponseHead, Http1Error> {
        self.check_prefix_limits(&input)?;
        let status = if self.limits.max_headers <= 128 {
            let mut headers = [httparse::EMPTY_HEADER; 128];
            self.parse_response_with_headers(
                &input,
                &mut headers[..self.limits.max_headers],
                Some(&input),
            )?
        } else {
            let mut headers = vec![httparse::EMPTY_HEADER; self.limits.max_headers];
            self.parse_response_with_headers(&input, &mut headers, Some(&input))?
        };
        match status {
            ParseStatus::Complete(parsed) => Ok(parsed),
            ParseStatus::Incomplete => Err(Http1Error::new(
                Http1ErrorKind::MalformedStartLine,
                "owned HTTP/1 response head is incomplete",
            )),
        }
    }

    fn parse_response_with_headers<'a>(
        &self,
        input: &'a [u8],
        headers: &mut [httparse::Header<'a>],
        source: Option<&Bytes>,
    ) -> Result<ParseStatus<ParsedResponseHead>, Http1Error> {
        let mut response = httparse::Response::new(headers);
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
        let headers = parse_headers(response.headers, source)?;
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

fn parse_headers(
    headers: &[httparse::Header<'_>],
    source: Option<&Bytes>,
) -> Result<HeaderBlock, Http1Error> {
    headers
        .iter()
        .map(|header| {
            let field = if let Some(source) = source {
                let name = source_range(source, header.name.as_bytes())?;
                let value = source_range(source, header.value)?;
                HeaderField::from_bytes(name, value)
            } else {
                HeaderField::new(header.name.as_bytes(), header.value)
            };
            field.map_err(|error| {
                Http1Error::new(
                    Http1ErrorKind::MalformedHeader,
                    format!("invalid header field: {error}"),
                )
            })
        })
        .collect::<Result<HeaderBlock, _>>()
}

fn source_range(source: &Bytes, range: &[u8]) -> Result<Bytes, Http1Error> {
    let source_start = source.as_ptr() as usize;
    let start = (range.as_ptr() as usize)
        .checked_sub(source_start)
        .filter(|start| *start <= source.len())
        .ok_or_else(|| {
            Http1Error::new(
                Http1ErrorKind::MalformedHeader,
                "HTTP/1 parser returned a header outside its source buffer",
            )
        })?;
    let end = start
        .checked_add(range.len())
        .filter(|end| *end <= source.len())
        .ok_or_else(|| {
            Http1Error::new(
                Http1ErrorKind::MalformedHeader,
                "HTTP/1 parser returned a header outside its source buffer",
            )
        })?;
    Ok(source.slice(start..end))
}

fn probe_request<'a>(
    input: &'a [u8],
    headers: &mut [httparse::Header<'a>],
) -> Result<Option<usize>, Http1Error> {
    match httparse::Request::new(headers)
        .parse(input)
        .map_err(map_httparse_error)?
    {
        httparse::Status::Partial => Ok(None),
        httparse::Status::Complete(consumed) => Ok(Some(consumed)),
    }
}

fn probe_response<'a>(
    input: &'a [u8],
    headers: &mut [httparse::Header<'a>],
) -> Result<Option<usize>, Http1Error> {
    match httparse::Response::new(headers)
        .parse(input)
        .map_err(map_httparse_error)?
    {
        httparse::Status::Partial => Ok(None),
        httparse::Status::Complete(consumed) => Ok(Some(consumed)),
    }
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
