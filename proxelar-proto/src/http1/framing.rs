use bytes::Bytes;
use http::{Method, StatusCode};
use proxyapi_models::{HeaderBlock, HeaderField};

use crate::BodyFrame;

use super::validation::{is_token_byte, trim_ows};
use super::{HeaderSemantics, Http1Error, Http1ErrorKind};

/// Wire framing selected after an HTTP/1 head has passed strict validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyFraming {
    None,
    ContentLength(u64),
    Chunked,
    UntilEof,
    /// A successful CONNECT switches protocols after the response head.
    Tunnel,
}

impl BodyFraming {
    pub const fn for_request(semantics: HeaderSemantics) -> Self {
        if semantics.chunked {
            Self::Chunked
        } else if let Some(length) = semantics.content_length {
            Self::ContentLength(length)
        } else {
            Self::None
        }
    }

    pub fn for_response(
        request_method: &Method,
        status: StatusCode,
        semantics: HeaderSemantics,
    ) -> Self {
        if request_method == Method::HEAD
            || status.is_informational()
            || status == StatusCode::NO_CONTENT
            || status == StatusCode::NOT_MODIFIED
        {
            Self::None
        } else if request_method == Method::CONNECT && status.is_success() {
            Self::Tunnel
        } else if semantics.chunked {
            Self::Chunked
        } else if semantics.transfer_encoded {
            Self::UntilEof
        } else if let Some(length) = semantics.content_length {
            Self::ContentLength(length)
        } else {
            Self::UntilEof
        }
    }
}

/// Limits for chunk metadata and trailer blocks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BodyDecoderLimits {
    pub max_chunk_line_bytes: usize,
    pub max_trailer_bytes: usize,
    pub max_trailers: usize,
}

impl Default for BodyDecoderLimits {
    fn default() -> Self {
        Self {
            max_chunk_line_bytes: 8 * 1024,
            max_trailer_bytes: 64 * 1024,
            max_trailers: 128,
        }
    }
}

/// One decoded body frame and the exact number of caller-owned bytes consumed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedBodyFrame {
    pub frame: BodyFrame,
    pub consumed: usize,
    pub end_stream: bool,
}

/// Result of advancing a sans-I/O body decoder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BodyDecodeStatus {
    /// More bytes are required. Any reported prefix can be discarded.
    Incomplete {
        consumed: usize,
    },
    Frame(DecodedBodyFrame),
    Complete {
        consumed: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChunkState {
    Size,
    Data(u64),
    DataTerminator,
    Trailers,
    Complete,
}

/// Incremental, runtime-independent HTTP/1 body decoder.
#[derive(Debug)]
pub struct BodyDecoder {
    framing: BodyFraming,
    fixed_remaining: u64,
    chunk_state: ChunkState,
    limits: BodyDecoderLimits,
    complete: bool,
}

impl BodyDecoder {
    pub fn new(framing: BodyFraming) -> Self {
        Self::with_limits(framing, BodyDecoderLimits::default())
    }

    pub fn with_limits(framing: BodyFraming, limits: BodyDecoderLimits) -> Self {
        let fixed_remaining = match framing {
            BodyFraming::ContentLength(length) => length,
            _ => 0,
        };
        let chunk_state = if framing == BodyFraming::Chunked {
            ChunkState::Size
        } else {
            ChunkState::Complete
        };
        let complete = matches!(framing, BodyFraming::None | BodyFraming::Tunnel)
            || matches!(framing, BodyFraming::ContentLength(0));
        Self {
            framing,
            fixed_remaining,
            chunk_state,
            limits,
            complete,
        }
    }

    pub const fn framing(&self) -> BodyFraming {
        self.framing
    }

    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn decode(&mut self, input: &[u8]) -> Result<BodyDecodeStatus, Http1Error> {
        if self.complete {
            return Ok(BodyDecodeStatus::Complete { consumed: 0 });
        }
        match self.framing {
            BodyFraming::None | BodyFraming::Tunnel => {
                self.complete = true;
                Ok(BodyDecodeStatus::Complete { consumed: 0 })
            }
            BodyFraming::ContentLength(_) => self.decode_fixed(input),
            BodyFraming::Chunked => self.decode_chunked(input),
            BodyFraming::UntilEof => {
                if input.is_empty() {
                    Ok(BodyDecodeStatus::Incomplete { consumed: 0 })
                } else {
                    Ok(BodyDecodeStatus::Frame(DecodedBodyFrame {
                        frame: BodyFrame::Data(Bytes::copy_from_slice(input)),
                        consumed: input.len(),
                        end_stream: false,
                    }))
                }
            }
        }
    }

    /// Notify the decoder that the transport reached a clean EOF.
    pub fn decode_eof(&mut self) -> Result<BodyDecodeStatus, Http1Error> {
        if self.complete {
            return Ok(BodyDecodeStatus::Complete { consumed: 0 });
        }
        match self.framing {
            BodyFraming::UntilEof => {
                self.complete = true;
                Ok(BodyDecodeStatus::Complete { consumed: 0 })
            }
            BodyFraming::ContentLength(_) => Err(Http1Error::new(
                Http1ErrorKind::BodyLengthMismatch,
                format!(
                    "HTTP/1 body ended with {} Content-Length bytes missing",
                    self.fixed_remaining
                ),
            )),
            BodyFraming::Chunked => Err(Http1Error::new(
                Http1ErrorKind::InvalidChunkTerminator,
                "chunked body ended before the terminal chunk and trailers",
            )),
            BodyFraming::None | BodyFraming::Tunnel => {
                self.complete = true;
                Ok(BodyDecodeStatus::Complete { consumed: 0 })
            }
        }
    }

    fn decode_fixed(&mut self, input: &[u8]) -> Result<BodyDecodeStatus, Http1Error> {
        if self.fixed_remaining == 0 {
            self.complete = true;
            return Ok(BodyDecodeStatus::Complete { consumed: 0 });
        }
        if input.is_empty() {
            return Ok(BodyDecodeStatus::Incomplete { consumed: 0 });
        }
        let consumed = usize::try_from(self.fixed_remaining)
            .unwrap_or(usize::MAX)
            .min(input.len());
        self.fixed_remaining -= consumed as u64;
        let end_stream = self.fixed_remaining == 0;
        self.complete = end_stream;
        Ok(BodyDecodeStatus::Frame(DecodedBodyFrame {
            frame: BodyFrame::Data(Bytes::copy_from_slice(&input[..consumed])),
            consumed,
            end_stream,
        }))
    }

    fn decode_chunked(&mut self, input: &[u8]) -> Result<BodyDecodeStatus, Http1Error> {
        let mut offset = 0;
        loop {
            match self.chunk_state {
                ChunkState::Size => {
                    let Some(line_end) = find_crlf(&input[offset..]) else {
                        reject_invalid_partial_line(
                            &input[offset..],
                            Http1ErrorKind::InvalidChunkSize,
                        )?;
                        if input.len() - offset > self.limits.max_chunk_line_bytes {
                            return Err(Http1Error::new(
                                Http1ErrorKind::BodyTooLarge,
                                "chunk-size line exceeds the configured limit",
                            ));
                        }
                        return Ok(BodyDecodeStatus::Incomplete { consumed: offset });
                    };
                    if line_end > self.limits.max_chunk_line_bytes {
                        return Err(Http1Error::new(
                            Http1ErrorKind::BodyTooLarge,
                            "chunk-size line exceeds the configured limit",
                        ));
                    }
                    let size = parse_chunk_line(&input[offset..offset + line_end])?;
                    offset += line_end + 2;
                    self.chunk_state = if size == 0 {
                        ChunkState::Trailers
                    } else {
                        ChunkState::Data(size)
                    };
                }
                ChunkState::Data(remaining) => {
                    if offset == input.len() {
                        return Ok(BodyDecodeStatus::Incomplete { consumed: offset });
                    }
                    let available = input.len() - offset;
                    let consumed = usize::try_from(remaining)
                        .unwrap_or(usize::MAX)
                        .min(available);
                    let next_remaining = remaining - consumed as u64;
                    self.chunk_state = if next_remaining == 0 {
                        ChunkState::DataTerminator
                    } else {
                        ChunkState::Data(next_remaining)
                    };
                    return Ok(BodyDecodeStatus::Frame(DecodedBodyFrame {
                        frame: BodyFrame::Data(Bytes::copy_from_slice(
                            &input[offset..offset + consumed],
                        )),
                        consumed: offset + consumed,
                        end_stream: false,
                    }));
                }
                ChunkState::DataTerminator => {
                    if input.len() - offset < 2 {
                        return Ok(BodyDecodeStatus::Incomplete { consumed: offset });
                    }
                    if &input[offset..offset + 2] != b"\r\n" {
                        return Err(Http1Error::new(
                            Http1ErrorKind::InvalidChunkTerminator,
                            "chunk data is not followed by CRLF",
                        ));
                    }
                    offset += 2;
                    self.chunk_state = ChunkState::Size;
                }
                ChunkState::Trailers => {
                    let trailer_input = &input[offset..];
                    let Some(length) = find_trailer_end(trailer_input) else {
                        reject_invalid_partial_line(trailer_input, Http1ErrorKind::InvalidTrailer)?;
                        if trailer_input.len() > self.limits.max_trailer_bytes {
                            return Err(Http1Error::new(
                                Http1ErrorKind::BodyTooLarge,
                                "trailer block exceeds the configured byte limit",
                            ));
                        }
                        return Ok(BodyDecodeStatus::Incomplete { consumed: offset });
                    };
                    if length > self.limits.max_trailer_bytes {
                        return Err(Http1Error::new(
                            Http1ErrorKind::BodyTooLarge,
                            "trailer block exceeds the configured byte limit",
                        ));
                    }
                    let trailers = parse_trailers(&trailer_input[..length], self.limits)?;
                    offset += length;
                    self.chunk_state = ChunkState::Complete;
                    self.complete = true;
                    if trailers.is_empty() {
                        return Ok(BodyDecodeStatus::Complete { consumed: offset });
                    }
                    return Ok(BodyDecodeStatus::Frame(DecodedBodyFrame {
                        frame: BodyFrame::Trailers(trailers),
                        consumed: offset,
                        end_stream: true,
                    }));
                }
                ChunkState::Complete => {
                    self.complete = true;
                    return Ok(BodyDecodeStatus::Complete { consumed: offset });
                }
            }
        }
    }
}

fn find_crlf(input: &[u8]) -> Option<usize> {
    input.windows(2).position(|window| window == b"\r\n")
}

fn find_trailer_end(input: &[u8]) -> Option<usize> {
    if input.starts_with(b"\r\n") {
        Some(2)
    } else {
        input
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
    }
}

fn reject_invalid_partial_line(input: &[u8], kind: Http1ErrorKind) -> Result<(), Http1Error> {
    for (index, byte) in input.iter().copied().enumerate() {
        if byte == b'\n' && (index == 0 || input[index - 1] != b'\r') {
            return Err(Http1Error::new(
                kind,
                "HTTP/1 body metadata contains a bare line feed",
            ));
        }
        if byte == b'\r' && input.get(index + 1).is_some_and(|next| *next != b'\n') {
            return Err(Http1Error::new(
                kind,
                "HTTP/1 body metadata contains an invalid carriage return",
            ));
        }
    }
    Ok(())
}

fn parse_chunk_line(line: &[u8]) -> Result<u64, Http1Error> {
    let (size, extensions) = line
        .iter()
        .position(|byte| *byte == b';')
        .map_or((line, None), |index| (&line[..index], Some(&line[index..])));
    let size = trim_ows(size);
    if size.is_empty() || !size.iter().all(u8::is_ascii_hexdigit) {
        return Err(Http1Error::new(
            Http1ErrorKind::InvalidChunkSize,
            "chunk size must contain one or more hexadecimal digits",
        ));
    }
    let size = size.iter().try_fold(0_u64, |value, byte| {
        value.checked_mul(16)?.checked_add(hex_value(*byte)?)
    });
    let size = size.ok_or_else(|| {
        Http1Error::new(
            Http1ErrorKind::InvalidChunkSize,
            "chunk size exceeds the supported range",
        )
    })?;
    if let Some(extensions) = extensions {
        validate_chunk_extensions(extensions)?;
    }
    Ok(size)
}

fn hex_value(byte: u8) -> Option<u64> {
    match byte {
        b'0'..=b'9' => Some((byte - b'0') as u64),
        b'a'..=b'f' => Some((byte - b'a' + 10) as u64),
        b'A'..=b'F' => Some((byte - b'A' + 10) as u64),
        _ => None,
    }
}

fn validate_chunk_extensions(mut input: &[u8]) -> Result<(), Http1Error> {
    while !input.is_empty() {
        input = trim_leading_ows(input);
        if input[0] != b';' {
            return Err(invalid_extension());
        }
        input = &input[1..];
        input = trim_leading_ows(input);
        let name_len = input
            .iter()
            .take_while(|byte| is_token_byte(**byte))
            .count();
        if name_len == 0 {
            return Err(invalid_extension());
        }
        input = &input[name_len..];
        input = trim_leading_ows(input);
        if input.first() == Some(&b'=') {
            input = &input[1..];
            input = trim_leading_ows(input);
            if input.first() == Some(&b'"') {
                input = consume_quoted_string(input).ok_or_else(invalid_extension)?;
            } else {
                let value_len = input
                    .iter()
                    .take_while(|byte| is_token_byte(**byte))
                    .count();
                if value_len == 0 {
                    return Err(invalid_extension());
                }
                input = &input[value_len..];
            }
        }
        input = trim_leading_ows(input);
    }
    Ok(())
}

fn trim_leading_ows(mut input: &[u8]) -> &[u8] {
    while matches!(input.first(), Some(b' ' | b'\t')) {
        input = &input[1..];
    }
    input
}

fn consume_quoted_string(input: &[u8]) -> Option<&[u8]> {
    let mut index = 1;
    while index < input.len() {
        match input[index] {
            b'"' => return Some(&input[index + 1..]),
            b'\\' => {
                index += 1;
                let escaped = *input.get(index)?;
                if !(escaped == b'\t'
                    || escaped == b' '
                    || (0x21..=0x7e).contains(&escaped)
                    || escaped >= 0x80)
                {
                    return None;
                }
            }
            byte if byte == b'\t'
                || byte == b' '
                || byte == b'!'
                || (0x23..=0x5b).contains(&byte)
                || (0x5d..=0x7e).contains(&byte)
                || byte >= 0x80 => {}
            _ => return None,
        }
        index += 1;
    }
    None
}

fn invalid_extension() -> Http1Error {
    Http1Error::new(
        Http1ErrorKind::InvalidChunkExtension,
        "chunk extension does not match the RFC 9112 grammar",
    )
}

fn parse_trailers(input: &[u8], limits: BodyDecoderLimits) -> Result<HeaderBlock, Http1Error> {
    if input == b"\r\n" {
        return Ok(HeaderBlock::new());
    }
    if input.iter().enumerate().any(|(index, byte)| {
        (*byte == b'\n' && (index == 0 || input[index - 1] != b'\r'))
            || (*byte == b'\r' && input.get(index + 1) != Some(&b'\n'))
    }) {
        return Err(Http1Error::new(
            Http1ErrorKind::InvalidTrailer,
            "trailer block contains an invalid line ending",
        ));
    }

    let content = &input[..input.len() - 4];
    let mut trailers = HeaderBlock::new();
    for line in content.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() || matches!(line.first(), Some(b' ' | b'\t')) {
            return Err(Http1Error::new(
                Http1ErrorKind::InvalidTrailer,
                "empty or folded trailer field is rejected",
            ));
        }
        let colon = line.iter().position(|byte| *byte == b':').ok_or_else(|| {
            Http1Error::new(
                Http1ErrorKind::InvalidTrailer,
                "trailer field is missing a colon",
            )
        })?;
        if colon == 0 || matches!(line.get(colon - 1), Some(b' ' | b'\t')) {
            return Err(Http1Error::new(
                Http1ErrorKind::InvalidTrailer,
                "invalid whitespace before trailer field colon",
            ));
        }
        let field =
            HeaderField::new(&line[..colon], trim_ows(&line[colon + 1..])).map_err(|error| {
                Http1Error::new(
                    Http1ErrorKind::InvalidTrailer,
                    format!("invalid trailer field: {error}"),
                )
            })?;
        if is_forbidden_trailer(field.name()) {
            return Err(Http1Error::new(
                Http1ErrorKind::InvalidTrailer,
                "routing and framing fields are forbidden in trailers",
            ));
        }
        trailers.push(field);
        if trailers.len() > limits.max_trailers {
            return Err(Http1Error::new(
                Http1ErrorKind::BodyTooLarge,
                "trailer block exceeds the configured field count",
            ));
        }
    }
    Ok(trailers)
}

pub(crate) fn is_forbidden_trailer(name: &[u8]) -> bool {
    [
        b"content-length".as_slice(),
        b"transfer-encoding".as_slice(),
        b"host".as_slice(),
        b"trailer".as_slice(),
        b"connection".as_slice(),
        b"upgrade".as_slice(),
    ]
    .iter()
    .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
}
