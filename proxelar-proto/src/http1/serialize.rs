use bytes::{BufMut as _, Bytes, BytesMut};
use http::Version;
use proxyapi_models::HeaderBlock;

use crate::{BodyFrame, RequestHead, ResponseHead};

use super::framing::is_forbidden_trailer;
use super::validation;
use super::{BodyFraming, Http1Error, Http1ErrorKind};

/// Serialize and revalidate an HTTP/1 request head without changing field
/// order, duplicates, casing, or value bytes.
pub fn encode_request_head(head: &RequestHead) -> Result<Bytes, Http1Error> {
    let version = version_bytes(head.version)?;
    let target = head.uri.to_string();
    if target.is_empty() {
        return Err(Http1Error::new(
            Http1ErrorKind::InvalidRequestTarget,
            "request URI has no serializable target",
        ));
    }
    let mut output = BytesMut::with_capacity(
        head.method.as_str().len()
            + target.len()
            + version.len()
            + encoded_headers_len(&head.headers),
    );
    output.extend_from_slice(head.method.as_str().as_bytes());
    output.extend_from_slice(b" ");
    output.extend_from_slice(target.as_bytes());
    output.extend_from_slice(b" ");
    output.extend_from_slice(version);
    output.extend_from_slice(b"\r\n");
    encode_headers(&mut output, &head.headers, false)?;
    output.extend_from_slice(b"\r\n");

    validation::validate_request(
        &output,
        &head.method,
        &target,
        &head.uri,
        head.version,
        &head.headers,
    )?;
    Ok(output.freeze())
}

/// Serialize and revalidate an HTTP/1 response head. Informational responses
/// use the same function and do not imply a final response or a body.
pub fn encode_response_head(head: &ResponseHead) -> Result<Bytes, Http1Error> {
    let version = version_bytes(head.version)?;
    let mut output = BytesMut::with_capacity(
        version.len()
            + head.status.as_str().len()
            + head.status.canonical_reason().map_or(0, str::len)
            + encoded_headers_len(&head.headers),
    );
    output.extend_from_slice(version);
    output.extend_from_slice(b" ");
    output.extend_from_slice(head.status.as_str().as_bytes());
    output.extend_from_slice(b" ");
    if let Some(reason) = head.status.canonical_reason() {
        output.extend_from_slice(reason.as_bytes());
    }
    output.extend_from_slice(b"\r\n");
    encode_headers(&mut output, &head.headers, false)?;
    output.extend_from_slice(b"\r\n");

    validation::validate_response(&output, head.status, head.version, &head.headers)?;
    Ok(output.freeze())
}

fn version_bytes(version: Version) -> Result<&'static [u8], Http1Error> {
    match version {
        Version::HTTP_10 => Ok(b"HTTP/1.0"),
        Version::HTTP_11 => Ok(b"HTTP/1.1"),
        _ => Err(Http1Error::new(
            Http1ErrorKind::MalformedStartLine,
            "HTTP/1 serializer only supports HTTP/1.0 and HTTP/1.1",
        )),
    }
}

fn encode_headers(
    output: &mut BytesMut,
    headers: &HeaderBlock,
    trailers: bool,
) -> Result<(), Http1Error> {
    for field in headers {
        if field.name().starts_with(b":") {
            return Err(Http1Error::new(
                if trailers {
                    Http1ErrorKind::InvalidTrailer
                } else {
                    Http1ErrorKind::MalformedHeader
                },
                "HTTP/1 cannot serialize pseudo-header fields",
            ));
        }
        if trailers && is_forbidden_trailer(field.name()) {
            return Err(Http1Error::new(
                Http1ErrorKind::InvalidTrailer,
                "routing and framing fields are forbidden in trailers",
            ));
        }
        output.extend_from_slice(field.name());
        output.extend_from_slice(b": ");
        output.extend_from_slice(field.value());
        output.extend_from_slice(b"\r\n");
    }
    Ok(())
}

fn encoded_headers_len(headers: &HeaderBlock) -> usize {
    headers
        .iter()
        .map(|field| field.name().len() + field.value().len() + 4)
        .sum::<usize>()
        + 16
}

/// Stateful frame serializer that enforces the framing selected from a head.
#[derive(Debug)]
pub struct BodyEncoder {
    framing: BodyFraming,
    fixed_remaining: u64,
    complete: bool,
}

impl BodyEncoder {
    pub const fn new(framing: BodyFraming) -> Self {
        let fixed_remaining = match framing {
            BodyFraming::ContentLength(length) => length,
            _ => 0,
        };
        let complete = matches!(framing, BodyFraming::None | BodyFraming::Tunnel);
        Self {
            framing,
            fixed_remaining,
            complete,
        }
    }

    pub const fn framing(&self) -> BodyFraming {
        self.framing
    }

    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn encode(&mut self, frame: BodyFrame) -> Result<Bytes, Http1Error> {
        if self.complete {
            return Err(Http1Error::new(
                Http1ErrorKind::UnexpectedBodyFrame,
                "body frame arrived after the HTTP/1 message completed",
            ));
        }
        match (self.framing, frame) {
            (BodyFraming::None | BodyFraming::Tunnel, _) => Err(Http1Error::new(
                Http1ErrorKind::UnexpectedBodyFrame,
                "this HTTP/1 message cannot carry body frames",
            )),
            (BodyFraming::ContentLength(_), BodyFrame::Data(data)) => {
                let length = data.len() as u64;
                if length > self.fixed_remaining {
                    return Err(Http1Error::new(
                        Http1ErrorKind::BodyLengthMismatch,
                        "body exceeds the declared Content-Length",
                    ));
                }
                self.fixed_remaining -= length;
                Ok(data)
            }
            (BodyFraming::ContentLength(_), BodyFrame::Trailers(_)) => Err(Http1Error::new(
                Http1ErrorKind::UnexpectedBodyFrame,
                "trailers require chunked transfer coding in HTTP/1",
            )),
            (BodyFraming::Chunked, BodyFrame::Data(data)) => {
                if data.is_empty() {
                    return Ok(Bytes::new());
                }
                let mut output = BytesMut::with_capacity(data.len() + 32);
                put_hex(&mut output, data.len());
                output.put_slice(b"\r\n");
                output.extend_from_slice(&data);
                output.extend_from_slice(b"\r\n");
                Ok(output.freeze())
            }
            (BodyFraming::Chunked, BodyFrame::Trailers(trailers)) => {
                let mut output = BytesMut::new();
                output.extend_from_slice(b"0\r\n");
                encode_headers(&mut output, &trailers, true)?;
                output.extend_from_slice(b"\r\n");
                self.complete = true;
                Ok(output.freeze())
            }
            (BodyFraming::UntilEof, BodyFrame::Data(data)) => Ok(data),
            (BodyFraming::UntilEof, BodyFrame::Trailers(_)) => Err(Http1Error::new(
                Http1ErrorKind::UnexpectedBodyFrame,
                "EOF-delimited HTTP/1 bodies cannot carry trailers",
            )),
        }
    }

    /// Finish the message and return any terminal wire bytes.
    pub fn finish(&mut self) -> Result<Bytes, Http1Error> {
        if self.complete {
            return Ok(Bytes::new());
        }
        match self.framing {
            BodyFraming::None | BodyFraming::Tunnel => {
                self.complete = true;
                Ok(Bytes::new())
            }
            BodyFraming::ContentLength(_) if self.fixed_remaining != 0 => Err(Http1Error::new(
                Http1ErrorKind::BodyLengthMismatch,
                format!(
                    "HTTP/1 body ended with {} Content-Length bytes missing",
                    self.fixed_remaining
                ),
            )),
            BodyFraming::ContentLength(_) | BodyFraming::UntilEof => {
                self.complete = true;
                Ok(Bytes::new())
            }
            BodyFraming::Chunked => {
                self.complete = true;
                Ok(Bytes::from_static(b"0\r\n\r\n"))
            }
        }
    }
}

fn put_hex(output: &mut BytesMut, mut value: usize) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut digits = [0_u8; usize::BITS as usize / 4];
    let mut index = digits.len();
    loop {
        index -= 1;
        digits[index] = HEX[value & 0x0f];
        value >>= 4;
        if value == 0 {
            break;
        }
    }
    output.extend_from_slice(&digits[index..]);
}
