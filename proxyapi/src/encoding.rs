//! `content-encoding` (de)compression for the Lua scripting hooks.
//!
//! Lua scripts always see plaintext bodies: the proxy decodes a compressed
//! body before invoking a hook and re-encodes the script's result on the way
//! out, mirroring mitmproxy. Only the codecs below are handled; any other
//! `content-encoding` is left untouched and passed through verbatim.

use std::io::{self, Read, Write};

use bytes::Bytes;
use http::header::{HeaderMap, HeaderValue, CONTENT_ENCODING, CONTENT_LENGTH};

/// A `content-encoding` the proxy can both decode and re-encode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Codec {
    Gzip,
    Deflate,
    Brotli,
}

impl Codec {
    /// The codec named by a message's `content-encoding`, if we support it.
    ///
    /// Returns `None` for identity, absent, multi-codec, or unknown values,
    /// which the caller treats as "pass the body through unchanged".
    fn from_headers(headers: &HeaderMap) -> Option<Self> {
        let value = headers.get(CONTENT_ENCODING)?.to_str().ok()?;
        match value.trim().to_ascii_lowercase().as_str() {
            "gzip" | "x-gzip" => Some(Self::Gzip),
            "deflate" => Some(Self::Deflate),
            "br" => Some(Self::Brotli),
            _ => None,
        }
    }

    fn decode(self, data: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        match self {
            Self::Gzip => {
                flate2::read::GzDecoder::new(data).read_to_end(&mut out)?;
            }
            Self::Deflate => {
                // Per RFC 7230 `deflate` is zlib-wrapped, but some servers send
                // a raw DEFLATE stream — fall back to that if zlib framing fails.
                if flate2::read::ZlibDecoder::new(data)
                    .read_to_end(&mut out)
                    .is_err()
                {
                    out.clear();
                    flate2::read::DeflateDecoder::new(data).read_to_end(&mut out)?;
                }
            }
            Self::Brotli => {
                brotli::Decompressor::new(data, 4096).read_to_end(&mut out)?;
            }
        }
        Ok(out)
    }

    fn encode(self, data: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::Gzip => {
                let mut enc =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                enc.write_all(data)?;
                enc.finish()
            }
            Self::Deflate => {
                let mut enc =
                    flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
                enc.write_all(data)?;
                enc.finish()
            }
            Self::Brotli => {
                let mut out = Vec::new();
                {
                    let mut enc = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
                    enc.write_all(data)?;
                    enc.flush()?;
                }
                Ok(out)
            }
        }
    }
}

/// Decode `body` for a script hook, based on the message's `content-encoding`.
///
/// Returns `Some(plaintext)` when the body was decoded. Returns `None` when
/// there is no supported codec (or decoding fails), in which case the caller
/// hands the script the original bytes and does not re-encode afterward.
pub(crate) fn decode_for_hook(headers: &HeaderMap, body: &[u8]) -> Option<Bytes> {
    let codec = Codec::from_headers(headers)?;
    match codec.decode(body) {
        Ok(plaintext) => Some(Bytes::from(plaintext)),
        Err(e) => {
            tracing::warn!("Failed to decode {codec:?} body for script; passing through: {e}");
            None
        }
    }
}

/// Whether the original wire bytes are still valid for the hook's returned
/// headers after the body was decoded for Lua and returned unchanged.
pub(crate) fn can_reuse_wire_body(
    original_headers: &HeaderMap,
    updated_headers: &HeaderMap,
) -> bool {
    matches!(
        (
            Codec::from_headers(original_headers),
            Codec::from_headers(updated_headers),
        ),
        (Some(original), Some(updated)) if original == updated
    )
}

/// Re-encode a script's plaintext `body` to the message's `content-encoding`
/// and refresh `content-length`. Serves identity — stripping `content-encoding`
/// — when the script left no supported codec or compression fails.
///
/// Only call this when [`decode_for_hook`] returned `Some`, i.e. the body was
/// decoded before the hook ran.
pub(crate) fn encode_from_hook(headers: &mut HeaderMap, body: Bytes) -> Bytes {
    let body = match Codec::from_headers(headers) {
        Some(codec) => match codec.encode(&body) {
            Ok(encoded) => Bytes::from(encoded),
            Err(e) => {
                tracing::warn!("Failed to re-encode body as {codec:?}; serving identity: {e}");
                headers.remove(CONTENT_ENCODING);
                body
            }
        },
        None => {
            headers.remove(CONTENT_ENCODING);
            body
        }
    };

    if let Ok(len) = HeaderValue::try_from(body.len().to_string()) {
        headers.insert(CONTENT_LENGTH, len);
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with_encoding(encoding: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_ENCODING, encoding.parse().unwrap());
        headers
    }

    #[test]
    fn roundtrip_each_codec() {
        let payload = b"the quick brown fox jumps over the lazy dog".repeat(10);
        for encoding in ["gzip", "deflate", "br"] {
            let headers = headers_with_encoding(encoding);
            let codec = Codec::from_headers(&headers).unwrap();
            let compressed = codec.encode(&payload).unwrap();
            let decoded = codec.decode(&compressed).unwrap();
            assert_eq!(decoded, payload, "{encoding} roundtrip mismatch");
        }
    }

    #[test]
    fn from_headers_ignores_unknown_and_identity() {
        assert!(Codec::from_headers(&HeaderMap::new()).is_none());
        assert!(Codec::from_headers(&headers_with_encoding("identity")).is_none());
        assert!(Codec::from_headers(&headers_with_encoding("zstd")).is_none());
    }

    #[test]
    fn decode_for_hook_returns_plaintext() {
        let headers = headers_with_encoding("gzip");
        let compressed = Codec::Gzip.encode(b"hello world").unwrap();
        let decoded = decode_for_hook(&headers, &compressed).unwrap();
        assert_eq!(decoded.as_ref(), b"hello world");
    }

    #[test]
    fn decode_for_hook_passthrough_without_codec() {
        assert!(decode_for_hook(&HeaderMap::new(), b"plain").is_none());
    }

    #[test]
    fn can_reuse_wire_body_requires_same_supported_codec() {
        assert!(can_reuse_wire_body(
            &headers_with_encoding("br"),
            &headers_with_encoding("BR")
        ));
        assert!(!can_reuse_wire_body(
            &headers_with_encoding("br"),
            &headers_with_encoding("gzip")
        ));
        assert!(!can_reuse_wire_body(
            &headers_with_encoding("br"),
            &HeaderMap::new()
        ));
    }

    #[test]
    fn encode_from_hook_recompresses_and_sets_length() {
        let mut headers = headers_with_encoding("br");
        let wire = encode_from_hook(&mut headers, Bytes::from_static(b"recompress me"));

        assert_eq!(headers.get(CONTENT_ENCODING).unwrap(), "br");
        assert_eq!(
            headers.get(CONTENT_LENGTH).unwrap(),
            wire.len().to_string().as_str()
        );
        let back = Codec::Brotli.decode(&wire).unwrap();
        assert_eq!(back, b"recompress me");
    }

    #[test]
    fn encode_from_hook_serves_identity_when_codec_removed() {
        let mut headers = HeaderMap::new();
        let wire = encode_from_hook(&mut headers, Bytes::from_static(b"plain body"));

        assert!(headers.get(CONTENT_ENCODING).is_none());
        assert_eq!(wire.as_ref(), b"plain body");
        assert_eq!(headers.get(CONTENT_LENGTH).unwrap(), "10");
    }
}
