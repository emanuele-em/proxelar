//! Temporary conversions between the ordered capture model and `http` types.
//!
//! Protocol engines operate on [`proxyapi_models::HeaderBlock`]. The Hyper
//! compatibility path still uses [`http::HeaderMap`], so conversions live here
//! rather than leaking `HeaderMap` back into the public capture models.

use http::{HeaderMap, HeaderName, HeaderValue};
use proxyapi_models::{HeaderBlock, HeaderField};
use thiserror::Error;

/// An ordered header block could not be represented by `http::HeaderMap`.
#[derive(Debug, Error)]
pub enum HeaderConversionError {
    #[error("header name cannot be represented by the compatibility adapter: {0}")]
    Name(#[from] http::header::InvalidHeaderName),
    #[error("header value cannot be represented by the compatibility adapter: {0}")]
    Value(#[from] http::header::InvalidHeaderValue),
}

/// Snapshot a compatibility `HeaderMap` into the canonical ordered model.
///
/// `HeaderMap` has already discarded global interleaving and original casing;
/// native protocol adapters avoid this lossy boundary. Duplicate values remain
/// in their map iteration order.
pub fn from_http(headers: &HeaderMap) -> HeaderBlock {
    HeaderBlock::from_fields(headers.iter().map(|(name, value)| {
        HeaderField::new(name.as_str(), value.as_bytes())
            .expect("http crate header values satisfy the model's RFC validation")
    }))
}

/// Convert an ordered block for the temporary Hyper compatibility path.
pub fn to_http(headers: &HeaderBlock) -> Result<HeaderMap, HeaderConversionError> {
    let mut output = HeaderMap::with_capacity(headers.len());
    for field in headers {
        let name = HeaderName::from_bytes(field.name())?;
        let value = HeaderValue::from_bytes(field.value())?;
        output.append(name, value);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatibility_adapter_preserves_duplicate_values_and_binary_data() {
        let headers = HeaderBlock::from_fields([
            HeaderField::new("x-test", "one").unwrap(),
            HeaderField::new("x-test", [0x80, 0xff]).unwrap(),
        ]);

        let restored = to_http(&headers).unwrap();
        let values = restored
            .get_all("x-test")
            .iter()
            .map(HeaderValue::as_bytes)
            .collect::<Vec<_>>();
        assert_eq!(values, vec![b"one".as_slice(), [0x80, 0xff].as_slice()]);
        assert_eq!(from_http(&restored), headers);
    }

    #[test]
    fn compatibility_adapter_rejects_pseudo_headers() {
        let headers = HeaderBlock::from_fields([HeaderField::new(":method", "GET").unwrap()]);
        assert!(matches!(
            to_http(&headers),
            Err(HeaderConversionError::Name(_))
        ));
    }
}
