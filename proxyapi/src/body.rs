use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};

/// Boxed HTTP body type used throughout the proxy.
///
/// Erases the concrete body type so that both `Full` (captured) and `Empty`
/// bodies can be returned in the same position.
pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

/// Create a body from the given bytes.
pub fn full(bytes: Bytes) -> ProxyBody {
    Full::new(bytes).map_err(|never| match never {}).boxed()
}

/// Create an empty body.
#[must_use]
pub fn empty() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn test_full_body() {
        let body = full(Bytes::from("hello"));
        let collected = body.collect().await.unwrap().to_bytes();
        assert_eq!(collected, Bytes::from("hello"));
    }

    #[tokio::test]
    async fn test_empty_body() {
        let body = empty();
        let collected = body.collect().await.unwrap().to_bytes();
        assert!(collected.is_empty());
    }
}
