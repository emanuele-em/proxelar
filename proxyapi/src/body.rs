use rama::bytes::Bytes;
use rama::http::Body;

/// HTTP body type used throughout the proxy, for both requests and responses.
pub type ProxyBody = Body;

/// Create a body from the given bytes.
pub fn full(bytes: Bytes) -> ProxyBody {
    Body::from(bytes)
}

/// Create an empty body.
pub fn empty() -> ProxyBody {
    Body::empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::http::body::util::BodyExt;

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
