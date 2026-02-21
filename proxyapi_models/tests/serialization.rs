use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri, Version};
use proxyapi_models::{ProxiedRequest, ProxiedResponse};

#[test]
fn test_proxied_request_serialization() {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", "application/json".parse().unwrap());

    let req = ProxiedRequest::new(
        Method::POST,
        "https://example.com/api".parse().unwrap(),
        Version::HTTP_11,
        headers,
        Bytes::from(r#"{"key":"value"}"#),
        1234567890,
    );

    let json = serde_json::to_string(&req).unwrap();
    let deserialized: ProxiedRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, deserialized);
}

#[test]
fn test_proxied_response_serialization() {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", "text/plain".parse().unwrap());

    let res = ProxiedResponse::new(
        StatusCode::OK,
        Version::HTTP_11,
        headers,
        Bytes::from("hello"),
        1234567890,
    );

    let json = serde_json::to_string(&res).unwrap();
    let deserialized: ProxiedResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(res, deserialized);
}

#[test]
fn test_proxied_request_empty_body() {
    let req = ProxiedRequest::new(
        Method::GET,
        "https://example.com/".parse().unwrap(),
        Version::HTTP_11,
        HeaderMap::new(),
        Bytes::new(),
        0,
    );

    let json = serde_json::to_string(&req).unwrap();
    let deserialized: ProxiedRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, deserialized);
}

#[test]
fn test_proxied_response_accessors() {
    let mut headers = HeaderMap::new();
    headers.insert("x-custom", "value".parse().unwrap());

    let res = ProxiedResponse::new(
        StatusCode::NOT_FOUND,
        Version::HTTP_11,
        headers,
        Bytes::from("not found"),
        999,
    );

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert_eq!(res.version(), Version::HTTP_11);
    assert_eq!(res.body().as_ref(), b"not found");
    assert_eq!(res.time(), 999);
    assert!(res.headers().contains_key("x-custom"));
}

#[test]
fn test_proxied_request_accessors() {
    let mut headers = HeaderMap::new();
    headers.insert("x-req", "value".parse().unwrap());

    let req = ProxiedRequest::new(
        Method::PUT,
        "https://example.com/path?q=1".parse::<Uri>().unwrap(),
        Version::HTTP_11,
        headers,
        Bytes::from("request body"),
        42,
    );

    assert_eq!(req.method(), Method::PUT);
    assert_eq!(req.uri().path(), "/path");
    assert_eq!(req.version(), Version::HTTP_11);
    assert_eq!(req.body().as_ref(), b"request body");
    assert_eq!(req.time(), 42);
    assert!(req.headers().contains_key("x-req"));
}

#[test]
fn test_proxied_request_multiple_headers_same_key() {
    let mut headers = HeaderMap::new();
    headers.append("set-cookie", "a=1".parse().unwrap());
    headers.append("set-cookie", "b=2".parse().unwrap());

    let req = ProxiedRequest::new(
        Method::GET,
        "https://example.com/".parse().unwrap(),
        Version::HTTP_11,
        headers,
        Bytes::new(),
        0,
    );

    let json = serde_json::to_string(&req).unwrap();
    let deserialized: ProxiedRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, deserialized);
    assert_eq!(
        deserialized.headers().get_all("set-cookie").iter().count(),
        2
    );
}

#[test]
fn test_proxied_response_large_body() {
    let body = Bytes::from(vec![0xABu8; 1024 * 1024]); // 1MB
    let res = ProxiedResponse::new(
        StatusCode::OK,
        Version::HTTP_11,
        HeaderMap::new(),
        body.clone(),
        0,
    );

    let json = serde_json::to_string(&res).unwrap();
    let deserialized: ProxiedResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.body().len(), 1024 * 1024);
    assert_eq!(res, deserialized);
}
