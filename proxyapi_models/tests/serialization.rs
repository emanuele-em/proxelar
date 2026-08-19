use proxyapi_models::{
    BodyMetadata, CapturedDnsExchange, CapturedUdpExchange, ProxiedRequest, ProxiedResponse,
    TrafficSession, WsDirection, WsFrame, WsOpcode, SESSION_FORMAT_VERSION,
};
use rama::bytes::Bytes;
use rama::http::{HeaderMap, Method, StatusCode, Version};
use rama::net::uri::Uri;

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
    assert_eq!(req.uri().path_or_root(), "/path");
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
fn headers_serialize_as_ordered_pairs_and_accept_legacy_objects() {
    let mut headers = HeaderMap::new();
    headers.append("x-first", "one".parse().unwrap());
    headers.append("x-second", "middle".parse().unwrap());
    headers.append("x-first", "two".parse().unwrap());
    let request = ProxiedRequest::new(
        Method::GET,
        "https://example.com/".parse().unwrap(),
        Version::HTTP_11,
        headers,
        Bytes::new(),
        0,
    );

    let mut value = serde_json::to_value(&request).unwrap();
    assert_eq!(
        value["headers"],
        serde_json::json!([
            ["x-first", "one"],
            ["x-second", "middle"],
            ["x-first", "two"]
        ])
    );

    value["headers"] = serde_json::json!({
        "content-type": "text/plain",
        "set-cookie": ["a=1", "b=2"]
    });
    let decoded: ProxiedRequest = serde_json::from_value(value).unwrap();
    assert_eq!(decoded.headers()["content-type"], "text/plain");
    assert_eq!(decoded.headers().get_all("set-cookie").iter().count(), 2);
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

#[test]
fn test_ws_frame_serialization() {
    let frame = WsFrame::new(
        WsDirection::ClientToServer,
        WsOpcode::Text,
        1234,
        Bytes::from_static(b"hello"),
        false,
    );

    let json = serde_json::to_string(&frame).unwrap();
    let deserialized: WsFrame = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.direction, WsDirection::ClientToServer);
    assert_eq!(deserialized.opcode, WsOpcode::Text);
    assert_eq!(deserialized.time, 1234);
    assert_eq!(deserialized.payload.as_ref(), b"hello");
    assert!(!deserialized.truncated);
}

#[test]
fn test_ws_frame_variants_serialize() {
    let directions = [
        (WsDirection::ClientToServer, "ClientToServer"),
        (WsDirection::ServerToClient, "ServerToClient"),
    ];
    let opcodes = [
        (WsOpcode::Continuation, "Continuation"),
        (WsOpcode::Text, "Text"),
        (WsOpcode::Binary, "Binary"),
        (WsOpcode::Close, "Close"),
        (WsOpcode::Ping, "Ping"),
        (WsOpcode::Pong, "Pong"),
    ];

    for (direction, expected) in directions {
        let value = serde_json::to_value(direction).unwrap();
        assert_eq!(value, serde_json::json!(expected));
        assert_eq!(
            serde_json::from_value::<WsDirection>(serde_json::json!(expected)).unwrap(),
            direction
        );
    }

    for (opcode, expected) in opcodes {
        let value = serde_json::to_value(opcode).unwrap();
        assert_eq!(value, serde_json::json!(expected));
        assert_eq!(
            serde_json::from_value::<WsOpcode>(serde_json::json!(expected)).unwrap(),
            opcode
        );
    }

    assert!(serde_json::from_value::<WsOpcode>(serde_json::json!("text")).is_err());
}

#[test]
fn body_metadata_distinguishes_captured_bytes_from_wire_bytes() {
    let request = ProxiedRequest::new_with_body_metadata(
        Method::POST,
        "https://example.com/upload".parse().unwrap(),
        Version::HTTP_11,
        HeaderMap::new(),
        Bytes::from_static(b"prefix"),
        BodyMetadata {
            truncated: true,
            total_seen: 4096,
        },
        1,
    );
    let encoded = serde_json::to_string(&request).unwrap();
    let decoded: ProxiedRequest = serde_json::from_str(&encoded).unwrap();

    assert_eq!(decoded.body().len(), 6);
    assert_eq!(decoded.body_metadata().total_seen, 4096);
    assert!(decoded.body_metadata().truncated);
}

#[test]
fn traffic_session_roundtrip_keeps_version_and_dns_state() {
    let mut session = TrafficSession::new(123);
    session.dns_exchanges.push(CapturedDnsExchange {
        id: 7,
        name: "api.example.test".to_owned(),
        query_type: 1,
        time: 123,
        answers: vec!["127.0.0.1".to_owned()],
        overridden: true,
        completed: true,
    });
    session.udp_exchanges.push(CapturedUdpExchange {
        id: 8,
        target: "127.0.0.1:9000".to_owned(),
        client: "127.0.0.1:50000".to_owned(),
        time: 124,
        request: Bytes::from_static(b"\0request"),
        response: Bytes::from_static(b"\xffresponse"),
        response_received: true,
        request_truncated: false,
        response_truncated: true,
    });

    let encoded = serde_json::to_string(&session).unwrap();
    let decoded: TrafficSession = serde_json::from_str(&encoded).unwrap();

    assert_eq!(decoded.version, SESSION_FORMAT_VERSION);
    assert_eq!(decoded.created_at, 123);
    assert_eq!(decoded.dns_exchanges[0].answers, ["127.0.0.1"]);
    assert!(decoded.dns_exchanges[0].completed);
    assert_eq!(decoded.udp_exchanges[0].request.as_ref(), b"\0request");
    assert_eq!(decoded.udp_exchanges[0].response.as_ref(), b"\xffresponse");
    assert!(decoded.udp_exchanges[0].response_received);
    assert!(decoded.udp_exchanges[0].response_truncated);
}
