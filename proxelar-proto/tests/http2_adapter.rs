use h2::ext::Protocol;
use http::{Method, Response, StatusCode, Version};
use proxelar_proto::http2::{
    decode_request_head, decode_response_head, encode_request_head, encode_response_head,
    from_h2_request, from_h2_response, from_h2_trailers, to_h2_request, to_h2_response,
    to_h2_trailers,
};
use proxelar_proto::{ErrorKind, RequestHead, ResponseHead};
use proxyapi_models::{HeaderBlock, HeaderField};

fn field(name: &str, value: impl AsRef<[u8]>) -> HeaderField {
    HeaderField::new(name, value).unwrap()
}

#[test]
fn h1_request_translation_adds_pseudo_headers_and_preserves_duplicate_order() {
    let head = RequestHead::new(
        Method::POST,
        "https://example.test/upload?q=1".parse().unwrap(),
        Version::HTTP_11,
        HeaderBlock::from_fields([
            field("Host", "stale.test"),
            field("X-Trace", "one"),
            field("Connection", "x-remove"),
            field("x-remove", "gone"),
            field("x-trace", [0x80, 0xff]),
            field("TE", "trailers"),
        ]),
    );

    let block = encode_request_head(&head).unwrap();
    let pairs = block
        .iter()
        .map(|field| (field.name().to_vec(), field.value().to_vec()))
        .collect::<Vec<_>>();
    assert_eq!(
        pairs,
        vec![
            (b":method".to_vec(), b"POST".to_vec()),
            (b":scheme".to_vec(), b"https".to_vec()),
            (b":authority".to_vec(), b"example.test".to_vec()),
            (b":path".to_vec(), b"/upload?q=1".to_vec()),
            (b"x-trace".to_vec(), b"one".to_vec()),
            (b"x-trace".to_vec(), vec![0x80, 0xff]),
            (b"te".to_vec(), b"trailers".to_vec()),
        ]
    );

    let decoded = decode_request_head(&block).unwrap();
    assert_eq!(decoded.version, Version::HTTP_2);
    assert_eq!(decoded.uri, head.uri);
    assert_eq!(
        decoded.headers.get_all("x-trace").collect::<Vec<_>>(),
        vec![b"one".as_slice(), [0x80, 0xff].as_slice()]
    );
}

#[test]
fn strict_decoder_rejects_pseudo_order_uppercase_duplicates_and_hop_fields() {
    let cases = [
        HeaderBlock::from_fields([
            field(":method", "GET"),
            field("x-test", "one"),
            field(":scheme", "https"),
            field(":authority", "example.test"),
            field(":path", "/"),
        ]),
        HeaderBlock::from_fields([
            field(":method", "GET"),
            field(":method", "POST"),
            field(":scheme", "https"),
            field(":authority", "example.test"),
            field(":path", "/"),
        ]),
        HeaderBlock::from_fields([
            field(":method", "GET"),
            field(":scheme", "https"),
            field(":authority", "example.test"),
            field(":path", "/"),
            field("X-Test", "bad"),
        ]),
        HeaderBlock::from_fields([
            field(":method", "GET"),
            field(":scheme", "https"),
            field(":authority", "example.test"),
            field(":path", "/"),
            field("connection", "close"),
        ]),
    ];
    for block in cases {
        assert_eq!(
            decode_request_head(&block).unwrap_err().kind(),
            ErrorKind::ProtocolViolation
        );
    }
}

#[test]
fn standard_and_extended_connect_use_native_h2_shapes() {
    let standard = RequestHead::new(
        Method::CONNECT,
        "example.test:443".parse().unwrap(),
        Version::HTTP_11,
        HeaderBlock::new(),
    );
    let standard = encode_request_head(&standard).unwrap();
    assert_eq!(standard.len(), 2);
    assert_eq!(
        standard.get(":authority"),
        Some(b"example.test:443".as_slice())
    );
    assert_eq!(
        decode_request_head(&standard).unwrap().method,
        Method::CONNECT
    );

    let extended = RequestHead::new(
        Method::CONNECT,
        "https://example.test/chat".parse().unwrap(),
        Version::HTTP_2,
        HeaderBlock::from_fields([field(":protocol", "websocket")]),
    );
    let request = to_h2_request(&extended).unwrap();
    assert_eq!(
        request.extensions().get::<Protocol>().unwrap().as_str(),
        "websocket"
    );
    let decoded = from_h2_request(&request).unwrap();
    assert_eq!(decoded.headers.iter().next().unwrap().name(), b":protocol");
    assert_eq!(
        decoded.headers.get(":protocol"),
        Some(b"websocket".as_slice())
    );
    assert_eq!(decoded.uri, extended.uri);
}

#[test]
fn responses_and_trailers_round_trip_through_h2_http_types() {
    let head = ResponseHead::new(
        StatusCode::EARLY_HINTS,
        Version::HTTP_11,
        HeaderBlock::from_fields([
            field("Link", "</one>"),
            field("link", "</two>"),
            field("Connection", "close"),
        ]),
    );
    let block = encode_response_head(&head).unwrap();
    assert_eq!(block.get(":status"), Some(b"103".as_slice()));
    assert_eq!(
        block.get_all("link").collect::<Vec<_>>(),
        vec![b"</one>".as_slice(), b"</two>".as_slice()]
    );
    assert_eq!(
        decode_response_head(&block).unwrap().version,
        Version::HTTP_2
    );

    let response = to_h2_response(&head).unwrap();
    assert_eq!(
        from_h2_response(&response).unwrap().status,
        StatusCode::EARLY_HINTS
    );

    let trailers =
        HeaderBlock::from_fields([field("X-Checksum", "one"), field("x-checksum", "two")]);
    let wire = to_h2_trailers(&trailers).unwrap();
    assert_eq!(
        wire.get_all("x-checksum")
            .iter()
            .map(http::HeaderValue::as_bytes)
            .collect::<Vec<_>>(),
        vec![b"one".as_slice(), b"two".as_slice()]
    );
    let restored = from_h2_trailers(&wire).unwrap();
    assert_eq!(
        restored.get_all("x-checksum").collect::<Vec<_>>(),
        vec![b"one".as_slice(), b"two".as_slice()]
    );
}

#[test]
fn invalid_h2_response_shapes_are_rejected() {
    let missing = HeaderBlock::from_fields([field("x-test", "one")]);
    assert_eq!(
        decode_response_head(&missing).unwrap_err().kind(),
        ErrorKind::ProtocolViolation
    );

    let response = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(())
        .unwrap();
    assert_eq!(
        from_h2_response(&response).unwrap().version,
        Version::HTTP_2
    );
}
