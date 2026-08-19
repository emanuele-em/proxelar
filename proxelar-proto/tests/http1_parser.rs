use http::{Method, StatusCode, Version};
use proptest::prelude::*;
use proxelar_proto::http1::{
    HeadParser, HeadParserLimits, Http1ErrorKind, ParseStatus, ParsedRequestHead,
    ParsedResponseHead,
};

fn request(input: &[u8]) -> ParsedRequestHead {
    match HeadParser::default().parse_request(input).unwrap() {
        ParseStatus::Complete(parsed) => parsed,
        ParseStatus::Incomplete => panic!("request was incomplete"),
    }
}

fn response(input: &[u8]) -> ParsedResponseHead {
    match HeadParser::default().parse_response(input).unwrap() {
        ParseStatus::Complete(parsed) => parsed,
        ParseStatus::Incomplete => panic!("response was incomplete"),
    }
}

#[test]
fn request_is_incremental_at_every_byte_boundary() {
    let wire =
        b"POST /upload?q=1 HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\n\r\nbodyNEXT";
    let head_end = wire
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    let parser = HeadParser::default();
    for boundary in 0..head_end {
        assert!(matches!(
            parser.parse_request(&wire[..boundary]).unwrap(),
            ParseStatus::Incomplete
        ));
    }

    let parsed = request(wire);
    assert_eq!(parsed.consumed, head_end);
    assert_eq!(parsed.head.method, Method::POST);
    assert_eq!(parsed.head.uri.path(), "/upload");
    assert_eq!(parsed.head.uri.query(), Some("q=1"));
    assert_eq!(parsed.semantics.content_length, Some(4));
}

#[test]
fn response_is_incremental_at_every_byte_boundary() {
    let wire = b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n";
    let parser = HeadParser::default();
    for boundary in 0..wire.len() {
        assert!(matches!(
            parser.parse_response(&wire[..boundary]).unwrap(),
            ParseStatus::Incomplete
        ));
    }
    let parsed = response(wire);
    assert_eq!(parsed.head.status, StatusCode::EARLY_HINTS);
    assert_eq!(parsed.head.version, Version::HTTP_11);
    assert_eq!(parsed.consumed, wire.len());
}

#[test]
fn preserves_interleaved_duplicates_casing_and_obs_text() {
    let parsed = request(
        b"GET / HTTP/1.1\r\nHost: example.test\r\nX-One: first\r\nx-Two: middle\r\nX-One: \xff\x80\r\n\r\n",
    );
    let fields = parsed
        .head
        .headers
        .iter()
        .map(|field| (field.name(), field.value()))
        .collect::<Vec<_>>();
    assert_eq!(
        fields,
        vec![
            (b"Host".as_slice(), b"example.test".as_slice()),
            (b"X-One".as_slice(), b"first".as_slice()),
            (b"x-Two".as_slice(), b"middle".as_slice()),
            (b"X-One".as_slice(), [0xff, 0x80].as_slice()),
        ]
    );
}

#[test]
fn accepts_safe_framing_and_rejects_smuggling_shapes() {
    let identical = request(
        b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 05\r\nContent-Length: 5\r\n\r\n",
    );
    assert_eq!(identical.semantics.content_length, Some(5));

    let chunked =
        request(b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n");
    assert!(chunked.semantics.transfer_encoded);

    let cases: &[(&[u8], Http1ErrorKind)] = &[
        (
            b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n",
            Http1ErrorKind::AmbiguousFraming,
        ),
        (
            b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\n",
            Http1ErrorKind::ConflictingContentLength,
        ),
        (
            b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: +5\r\n\r\n",
            Http1ErrorKind::InvalidContentLength,
        ),
        (
            b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            Http1ErrorKind::InvalidTransferEncoding,
        ),
        (
            b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
            Http1ErrorKind::InvalidTransferEncoding,
        ),
        (
            b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked, chunked\r\n\r\n",
            Http1ErrorKind::InvalidTransferEncoding,
        ),
        (
            b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked;foo=bar\r\n\r\n",
            Http1ErrorKind::InvalidTransferEncoding,
        ),
        (
            b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\nConnection: content-length\r\n\r\n",
            Http1ErrorKind::InvalidConnection,
        ),
    ];
    for (wire, expected) in cases {
        let error = HeadParser::default().parse_request(wire).unwrap_err();
        assert_eq!(error.kind(), *expected, "wire={wire:?}");
    }
}

#[test]
fn rejects_invalid_lines_hosts_and_targets() {
    let cases: &[(&[u8], Http1ErrorKind)] = &[
        (
            b"GET / HTTP/1.1\nHost: example.test\n\n",
            Http1ErrorKind::InvalidLineEnding,
        ),
        (
            b"GET / HTTP/1.1\r\nHost : example.test\r\n\r\n",
            Http1ErrorKind::MalformedHeader,
        ),
        (
            b"GET / HTTP/1.1\r\nHost: example.test\r\n folded\r\n\r\n",
            Http1ErrorKind::MalformedHeader,
        ),
        (b"GET / HTTP/1.1\r\n\r\n", Http1ErrorKind::MissingHost),
        (
            b"GET / HTTP/1.1\r\nHost: one.test\r\nHost: two.test\r\n\r\n",
            Http1ErrorKind::DuplicateHost,
        ),
        (
            b"GET * HTTP/1.1\r\nHost: example.test\r\n\r\n",
            Http1ErrorKind::InvalidRequestTarget,
        ),
        (
            b"CONNECT /wrong HTTP/1.1\r\nHost: example.test\r\n\r\n",
            Http1ErrorKind::InvalidRequestTarget,
        ),
    ];
    for (wire, expected) in cases {
        let error = HeadParser::default().parse_request(wire).unwrap_err();
        assert_eq!(error.kind(), *expected, "wire={wire:?}, error={error}");
    }

    let options = request(b"OPTIONS * HTTP/1.1\r\nHost: example.test\r\n\r\n");
    assert_eq!(options.head.uri.path(), "*");
    let connect = request(b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n");
    assert_eq!(connect.head.method, Method::CONNECT);
    let absolute = request(b"GET http://example.test/path HTTP/1.1\r\nHost: example.test\r\n\r\n");
    assert_eq!(absolute.head.uri.scheme_str(), Some("http"));
}

#[test]
fn enforces_head_start_line_and_header_count_limits() {
    let parser = HeadParser::new(HeadParserLimits {
        max_head_bytes: 48,
        max_start_line_bytes: 16,
        max_headers: 2,
    });
    let error = parser
        .parse_request(b"GET /this-path-is-too-long HTTP/1.1\r\n")
        .unwrap_err();
    assert_eq!(error.kind(), Http1ErrorKind::StartLineTooLarge);

    let error = parser
        .parse_request(b"GET / HTTP/1.1\r\nHost: a\r\nX-One: 1\r\nX-Two: 2\r\n\r\n")
        .unwrap_err();
    assert!(matches!(
        error.kind(),
        Http1ErrorKind::HeadTooLarge | Http1ErrorKind::TooManyHeaders
    ));

    let parser = HeadParser::new(HeadParserLimits {
        max_head_bytes: 12,
        max_start_line_bytes: 64,
        max_headers: 8,
    });
    let error = parser.parse_request(b"GET / HTTP/1.1").unwrap_err();
    assert_eq!(error.kind(), Http1ErrorKind::HeadTooLarge);

    let parser = HeadParser::new(HeadParserLimits {
        max_head_bytes: 32,
        max_start_line_bytes: 64,
        max_headers: 8,
    });
    let error = parser
        .parse_request(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\nbody")
        .unwrap_err();
    assert_eq!(error.kind(), Http1ErrorKind::HeadTooLarge);
}

#[test]
fn validates_response_framing_without_requiring_host() {
    let parsed = response(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nX-Test: yes\r\n\r\nbody");
    assert_eq!(parsed.semantics.content_length, Some(3));
    assert_eq!(parsed.head.headers.get("x-test"), Some(b"yes".as_slice()));

    let error = HeadParser::default()
        .parse_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
        )
        .unwrap_err();
    assert_eq!(error.kind(), Http1ErrorKind::AmbiguousFraming);

    for wire in [
        b"HTTP/1.1 103 Early Hints\r\nContent-Length: 0\r\n\r\n".as_slice(),
        b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
    ] {
        let error = HeadParser::default().parse_response(wire).unwrap_err();
        assert_eq!(error.kind(), Http1ErrorKind::AmbiguousFraming);
    }
}

proptest! {
    #[test]
    fn arbitrary_prefixes_never_panic_or_overconsume(input in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let parser = HeadParser::default();
        if let Ok(ParseStatus::Complete(parsed)) = parser.parse_request(&input) {
            prop_assert!(parsed.consumed <= input.len());
        }
        if let Ok(ParseStatus::Complete(parsed)) = parser.parse_response(&input) {
            prop_assert!(parsed.consumed <= input.len());
        }
    }
}
