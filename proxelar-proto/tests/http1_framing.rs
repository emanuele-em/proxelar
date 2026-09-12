use bytes::Bytes;
use http::{Method, StatusCode, Uri, Version};
use proptest::prelude::*;
use proxelar_proto::http1::{
    encode_request_head, encode_response_head, BodyDecodeStatus, BodyDecoder, BodyEncoder,
    BodyFraming, HeadParser, HeaderSemantics, Http1ErrorKind, ParseStatus,
};
use proxelar_proto::{BodyFrame, RequestHead, ResponseHead};
use proxyapi_models::HeaderBlock;

fn headers(fields: &[(&[u8], &[u8])]) -> HeaderBlock {
    let mut headers = HeaderBlock::new();
    for (name, value) in fields {
        headers.add(name, value).unwrap();
    }
    headers
}

fn semantics(
    content_length: Option<u64>,
    transfer_encoded: bool,
    chunked: bool,
) -> HeaderSemantics {
    HeaderSemantics {
        content_length,
        transfer_encoded,
        chunked,
    }
}

#[test]
fn selects_request_and_response_framing_from_rfc_context() {
    assert_eq!(
        BodyFraming::for_request(semantics(None, false, false)),
        BodyFraming::None
    );
    assert_eq!(
        BodyFraming::for_request(semantics(Some(12), false, false)),
        BodyFraming::ContentLength(12)
    );
    assert_eq!(
        BodyFraming::for_request(semantics(None, true, true)),
        BodyFraming::Chunked
    );

    assert_eq!(
        BodyFraming::for_response(&Method::GET, StatusCode::OK, semantics(None, false, false)),
        BodyFraming::UntilEof
    );
    assert_eq!(
        BodyFraming::for_response(&Method::GET, StatusCode::OK, semantics(None, true, false)),
        BodyFraming::UntilEof
    );
    assert_eq!(
        BodyFraming::for_response(&Method::GET, StatusCode::OK, semantics(None, true, true)),
        BodyFraming::Chunked
    );
    for (method, status) in [
        (Method::HEAD, StatusCode::OK),
        (Method::GET, StatusCode::EARLY_HINTS),
        (Method::GET, StatusCode::NO_CONTENT),
        (Method::GET, StatusCode::NOT_MODIFIED),
    ] {
        assert_eq!(
            BodyFraming::for_response(&method, status, semantics(Some(99), false, false)),
            BodyFraming::None
        );
    }
    assert_eq!(
        BodyFraming::for_response(
            &Method::CONNECT,
            StatusCode::OK,
            semantics(Some(99), false, false)
        ),
        BodyFraming::Tunnel
    );
}

#[test]
fn head_serializer_matches_independent_wire_vectors() {
    let request = RequestHead::new(
        Method::POST,
        Uri::from_static("/submit?q=1"),
        Version::HTTP_11,
        headers(&[
            (b"Host", b"example.test"),
            (b"X-Mixed", b"one"),
            (b"x-other", b"\xff"),
            (b"X-Mixed", b"two"),
            (b"Content-Length", b"3"),
        ]),
    );
    let wire = encode_request_head(&request).unwrap();
    assert_eq!(
        wire,
        Bytes::from_static(
            b"POST /submit?q=1 HTTP/1.1\r\nHost: example.test\r\nX-Mixed: one\r\nx-other: \xff\r\nX-Mixed: two\r\nContent-Length: 3\r\n\r\n"
        )
    );
    let ParseStatus::Complete(parsed) = HeadParser::default().parse_request(&wire).unwrap() else {
        panic!("encoded request was incomplete");
    };
    assert_eq!(parsed.head, request);

    let informational = ResponseHead::new(
        StatusCode::EARLY_HINTS,
        Version::HTTP_11,
        headers(&[(b"Link", b"</style.css>; rel=preload")]),
    );
    assert_eq!(
        encode_response_head(&informational).unwrap(),
        Bytes::from_static(b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n")
    );

    let response = ResponseHead::new(
        StatusCode::OK,
        Version::HTTP_10,
        headers(&[(b"Content-Length", b"0"), (b"Set-Cookie", b"a=1")]),
    );
    assert_eq!(
        encode_response_head(&response).unwrap(),
        Bytes::from_static(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\nSet-Cookie: a=1\r\n\r\n")
    );
}

#[test]
fn fixed_length_codec_never_consumes_a_pipelined_message() {
    let mut encoder = BodyEncoder::new(BodyFraming::ContentLength(5));
    assert_eq!(
        encoder
            .encode(BodyFrame::Data(Bytes::from_static(b"he")))
            .unwrap(),
        Bytes::from_static(b"he")
    );
    assert_eq!(
        encoder
            .encode(BodyFrame::Data(Bytes::from_static(b"llo")))
            .unwrap(),
        Bytes::from_static(b"llo")
    );
    assert!(encoder.finish().unwrap().is_empty());

    let mut decoder = BodyDecoder::new(BodyFraming::ContentLength(5));
    let BodyDecodeStatus::Frame(frame) = decoder.decode(b"helloNEXT").unwrap() else {
        panic!("expected a data frame");
    };
    assert_eq!(frame.frame, BodyFrame::Data(Bytes::from_static(b"hello")));
    assert_eq!(frame.consumed, 5);
    assert!(frame.end_stream);
    assert!(decoder.is_complete());

    let mut too_short = BodyEncoder::new(BodyFraming::ContentLength(4));
    too_short
        .encode(BodyFrame::Data(Bytes::from_static(b"abc")))
        .unwrap();
    assert_eq!(
        too_short.finish().unwrap_err().kind(),
        Http1ErrorKind::BodyLengthMismatch
    );
    let mut too_long = BodyEncoder::new(BodyFraming::ContentLength(2));
    assert_eq!(
        too_long
            .encode(BodyFrame::Data(Bytes::from_static(b"abc")))
            .unwrap_err()
            .kind(),
        Http1ErrorKind::BodyLengthMismatch
    );
}

#[test]
fn chunked_decoder_handles_every_byte_boundary_extensions_and_trailers() {
    let wire = b"4 ; foo = \"a\\\"b\"\r\nWiki\r\n5;flag\r\npedia\r\n0\r\nX-One: first\r\nx-Two: \xff\r\nX-One: last\r\n\r\nNEXT";
    let message_length = wire.len() - 4;
    let mut decoder = BodyDecoder::new(BodyFraming::Chunked);
    let mut pending = Vec::new();
    let mut data = Vec::new();
    let mut trailers = None;
    let mut total_consumed = 0;

    for byte in wire {
        pending.push(*byte);
        loop {
            match decoder.decode(&pending).unwrap() {
                BodyDecodeStatus::Incomplete { consumed } => {
                    pending.drain(..consumed);
                    total_consumed += consumed;
                    break;
                }
                BodyDecodeStatus::Frame(frame) => {
                    pending.drain(..frame.consumed);
                    total_consumed += frame.consumed;
                    match frame.frame {
                        BodyFrame::Data(bytes) => data.extend_from_slice(&bytes),
                        BodyFrame::Trailers(block) => trailers = Some(block),
                    }
                    if frame.end_stream {
                        break;
                    }
                }
                BodyDecodeStatus::Complete { consumed } => {
                    pending.drain(..consumed);
                    total_consumed += consumed;
                    break;
                }
            }
        }
    }

    assert_eq!(data, b"Wikipedia");
    let trailers = trailers.unwrap();
    assert_eq!(
        trailers
            .iter()
            .map(|field| (field.name(), field.value()))
            .collect::<Vec<_>>(),
        vec![
            (b"X-One".as_slice(), b"first".as_slice()),
            (b"x-Two".as_slice(), b"\xff".as_slice()),
            (b"X-One".as_slice(), b"last".as_slice()),
        ]
    );
    assert_eq!(total_consumed, message_length);
    assert_eq!(pending, b"NEXT");
    assert!(decoder.is_complete());
}

#[test]
fn chunked_decoder_accepts_every_two_part_fragmentation() {
    let wire = b"3;name=value\r\nabc\r\n0\r\nX-End: yes\r\n\r\n";
    for boundary in 0..=wire.len() {
        let mut decoder = BodyDecoder::new(BodyFraming::Chunked);
        let mut pending = wire[..boundary].to_vec();
        let mut data = Vec::new();
        let mut trailers = None;

        drain_decoder(&mut decoder, &mut pending, &mut data, &mut trailers);
        pending.extend_from_slice(&wire[boundary..]);
        drain_decoder(&mut decoder, &mut pending, &mut data, &mut trailers);

        assert!(decoder.is_complete(), "boundary={boundary}");
        assert!(pending.is_empty(), "boundary={boundary}");
        assert_eq!(data, b"abc", "boundary={boundary}");
        assert_eq!(
            trailers.as_ref().and_then(|block| block.get("x-end")),
            Some(b"yes".as_slice()),
            "boundary={boundary}"
        );
    }
}

fn drain_decoder(
    decoder: &mut BodyDecoder,
    pending: &mut Vec<u8>,
    data: &mut Vec<u8>,
    trailers: &mut Option<HeaderBlock>,
) {
    loop {
        match decoder.decode(pending).unwrap() {
            BodyDecodeStatus::Incomplete { consumed } => {
                pending.drain(..consumed);
                if consumed == 0 {
                    break;
                }
            }
            BodyDecodeStatus::Complete { consumed } => {
                pending.drain(..consumed);
                break;
            }
            BodyDecodeStatus::Frame(frame) => {
                pending.drain(..frame.consumed);
                match frame.frame {
                    BodyFrame::Data(bytes) => data.extend_from_slice(&bytes),
                    BodyFrame::Trailers(block) => *trailers = Some(block),
                }
                if frame.end_stream {
                    break;
                }
            }
        }
    }
}

#[test]
fn chunked_encoder_round_trips_data_and_ordered_trailers() {
    let trailers = headers(&[(b"X-First", b"one"), (b"x-first", b"two")]);
    let mut encoder = BodyEncoder::new(BodyFraming::Chunked);
    let mut wire = Vec::new();
    wire.extend_from_slice(
        &encoder
            .encode(BodyFrame::Data(Bytes::from_static(b"hello")))
            .unwrap(),
    );
    wire.extend_from_slice(
        &encoder
            .encode(BodyFrame::Data(Bytes::from_static(b" world")))
            .unwrap(),
    );
    wire.extend_from_slice(
        &encoder
            .encode(BodyFrame::Trailers(trailers.clone()))
            .unwrap(),
    );
    assert_eq!(
        wire,
        b"5\r\nhello\r\n6\r\n world\r\n0\r\nX-First: one\r\nx-first: two\r\n\r\n"
    );

    let mut decoder = BodyDecoder::new(BodyFraming::Chunked);
    let mut remaining = wire.as_slice();
    let mut body = Vec::new();
    let decoded_trailers = loop {
        match decoder.decode(remaining).unwrap() {
            BodyDecodeStatus::Incomplete { .. } => panic!("complete wire was incomplete"),
            BodyDecodeStatus::Complete { consumed } => {
                remaining = &remaining[consumed..];
                break HeaderBlock::new();
            }
            BodyDecodeStatus::Frame(frame) => {
                remaining = &remaining[frame.consumed..];
                match frame.frame {
                    BodyFrame::Data(bytes) => body.extend_from_slice(&bytes),
                    BodyFrame::Trailers(block) => break block,
                }
            }
        }
    };
    assert_eq!(body, b"hello world");
    assert_eq!(decoded_trailers, trailers);
    assert!(remaining.is_empty());
}

#[test]
fn rejects_malformed_chunk_metadata_and_forbidden_trailers() {
    let cases: &[(&[u8], Http1ErrorKind)] = &[
        (b"z\r\n", Http1ErrorKind::InvalidChunkSize),
        (b"10000000000000000\r\n", Http1ErrorKind::InvalidChunkSize),
        (b"1;=bad\r\n", Http1ErrorKind::InvalidChunkExtension),
        (
            b"1;foo=\"unterminated\r\n",
            Http1ErrorKind::InvalidChunkExtension,
        ),
        (b"1\n", Http1ErrorKind::InvalidChunkSize),
        (b"1\r\naXY", Http1ErrorKind::InvalidChunkTerminator),
        (
            b"0\r\nContent-Length: 1\r\n\r\n",
            Http1ErrorKind::InvalidTrailer,
        ),
        (b"0\r\n folded: bad\r\n\r\n", Http1ErrorKind::InvalidTrailer),
    ];
    for (wire, kind) in cases {
        let mut decoder = BodyDecoder::new(BodyFraming::Chunked);
        let error = match decoder.decode(wire) {
            Err(error) => error,
            Ok(BodyDecodeStatus::Frame(frame)) => {
                let remainder = &wire[frame.consumed..];
                match decoder.decode(remainder) {
                    Err(error) => error,
                    result => panic!("wire unexpectedly decoded: {result:?}"),
                }
            }
            result => panic!("wire unexpectedly decoded: {result:?}"),
        };
        assert_eq!(error.kind(), *kind, "wire={wire:?}, error={error}");
    }
}

#[test]
fn eof_framing_completes_only_at_transport_eof() {
    let mut decoder = BodyDecoder::new(BodyFraming::UntilEof);
    let BodyDecodeStatus::Frame(frame) = decoder.decode(b"close-delimited").unwrap() else {
        panic!("expected data");
    };
    assert_eq!(
        frame.frame,
        BodyFrame::Data(Bytes::from_static(b"close-delimited"))
    );
    assert!(!frame.end_stream);
    assert!(matches!(
        decoder.decode_eof().unwrap(),
        BodyDecodeStatus::Complete { consumed: 0 }
    ));

    let mut fixed = BodyDecoder::new(BodyFraming::ContentLength(1));
    assert_eq!(
        fixed.decode_eof().unwrap_err().kind(),
        Http1ErrorKind::BodyLengthMismatch
    );
    let mut chunked = BodyDecoder::new(BodyFraming::Chunked);
    assert_eq!(
        chunked.decode_eof().unwrap_err().kind(),
        Http1ErrorKind::InvalidChunkTerminator
    );
}

#[test]
fn serializers_reject_protocol_specific_invalid_fields() {
    let pseudo = RequestHead::new(
        Method::GET,
        Uri::from_static("/"),
        Version::HTTP_11,
        headers(&[(b":authority", b"example.test"), (b"Host", b"example.test")]),
    );
    assert_eq!(
        encode_request_head(&pseudo).unwrap_err().kind(),
        Http1ErrorKind::MalformedHeader
    );

    let mut encoder = BodyEncoder::new(BodyFraming::Chunked);
    assert_eq!(
        encoder
            .encode(BodyFrame::Trailers(headers(&[(b"Host", b"wrong.test")])))
            .unwrap_err()
            .kind(),
        Http1ErrorKind::InvalidTrailer
    );
}

proptest! {
    #[test]
    fn arbitrary_chunked_prefixes_never_panic_or_overconsume(
        input in proptest::collection::vec(any::<u8>(), 0..2048)
    ) {
        let mut decoder = BodyDecoder::new(BodyFraming::Chunked);
        match decoder.decode(&input) {
            Ok(BodyDecodeStatus::Incomplete { consumed })
            | Ok(BodyDecodeStatus::Complete { consumed }) => {
                prop_assert!(consumed <= input.len());
            }
            Ok(BodyDecodeStatus::Frame(frame)) => {
                prop_assert!(frame.consumed <= input.len());
            }
            Err(_) => {}
        }
    }
}
