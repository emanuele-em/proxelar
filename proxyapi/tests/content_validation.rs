use proxyapi::content::{content_view, decode_body, editable_content, encode_edit, ContentKind};
use proxyapi_models::HeaderBlock;
use std::io::Write;

fn headers(media_type: &str) -> HeaderBlock {
    let mut headers = HeaderBlock::new();
    headers.add("Content-Type", media_type).unwrap();
    headers
}

#[test]
fn protobuf_fixed64_and_binary_fields_round_trip_without_loss() {
    let bytes = [
        0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x12, 2, 0, 0xff,
    ];
    let editor = editable_content(&headers("application/protobuf"), &bytes)
        .unwrap()
        .unwrap();
    assert!(editor.text.contains("18446744073709551615"));
    assert!(editor.text.contains("base64"));
    assert_eq!(
        encode_edit("protobuf", &editor.text).unwrap().as_ref(),
        bytes
    );
}

#[test]
fn protobuf_editor_rejects_malformed_wire_and_invalid_edits() {
    for bytes in [
        vec![0],
        vec![8],
        vec![0x80; 11],
        vec![0x0b],
        vec![0x09, 1],
        vec![0x12, 5, 1],
        vec![0x0d, 1],
    ] {
        assert!(
            editable_content(&headers("application/protobuf"), &bytes).is_err(),
            "{bytes:?}"
        );
        // Inspection must still display malformed data without crashing.
        assert_eq!(
            content_view(&headers("application/protobuf"), &bytes)
                .unwrap()
                .kind,
            ContentKind::Protobuf
        );
    }
    for text in [
        r#"[{"field":0,"wire":"varint","value":"1"}]"#,
        r#"[{"field":536870912,"wire":"varint","value":"1"}]"#,
        r#"[{"field":1,"wire":"varint","value":"-1"}]"#,
        r#"[{"field":1,"wire":"fixed32","value":"4294967296"}]"#,
        r#"[{"field":1,"wire":"length_delimited","encoding":"base64","value":"!"}]"#,
        r#"[{"field":1,"wire":"length_delimited","encoding":"hex","value":"ff"}]"#,
    ] {
        assert!(encode_edit("protobuf", text).is_err(), "{text}");
    }
    assert!(encode_edit("unsupported", "[]").is_err());
    assert!(encode_edit("messagepack", "{").is_err());
    assert!(editable_content(&headers("application/msgpack"), &[0xc1]).is_err());
}

#[test]
fn stacked_content_encodings_and_raw_deflate_are_decoded() {
    let payload = b"ordered headers and body";
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(payload).unwrap();
    let gzip = gzip.finish().unwrap();
    let mut deflate =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    deflate.write_all(&gzip).unwrap();
    let mut headers = headers("text/plain");
    headers
        .add("Content-Encoding", "identity, x-gzip, deflate")
        .unwrap();
    assert_eq!(
        decode_body(&headers, &deflate.finish().unwrap())
            .unwrap()
            .as_ref(),
        payload
    );
    for encoding in ["gzip", "br", "zstd", "deflate"] {
        headers.set("Content-Encoding", encoding).unwrap();
        assert!(
            decode_body(&headers, b"invalid compressed data").is_err(),
            "{encoding}"
        );
    }
}

#[test]
fn header_media_types_select_safe_text_and_image_views() {
    for (media_type, bytes, kind) in [
        ("text/css", b"p { color: red }".as_slice(), ContentKind::Css),
        ("text/javascript", b"alert(1)", ContentKind::JavaScript),
        ("text/html", b"<p>hello</p>", ContentKind::Html),
        ("image/jpeg", b"image", ContentKind::Image),
        ("image/gif", b"image", ContentKind::Image),
        ("image/webp", b"image", ContentKind::Image),
        ("application/unknown", b"text", ContentKind::Text),
        ("application/unknown", b"\xff", ContentKind::Binary),
    ] {
        let view = content_view(&headers(media_type), bytes).unwrap();
        assert_eq!(view.kind, kind);
    }
    assert!(editable_content(&headers("text/plain"), b"ordinary text")
        .unwrap()
        .is_none());
}
