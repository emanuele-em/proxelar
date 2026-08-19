use bytes::Bytes;
use proptest::collection::vec;
use proptest::prelude::*;
use proxyapi_models::{HeaderBlock, HeaderField, HeaderFieldError};

#[test]
fn preserves_global_order_duplicates_and_h1_casing() {
    let headers = HeaderBlock::from_fields([
        HeaderField::new("X-Trace", "one").unwrap(),
        HeaderField::new("Set-Cookie", "a=1").unwrap(),
        HeaderField::new("x-trace", "two").unwrap(),
        HeaderField::new("Set-Cookie", "b=2").unwrap(),
    ]);

    let fields = headers
        .iter()
        .map(|field| (field.name(), field.value()))
        .collect::<Vec<_>>();
    assert_eq!(
        fields,
        vec![
            (b"X-Trace".as_slice(), b"one".as_slice()),
            (b"Set-Cookie".as_slice(), b"a=1".as_slice()),
            (b"x-trace".as_slice(), b"two".as_slice()),
            (b"Set-Cookie".as_slice(), b"b=2".as_slice()),
        ]
    );
    assert_eq!(headers.get("X-TRACE"), Some(b"one".as_slice()));
    assert_eq!(
        headers.get_all("set-cookie").collect::<Vec<_>>(),
        vec![b"a=1".as_slice(), b"b=2".as_slice()]
    );
}

#[test]
fn set_and_remove_keep_unrelated_field_order() {
    let mut headers = HeaderBlock::from_fields([
        HeaderField::new("A", "1").unwrap(),
        HeaderField::new("X-Test", "old-1").unwrap(),
        HeaderField::new("B", "2").unwrap(),
        HeaderField::new("x-test", "old-2").unwrap(),
        HeaderField::new("C", "3").unwrap(),
    ]);

    headers.set("X-TEST", "new").unwrap();
    assert_eq!(
        headers
            .iter()
            .map(|field| (field.name(), field.value()))
            .collect::<Vec<_>>(),
        vec![
            (b"A".as_slice(), b"1".as_slice()),
            (b"X-TEST".as_slice(), b"new".as_slice()),
            (b"B".as_slice(), b"2".as_slice()),
            (b"C".as_slice(), b"3".as_slice()),
        ]
    );
    assert_eq!(headers.remove("b"), 1);
    assert_eq!(headers.remove("missing"), 0);
    assert_eq!(
        headers.iter().map(HeaderField::name).collect::<Vec<_>>(),
        vec![b"A".as_slice(), b"X-TEST".as_slice(), b"C".as_slice()]
    );
}

#[test]
fn validates_rfc_names_values_and_native_pseudo_headers() {
    assert!(HeaderField::new("content-type", "text/plain").is_ok());
    assert!(HeaderField::new(":method", "GET").is_ok());
    assert!(HeaderField::new("x-obs-text", [0x80, 0xff]).is_ok());
    assert_eq!(
        HeaderField::new("", "value"),
        Err(HeaderFieldError::EmptyName)
    );
    assert!(matches!(
        HeaderField::new("bad name", "value"),
        Err(HeaderFieldError::InvalidName { .. })
    ));
    assert!(matches!(
        HeaderField::new("x-test", b"line\r\nbreak"),
        Err(HeaderFieldError::InvalidValue { .. })
    ));
}

#[test]
fn json_uses_text_or_value_base64_and_rejects_ambiguous_values() {
    let headers = HeaderBlock::from_fields([
        HeaderField::new("X-Text", "caffè").unwrap(),
        HeaderField::new("X-Binary", [0x80, 0xff]).unwrap(),
    ]);
    let json = serde_json::to_value(&headers).unwrap();
    assert_eq!(
        json[0],
        serde_json::json!({"name": "X-Text", "value": "caffè"})
    );
    assert_eq!(
        json[1],
        serde_json::json!({"name": "X-Binary", "value_base64": "gP8="})
    );
    assert_eq!(
        serde_json::from_value::<HeaderBlock>(json).unwrap(),
        headers
    );

    let ambiguous = serde_json::json!([
        {"name": "x-test", "value": "a", "value_base64": "Yg=="}
    ]);
    assert!(serde_json::from_value::<HeaderBlock>(ambiguous).is_err());
}

#[test]
fn inline_and_shared_fields_have_identical_value_semantics() {
    let short = HeaderField::new("x-short", "value").unwrap();
    let short_owned =
        HeaderField::from_bytes(Bytes::from_static(b"x-short"), Bytes::from_static(b"value"))
            .unwrap();
    assert_eq!(short, short_owned);

    let long_value = vec![0x80; 128];
    let long = HeaderField::new("x-long", &long_value).unwrap();
    let long_owned = HeaderField::from_bytes(
        Bytes::from_static(b"x-long"),
        Bytes::from(long_value.clone()),
    )
    .unwrap();
    assert_eq!(long, long_owned);
    assert_eq!(long.clone().value(), long_value);
}

fn token_name() -> impl Strategy<Value = String> {
    vec(
        prop::sample::select(
            b"!#$%&'*+-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ^_`abcdefghijklmnopqrstuvwxyz|~"
                .to_vec(),
        ),
        1..32,
    )
    .prop_map(|bytes| String::from_utf8(bytes).unwrap())
}

fn field_value() -> impl Strategy<Value = Vec<u8>> {
    vec(
        prop::sample::select(
            std::iter::once(b'\t')
                .chain(b' '..=b'~')
                .chain(0x80..=0xff)
                .collect::<Vec<_>>(),
        ),
        0..64,
    )
}

proptest! {
    #[test]
    fn ordered_binary_header_blocks_roundtrip_json(
        fields in vec((token_name(), field_value()), 0..32)
    ) {
        let headers = HeaderBlock::from_fields(fields.into_iter().map(|(name, value)| {
            HeaderField::new(name, value).unwrap()
        }));

        let encoded = serde_json::to_vec(&headers).unwrap();
        let decoded: HeaderBlock = serde_json::from_slice(&encoded).unwrap();
        prop_assert_eq!(decoded, headers);
    }
}
