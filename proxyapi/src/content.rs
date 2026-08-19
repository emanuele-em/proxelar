//! Content decoding, detection, and safe human-readable previews.

use std::fmt::Write as _;
use std::io::{self, Read};

use base64::Engine as _;
use rama::bytes::Bytes;
use rama::http::header::{HeaderMap, CONTENT_ENCODING, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_DECODED_BYTES: usize = 100 * 1024 * 1024;
const BINARY_PREVIEW_BYTES: usize = 512;
const MAX_INLINE_IMAGE_BYTES: usize = 10 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentKind {
    Json,
    Xml,
    Html,
    Css,
    JavaScript,
    Form,
    Multipart,
    Image,
    Protobuf,
    MessagePack,
    Text,
    Binary,
}

impl ContentKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Json => "JSON",
            Self::Xml => "XML",
            Self::Html => "HTML",
            Self::Css => "CSS",
            Self::JavaScript => "JavaScript",
            Self::Form => "Form",
            Self::Multipart => "Multipart",
            Self::Image => "Image",
            Self::Protobuf => "Protobuf",
            Self::MessagePack => "MessagePack",
            Self::Text => "Text",
            Self::Binary => "Binary",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentView {
    pub kind: ContentKind,
    pub text: String,
    pub decoded_len: usize,
    pub content_encoding: Option<String>,
    /// Validated raster media type and base64 payload for browser rendering.
    pub inline_image: Option<InlineImage>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InlineImage {
    pub media_type: String,
    pub base64: String,
}

/// A lossless structured representation suitable for an intercept editor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EditableContent {
    pub format: EditableContentFormat,
    pub text: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EditableContentFormat {
    Protobuf,
    MessagePack,
}

impl EditableContentFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Protobuf => "protobuf",
            Self::MessagePack => "messagepack",
        }
    }
}

#[derive(Debug, Error)]
pub enum ContentError {
    #[error("unsupported content-encoding {0}")]
    UnsupportedEncoding(String),
    #[error("failed to decode {encoding}: {source}")]
    Decode {
        encoding: String,
        #[source]
        source: io::Error,
    },
    #[error("decoded body exceeds the {MAX_DECODED_BYTES} byte safety limit")]
    TooLarge,
}

#[derive(Debug, Error)]
pub enum ContentEditError {
    #[error("invalid structured editor JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid Protobuf wire data: {0}")]
    Protobuf(String),
    #[error("invalid MessagePack data: {0}")]
    MessagePack(String),
    #[error("unknown structured editor format {0}")]
    UnknownFormat(String),
    #[error(transparent)]
    Content(#[from] ContentError),
}

/// Decode all `Content-Encoding` layers in reverse application order.
pub fn decode_body(headers: &HeaderMap, body: &[u8]) -> Result<Bytes, ContentError> {
    let Some(value) = headers
        .get(CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(Bytes::copy_from_slice(body));
    };
    let encodings: Vec<String> = value
        .split(',')
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty() && value != "identity")
        .collect();
    let mut decoded = body.to_vec();
    for encoding in encodings.iter().rev() {
        decoded = decode_one(encoding, &decoded)?;
    }
    Ok(Bytes::from(decoded))
}

fn decode_one(encoding: &str, body: &[u8]) -> Result<Vec<u8>, ContentError> {
    let reader: Box<dyn Read> = match encoding {
        "gzip" | "x-gzip" => Box::new(flate2::read::GzDecoder::new(body)),
        "br" => Box::new(brotli::Decompressor::new(body, 4096)),
        "zstd" => Box::new(zstd::stream::read::Decoder::new(body).map_err(|source| {
            ContentError::Decode {
                encoding: encoding.to_owned(),
                source,
            }
        })?),
        "deflate" => return decode_deflate(body),
        unsupported => return Err(ContentError::UnsupportedEncoding(unsupported.to_owned())),
    };
    read_limited(reader, encoding)
}

fn decode_deflate(body: &[u8]) -> Result<Vec<u8>, ContentError> {
    match read_limited(flate2::read::ZlibDecoder::new(body), "deflate") {
        Ok(decoded) => Ok(decoded),
        Err(ContentError::Decode { .. }) => {
            read_limited(flate2::read::DeflateDecoder::new(body), "deflate")
        }
        Err(error) => Err(error),
    }
}

fn read_limited(reader: impl Read, encoding: &str) -> Result<Vec<u8>, ContentError> {
    let mut output = Vec::new();
    reader
        .take((MAX_DECODED_BYTES + 1) as u64)
        .read_to_end(&mut output)
        .map_err(|source| ContentError::Decode {
            encoding: encoding.to_owned(),
            source,
        })?;
    if output.len() > MAX_DECODED_BYTES {
        return Err(ContentError::TooLarge);
    }
    Ok(output)
}

/// Detect and render a decoded content body for terminal or web display.
pub fn content_view(headers: &HeaderMap, body: &[u8]) -> Result<ContentView, ContentError> {
    let decoded = decode_body(headers, body)?;
    let media_type = media_type(headers);
    let kind = detect_kind(media_type, &decoded);
    let text = render(kind, media_type, headers, &decoded);
    let inline_image = inline_image(media_type, &decoded);
    Ok(ContentView {
        kind,
        text,
        decoded_len: decoded.len(),
        content_encoding: headers
            .get(CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        inline_image,
    })
}

/// Return a lossless JSON editor for supported structured binary bodies.
///
/// Compressed bodies are decoded first. Callers should remove the original
/// content encoding after replacing the wire body, as the proxy handler does.
pub fn editable_content(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Option<EditableContent>, ContentEditError> {
    let decoded = decode_body(headers, body)?;
    let format = match detect_kind(media_type(headers), &decoded) {
        ContentKind::Protobuf => EditableContentFormat::Protobuf,
        ContentKind::MessagePack => EditableContentFormat::MessagePack,
        _ => return Ok(None),
    };
    let text = match format {
        EditableContentFormat::Protobuf => protobuf_to_json(&decoded)?,
        EditableContentFormat::MessagePack => messagepack_to_json(&decoded)?,
    };
    Ok(Some(EditableContent { format, text }))
}

/// Encode a structured editor document back to its binary wire format.
pub fn encode_edit(format: &str, text: &str) -> Result<Bytes, ContentEditError> {
    let bytes = match format {
        "protobuf" => protobuf_from_json(text)?,
        "messagepack" => messagepack_from_json(text)?,
        other => return Err(ContentEditError::UnknownFormat(other.to_owned())),
    };
    Ok(Bytes::from(bytes))
}

fn media_type(headers: &HeaderMap) -> &str {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .unwrap_or("")
}

fn detect_kind(media_type: &str, body: &[u8]) -> ContentKind {
    let media_type = media_type.to_ascii_lowercase();
    if media_type == "application/json" || media_type.ends_with("+json") {
        ContentKind::Json
    } else if media_type == "application/xml"
        || media_type == "text/xml"
        || media_type.ends_with("+xml")
    {
        ContentKind::Xml
    } else if media_type == "text/html" {
        ContentKind::Html
    } else if media_type == "text/css" {
        ContentKind::Css
    } else if matches!(
        media_type.as_str(),
        "application/javascript" | "text/javascript"
    ) {
        ContentKind::JavaScript
    } else if media_type == "application/x-www-form-urlencoded" {
        ContentKind::Form
    } else if media_type.starts_with("multipart/") {
        ContentKind::Multipart
    } else if media_type.starts_with("image/") {
        ContentKind::Image
    } else if matches!(
        media_type.as_str(),
        "application/protobuf" | "application/x-protobuf" | "application/grpc+proto"
    ) {
        ContentKind::Protobuf
    } else if matches!(
        media_type.as_str(),
        "application/msgpack" | "application/x-msgpack"
    ) {
        ContentKind::MessagePack
    } else if media_type.starts_with("text/") || std::str::from_utf8(body).is_ok() {
        ContentKind::Text
    } else {
        ContentKind::Binary
    }
}

fn render(kind: ContentKind, media_type: &str, headers: &HeaderMap, body: &[u8]) -> String {
    match kind {
        ContentKind::Json => serde_json::from_slice::<serde_json::Value>(body)
            .and_then(|value| serde_json::to_string_pretty(&value))
            .unwrap_or_else(|_| decode_text(headers, body)),
        ContentKind::Form => body
            .split(|byte| *byte == b'&')
            .map(|pair| {
                let (name, value) = pair
                    .iter()
                    .position(|byte| *byte == b'=')
                    .map_or((pair, &[][..]), |position| {
                        (&pair[..position], &pair[position + 1..])
                    });
                format!("{} = {}", percent_decode(name), percent_decode(value))
            })
            .collect::<Vec<_>>()
            .join("\n"),
        ContentKind::Image => {
            if body.len() <= MAX_INLINE_IMAGE_BYTES && raster_media_type(media_type).is_some() {
                format!("{} image · {} bytes", media_type, body.len())
            } else {
                format!(
                    "{} image · {} bytes · inline preview unavailable",
                    media_type,
                    body.len()
                )
            }
        }
        ContentKind::Multipart => render_multipart(headers, body),
        ContentKind::Protobuf => {
            protobuf_to_json(body).unwrap_or_else(|_| binary_preview(kind, body))
        }
        ContentKind::MessagePack => {
            messagepack_to_json(body).unwrap_or_else(|_| binary_preview(kind, body))
        }
        ContentKind::Binary => binary_preview(kind, body),
        ContentKind::Xml | ContentKind::Html => pretty_markup(&decode_text(headers, body)),
        ContentKind::Css | ContentKind::JavaScript | ContentKind::Text => {
            decode_text(headers, body)
        }
    }
}

fn inline_image(media_type: &str, body: &[u8]) -> Option<InlineImage> {
    let media_type = raster_media_type(media_type)?;
    (body.len() <= MAX_INLINE_IMAGE_BYTES).then(|| InlineImage {
        media_type: media_type.to_owned(),
        base64: base64::engine::general_purpose::STANDARD.encode(body),
    })
}

fn raster_media_type(media_type: &str) -> Option<&'static str> {
    match media_type.to_ascii_lowercase().as_str() {
        "image/png" => Some("image/png"),
        "image/jpeg" | "image/jpg" => Some("image/jpeg"),
        "image/gif" => Some("image/gif"),
        "image/webp" => Some("image/webp"),
        "image/bmp" => Some("image/bmp"),
        "image/avif" => Some("image/avif"),
        _ => None,
    }
}

fn pretty_markup(input: &str) -> String {
    let mut output = String::new();
    let mut cursor = 0;
    let mut depth = 0_usize;

    while let Some(relative_start) = input[cursor..].find('<') {
        let start = cursor + relative_start;
        let text = input[cursor..start].trim();
        if !text.is_empty() {
            markup_line(&mut output, depth, text);
        }
        let Some(relative_end) = input[start..].find('>') else {
            let tail = input[start..].trim();
            if !tail.is_empty() {
                markup_line(&mut output, depth, tail);
            }
            cursor = input.len();
            break;
        };
        let end = start + relative_end + 1;
        let tag = input[start..end].trim();
        let closing = tag.starts_with("</");
        if closing {
            depth = depth.saturating_sub(1);
        }
        markup_line(&mut output, depth, tag);
        if !closing && markup_opens_scope(tag) {
            depth = depth.saturating_add(1);
        }
        cursor = end;
    }
    let tail = input[cursor..].trim();
    if !tail.is_empty() {
        markup_line(&mut output, depth, tail);
    }
    output.trim_end().to_owned()
}

fn markup_line(output: &mut String, depth: usize, value: &str) {
    if !output.is_empty() {
        output.push('\n');
    }
    for _ in 0..depth {
        output.push_str("  ");
    }
    output.push_str(value);
}

fn markup_opens_scope(tag: &str) -> bool {
    if tag.ends_with("/>") || tag.starts_with("<!") || tag.starts_with("<?") {
        return false;
    }
    let name = tag
        .trim_start_matches('<')
        .split(|character: char| character.is_ascii_whitespace() || character == '>')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    !matches!(
        name.as_str(),
        "area"
            | "base"
            | "br"
            | "col"
            | "embed"
            | "hr"
            | "img"
            | "input"
            | "link"
            | "meta"
            | "param"
            | "source"
            | "track"
            | "wbr"
    )
}

fn render_multipart(headers: &HeaderMap, body: &[u8]) -> String {
    let Some(boundary) = content_type_parameter(headers, "boundary") else {
        return format!("Multipart body · {} bytes · boundary missing", body.len());
    };
    if boundary.is_empty() || boundary.len() > 70 || boundary.bytes().any(|byte| byte < 0x20) {
        return format!("Multipart body · {} bytes · invalid boundary", body.len());
    }
    let delimiter = format!("--{boundary}").into_bytes();
    let mut parts = Vec::new();
    let mut cursor = 0;
    while let Some(start) = find_bytes(&body[cursor..], &delimiter) {
        let start = cursor + start + delimiter.len();
        if body.get(start..start + 2) == Some(b"--") {
            break;
        }
        let content_start = if body.get(start..start + 2) == Some(b"\r\n") {
            start + 2
        } else if body.get(start) == Some(&b'\n') {
            start + 1
        } else {
            start
        };
        let Some(next) = find_bytes(&body[content_start..], &delimiter) else {
            break;
        };
        let mut part = &body[content_start..content_start + next];
        part = part
            .strip_suffix(b"\r\n")
            .or_else(|| part.strip_suffix(b"\n"))
            .unwrap_or(part);
        parts.push(part);
        cursor = content_start + next;
    }

    let mut output = format!(
        "Multipart body · {} parts · {} bytes",
        parts.len(),
        body.len()
    );
    for (index, part) in parts.into_iter().enumerate() {
        let separator = find_bytes(part, b"\r\n\r\n")
            .map(|position| (position, 4))
            .or_else(|| find_bytes(part, b"\n\n").map(|position| (position, 2)));
        let (head, content) = separator
            .map(|(position, length)| (&part[..position], &part[position + length..]))
            .unwrap_or((&[][..], part));
        write!(output, "\n\nPart {} · {} bytes", index + 1, content.len())
            .expect("writing to String cannot fail");
        if !head.is_empty() {
            output.push('\n');
            output.push_str(&String::from_utf8_lossy(head));
        }
        output.push_str("\n\n");
        if let Ok(text) = std::str::from_utf8(content) {
            output.push_str(text);
        } else {
            output.push_str(&binary_preview(ContentKind::Binary, content));
        }
    }
    output
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        None
    } else {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct ProtobufField {
    field: u32,
    #[serde(flatten)]
    value: ProtobufValue,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "wire", rename_all = "snake_case")]
enum ProtobufValue {
    Varint { value: String },
    Fixed64 { value: String },
    LengthDelimited { encoding: String, value: String },
    Fixed32 { value: String },
}

fn protobuf_to_json(body: &[u8]) -> Result<String, ContentEditError> {
    let mut fields = Vec::new();
    let mut cursor = 0;
    while cursor < body.len() {
        let key = decode_varint(body, &mut cursor)?;
        let field = u32::try_from(key >> 3)
            .map_err(|_| ContentEditError::Protobuf("field number is too large".to_owned()))?;
        if field == 0 || field > 0x1fff_ffff {
            return Err(ContentEditError::Protobuf(
                "field number must be between 1 and 536870911".to_owned(),
            ));
        }
        let value = match key & 7 {
            0 => ProtobufValue::Varint {
                value: decode_varint(body, &mut cursor)?.to_string(),
            },
            1 => {
                let bytes = take(body, &mut cursor, 8)?;
                ProtobufValue::Fixed64 {
                    value: u64::from_le_bytes(bytes.try_into().expect("eight bytes")).to_string(),
                }
            }
            2 => {
                let length = usize::try_from(decode_varint(body, &mut cursor)?).map_err(|_| {
                    ContentEditError::Protobuf("length-delimited field is too large".to_owned())
                })?;
                let bytes = take(body, &mut cursor, length)?;
                match std::str::from_utf8(bytes) {
                    Ok(text) if !text.chars().any(char::is_control) => {
                        ProtobufValue::LengthDelimited {
                            encoding: "utf8".to_owned(),
                            value: text.to_owned(),
                        }
                    }
                    _ => ProtobufValue::LengthDelimited {
                        encoding: "base64".to_owned(),
                        value: base64::engine::general_purpose::STANDARD.encode(bytes),
                    },
                }
            }
            5 => {
                let bytes = take(body, &mut cursor, 4)?;
                ProtobufValue::Fixed32 {
                    value: u32::from_le_bytes(bytes.try_into().expect("four bytes")).to_string(),
                }
            }
            wire => {
                return Err(ContentEditError::Protobuf(format!(
                    "unsupported wire type {wire}; groups require a descriptor-aware editor"
                )))
            }
        };
        fields.push(ProtobufField { field, value });
    }
    Ok(serde_json::to_string_pretty(&fields)?)
}

fn protobuf_from_json(text: &str) -> Result<Vec<u8>, ContentEditError> {
    let fields: Vec<ProtobufField> = serde_json::from_str(text)?;
    let mut output = Vec::new();
    for field in fields {
        if field.field == 0 || field.field > 0x1fff_ffff {
            return Err(ContentEditError::Protobuf(
                "field number must be between 1 and 536870911".to_owned(),
            ));
        }
        let (wire, bytes) = match field.value {
            ProtobufValue::Varint { value } => {
                let value = parse_decimal::<u64>(&value, "varint")?;
                let mut bytes = Vec::new();
                encode_varint(value, &mut bytes);
                (0_u64, bytes)
            }
            ProtobufValue::Fixed64 { value } => (
                1,
                parse_decimal::<u64>(&value, "fixed64")?
                    .to_le_bytes()
                    .to_vec(),
            ),
            ProtobufValue::LengthDelimited { encoding, value } => {
                let value = match encoding.as_str() {
                    "utf8" => value.into_bytes(),
                    "base64" => base64::engine::general_purpose::STANDARD
                        .decode(value)
                        .map_err(|_| {
                            ContentEditError::Protobuf(
                                "length-delimited base64 value is invalid".to_owned(),
                            )
                        })?,
                    _ => {
                        return Err(ContentEditError::Protobuf(
                            "length-delimited encoding must be utf8 or base64".to_owned(),
                        ))
                    }
                };
                let mut bytes = Vec::new();
                encode_varint(value.len() as u64, &mut bytes);
                bytes.extend_from_slice(&value);
                (2, bytes)
            }
            ProtobufValue::Fixed32 { value } => (
                5,
                parse_decimal::<u32>(&value, "fixed32")?
                    .to_le_bytes()
                    .to_vec(),
            ),
        };
        encode_varint((u64::from(field.field) << 3) | wire, &mut output);
        output.extend_from_slice(&bytes);
    }
    Ok(output)
}

fn parse_decimal<T>(value: &str, kind: &str) -> Result<T, ContentEditError>
where
    T: std::str::FromStr,
{
    value.parse().map_err(|_| {
        ContentEditError::Protobuf(format!("{kind} value must be an unsigned decimal string"))
    })
}

fn decode_varint(body: &[u8], cursor: &mut usize) -> Result<u64, ContentEditError> {
    let mut value = 0_u64;
    for shift in (0..70).step_by(7) {
        let byte = *body
            .get(*cursor)
            .ok_or_else(|| ContentEditError::Protobuf("truncated varint field".to_owned()))?;
        *cursor += 1;
        if shift == 63 && byte > 1 {
            return Err(ContentEditError::Protobuf("varint overflow".to_owned()));
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(ContentEditError::Protobuf("varint overflow".to_owned()))
}

fn encode_varint(mut value: u64, output: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            return;
        }
    }
}

fn take<'a>(
    body: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], ContentEditError> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| ContentEditError::Protobuf("field length overflow".to_owned()))?;
    let bytes = body
        .get(*cursor..end)
        .ok_or_else(|| ContentEditError::Protobuf("truncated field value".to_owned()))?;
    *cursor = end;
    Ok(bytes)
}

fn messagepack_to_json(body: &[u8]) -> Result<String, ContentEditError> {
    let value: serde_json::Value = rmp_serde::from_slice(body)
        .map_err(|error| ContentEditError::MessagePack(error.to_string()))?;
    Ok(serde_json::to_string_pretty(&value)?)
}

fn messagepack_from_json(text: &str) -> Result<Vec<u8>, ContentEditError> {
    let value: serde_json::Value = serde_json::from_str(text)?;
    rmp_serde::to_vec_named(&value)
        .map_err(|error| ContentEditError::MessagePack(error.to_string()))
}

fn decode_text(headers: &HeaderMap, body: &[u8]) -> String {
    let charset = content_type_parameter(headers, "charset");
    if let Some(encoding) =
        charset.and_then(|label| encoding_rs::Encoding::for_label(label.as_bytes()))
    {
        let (decoded, _, _) = encoding.decode(body);
        decoded.into_owned()
    } else {
        String::from_utf8_lossy(body).into_owned()
    }
}

fn content_type_parameter<'a>(headers: &'a HeaderMap, parameter: &str) -> Option<&'a str> {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value.split(';').skip(1).find_map(|segment| {
                let (name, value) = segment.trim().split_once('=')?;
                name.eq_ignore_ascii_case(parameter)
                    .then(|| value.trim_matches(['"', '\'']))
            })
        })
}

fn binary_preview(kind: ContentKind, body: &[u8]) -> String {
    let mut output = format!("{} · {} bytes", kind.label(), body.len());
    for (offset, chunk) in body[..body.len().min(BINARY_PREVIEW_BYTES)]
        .chunks(16)
        .enumerate()
    {
        write!(output, "\n{:08x}  ", offset * 16).expect("writing to String cannot fail");
        for byte in chunk {
            write!(output, "{byte:02x} ").expect("writing to String cannot fail");
        }
        for _ in chunk.len()..16 {
            output.push_str("   ");
        }
        output.push(' ');
        for byte in chunk {
            output.push(if byte.is_ascii_graphic() || *byte == b' ' {
                char::from(*byte)
            } else {
                '.'
            });
        }
    }
    if body.len() > BINARY_PREVIEW_BYTES {
        write!(
            output,
            "\n… preview capped at {BINARY_PREVIEW_BYTES} of {} bytes",
            body.len()
        )
        .expect("writing to String cannot fail");
    }
    output
}

fn percent_decode(bytes: &[u8]) -> String {
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let decoded = hex(bytes[index + 1])
                    .and_then(|high| hex(bytes[index + 2]).map(|low| (high << 4) | low));
                if let Some(decoded) = decoded {
                    output.push(decoded);
                    index += 3;
                } else {
                    output.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

const fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn headers(content_type: &str, encoding: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, content_type.parse().unwrap());
        if let Some(encoding) = encoding {
            headers.insert(CONTENT_ENCODING, encoding.parse().unwrap());
        }
        headers
    }

    #[test]
    fn renders_json_forms_charsets_and_binary_previews() {
        let json = content_view(&headers("application/json", None), br#"{"ok":true}"#).unwrap();
        assert_eq!(json.kind, ContentKind::Json);
        assert!(json.text.contains("\n  \"ok\""));

        let form = content_view(
            &headers("application/x-www-form-urlencoded", None),
            b"name=Proxelar+User&city=Rome%20IT",
        )
        .unwrap();
        assert!(form.text.contains("name = Proxelar User"));
        assert!(form.text.contains("city = Rome IT"));

        let latin = content_view(
            &headers("text/plain; charset=windows-1252", None),
            b"caf\xe9",
        )
        .unwrap();
        assert_eq!(latin.text, "café");

        let binary =
            content_view(&headers("application/octet-stream", None), &[0, 1, 255]).unwrap();
        assert_eq!(binary.kind, ContentKind::Binary);
        assert!(binary.text.contains("00 01 ff"));
    }

    #[test]
    fn renders_markup_multipart_and_safe_raster_previews() {
        let xml = content_view(
            &headers("application/xml", None),
            b"<root><item>one</item><item>two</item></root>",
        )
        .unwrap();
        assert_eq!(xml.kind, ContentKind::Xml);
        assert!(xml.text.contains("\n  <item>\n    one\n  </item>"));

        let multipart = content_view(
            &headers("multipart/form-data; boundary=abc123", None),
            b"--abc123\r\ncontent-disposition: form-data; name=\"title\"\r\n\r\nhello\r\n--abc123--\r\n",
        )
        .unwrap();
        assert!(multipart.text.contains("Multipart body · 1 parts"));
        assert!(multipart.text.contains("name=\"title\""));
        assert!(multipart.text.ends_with("hello"));

        let image = content_view(&headers("image/png", None), b"not-a-real-png").unwrap();
        let inline = image.inline_image.unwrap();
        assert_eq!(inline.media_type, "image/png");
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(inline.base64)
                .unwrap(),
            b"not-a-real-png"
        );

        let svg = content_view(&headers("image/svg+xml", None), b"<svg></svg>").unwrap();
        assert!(svg.inline_image.is_none());
    }

    #[test]
    fn decodes_gzip_brotli_zstd_and_deflate() {
        let payload = b"compressed content";
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(payload).unwrap();
        let gzip = gzip.finish().unwrap();

        let mut brotli = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut brotli, 4096, 5, 22);
            writer.write_all(payload).unwrap();
        }
        let zstd = zstd::stream::encode_all(payload.as_slice(), 1).unwrap();
        let mut deflate =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        deflate.write_all(payload).unwrap();
        let deflate = deflate.finish().unwrap();

        for (encoding, wire) in [
            ("gzip", gzip),
            ("br", brotli),
            ("zstd", zstd),
            ("deflate", deflate),
        ] {
            assert_eq!(
                decode_body(&headers("text/plain", Some(encoding)), &wire).unwrap(),
                payload.as_slice(),
                "{encoding}"
            );
        }
    }

    #[test]
    fn rejects_unknown_encoding() {
        assert!(matches!(
            decode_body(&headers("text/plain", Some("compress")), b"data"),
            Err(ContentError::UnsupportedEncoding(_))
        ));
    }

    #[test]
    fn protobuf_editor_is_lossless_and_accepts_field_edits() {
        let wire = [
            0x08, 0x96, 0x01, 0x12, 0x02, b'h', b'i', 0x1d, 0x78, 0x56, 0x34, 0x12,
        ];
        let headers = headers("application/x-protobuf", None);
        let editor = editable_content(&headers, &wire).unwrap().unwrap();
        assert_eq!(editor.format, EditableContentFormat::Protobuf);
        assert!(editor.text.contains("\"field\": 1"));
        assert!(editor.text.contains("\"value\": \"150\""));
        assert_eq!(
            encode_edit("protobuf", &editor.text).unwrap().as_ref(),
            wire
        );

        let edited = editor.text.replacen("\"150\"", "\"151\"", 1);
        let edited = encode_edit("protobuf", &edited).unwrap();
        assert_eq!(&edited[..3], &[0x08, 0x97, 0x01]);
    }

    #[test]
    fn messagepack_editor_roundtrips_json_values() {
        let value = serde_json::json!({"enabled": true, "count": 3, "items": ["a", "b"]});
        let wire = rmp_serde::to_vec_named(&value).unwrap();
        let headers = headers("application/msgpack", None);
        let editor = editable_content(&headers, &wire).unwrap().unwrap();
        assert_eq!(editor.format, EditableContentFormat::MessagePack);
        assert!(editor.text.contains("\"enabled\": true"));
        let roundtrip = encode_edit("messagepack", &editor.text).unwrap();
        let decoded: serde_json::Value = rmp_serde::from_slice(&roundtrip).unwrap();
        assert_eq!(decoded, value);
        assert!(content_view(&headers, &wire)
            .unwrap()
            .text
            .contains("\"items\""));
    }

    #[test]
    fn covers_content_labels_and_preview_edge_cases() {
        for (kind, label) in [
            (ContentKind::Json, "JSON"),
            (ContentKind::Xml, "XML"),
            (ContentKind::Html, "HTML"),
            (ContentKind::Css, "CSS"),
            (ContentKind::JavaScript, "JavaScript"),
            (ContentKind::Form, "Form"),
            (ContentKind::Multipart, "Multipart"),
            (ContentKind::Image, "Image"),
            (ContentKind::Protobuf, "Protobuf"),
            (ContentKind::MessagePack, "MessagePack"),
            (ContentKind::Text, "Text"),
            (ContentKind::Binary, "Binary"),
        ] {
            assert_eq!(kind.label(), label);
        }
        assert_eq!(EditableContentFormat::Protobuf.as_str(), "protobuf");
        assert_eq!(EditableContentFormat::MessagePack.as_str(), "messagepack");

        assert!(pretty_markup("<root><unfinished").contains("<unfinished"));
        assert!(!markup_opens_scope("<br>"));
        assert!(!markup_opens_scope("<meta charset=\"utf-8\">"));
        assert!(!markup_opens_scope("<!-- comment -->"));
        assert!(markup_opens_scope("<section>"));

        let missing = render_multipart(&headers("multipart/form-data", None), b"body");
        assert!(missing.contains("boundary missing"));
        let invalid = render_multipart(
            &headers("multipart/form-data; boundary=\"\"", None),
            b"body",
        );
        assert!(invalid.contains("invalid boundary"));
        assert_eq!(find_bytes(b"abc", b""), None);

        let preview = binary_preview(ContentKind::Binary, &vec![0xff; BINARY_PREVIEW_BYTES + 1]);
        assert!(preview.contains("preview capped"));
        assert_eq!(percent_decode(b"a%2Fb+%zz"), "a/b %zz");
        assert_eq!(hex(b'0'), Some(0));
        assert_eq!(hex(b'a'), Some(10));
        assert_eq!(hex(b'F'), Some(15));
        assert_eq!(hex(b'z'), None);
    }
}
