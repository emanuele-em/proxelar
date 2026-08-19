use bytes::Bytes;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use proxyapi::{InterceptConfig, InterceptDecision};
use proxyapi_models::{HeaderBlock, ProxiedRequest};
use std::sync::Arc;
use tokio::sync::mpsc;

use super::state::{AppState, EditAction, EditSession};

/// Handle a key event. Returns true if the app should quit.
pub fn handle_key_event(
    key: KeyEvent,
    state: &mut AppState,
    intercept: &Arc<InterceptConfig>,
    replay_tx: &mpsc::Sender<ProxiedRequest>,
) -> bool {
    // Help overlay: consume all keys; ? or Esc closes it.
    if state.show_help {
        if matches!(key.code, KeyCode::Char('?') | KeyCode::Esc) {
            state.show_help = false;
        }
        return false;
    }

    // Inline editor: intercept ALL keys only while actively typing.
    if let Some(ref mut session) = state.edit_session {
        if session.typing {
            match session.handle_key(key) {
                EditAction::None => {}
                EditAction::StageEdits => {
                    session.typing = false;
                }
                EditAction::Discard => {
                    state.edit_session = None;
                }
            }
            return false;
        }
        // Review mode: only Esc is handled here; f/d/e fall through below.
        if key.code == KeyCode::Esc {
            state.edit_session = None;
            return false;
        }
    }

    // Filter mode: capture text input.
    if state.filter_mode {
        match key.code {
            KeyCode::Esc => {
                state.filter_mode = false;
                state.filter_input.clear();
                state.filter = None;
            }
            KeyCode::Enter => {
                state.filter_mode = false;
                if state.filter_input.is_empty() {
                    state.filter = None;
                } else {
                    state.filter = Some(state.filter_input.clone());
                }
            }
            KeyCode::Backspace => {
                state.filter_input.pop();
            }
            KeyCode::Char(c) => {
                state.filter_input.push(c);
            }
            _ => {}
        }
        return false;
    }

    // Detail panel focus: j/k scroll content, Tab switches tab, Enter/Esc return to table.
    if state.detail_focused {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                state.frames_follow = false;
                state.detail_scroll = state.detail_scroll.saturating_add(1);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                state.frames_follow = false;
                state.detail_scroll = state.detail_scroll.saturating_sub(1);
            }
            KeyCode::Tab => state.toggle_tab(),
            KeyCode::Enter | KeyCode::Esc => {
                state.detail_focused = false;
            }
            KeyCode::Char('q' | 'Q') => return true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
            _ => {}
        }
        return false;
    }

    match key.code {
        KeyCode::Char('q' | 'Q') => return true,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
        KeyCode::Char('j') | KeyCode::Down => state.select_next(),
        KeyCode::Char('k') | KeyCode::Up => state.select_prev(),
        KeyCode::Char('g') => state.select_first(),
        KeyCode::Char('G') => state.select_last(),
        KeyCode::Enter => {
            if state.detail_open {
                // Second Enter focuses the detail panel for scrolling.
                state.detail_focused = true;
            } else {
                state.detail_open = true;
            }
        }
        KeyCode::Tab => state.toggle_tab(),
        KeyCode::Char('/') => {
            state.filter_mode = true;
            state.filter_input.clear();
        }
        KeyCode::Esc => {
            if state.detail_open {
                state.detail_open = false;
                state.detail_focused = false;
            } else {
                state.filter = None;
            }
        }
        KeyCode::Char('c') => state.clear(),

        // Intercept controls
        KeyCode::Char('i') => {
            state.intercept_enabled = intercept.toggle();
        }
        KeyCode::Char('f') => {
            if let Some(ref session) = state.edit_session {
                // Try to parse first; only clear the session on success.
                let id = session.id;
                let text = session.to_text();
                match parse_edited_http_request(&text, session.binary_body) {
                    Ok((method, uri, headers, body)) => {
                        state.edit_session = None;
                        intercept.resolve(
                            id,
                            InterceptDecision::Modified {
                                method,
                                uri,
                                headers,
                                body,
                            },
                        );
                    }
                    Err(_) => {
                        // Keep the session open so the user can fix the text.
                        let s = state.edit_session.as_mut().unwrap();
                        s.parse_error = true;
                        s.typing = true;
                    }
                }
            } else if let Some(id) = state.selected_pending_id() {
                intercept.resolve(id, InterceptDecision::Forward);
            }
        }
        KeyCode::Char('d') => {
            // Discard any staged edits and drop the request.
            let id = state
                .edit_session
                .take()
                .map(|s| s.id)
                .or_else(|| state.selected_pending_id());
            if let Some(id) = id {
                intercept.resolve(
                    id,
                    InterceptDecision::Block {
                        status: 504,
                        body: Bytes::from_static(b"Blocked by Proxelar intercept"),
                    },
                );
                state.remove_pending_by_id(id);
            }
        }
        KeyCode::Char('e') => {
            // If a staged session already exists for this row, re-enter typing.
            if let Some(ref mut session) = state.edit_session {
                session.typing = true;
                session.parse_error = false;
                state.detail_open = true;
            } else if let Some((id, req)) = state.selected_pending_request() {
                let (text, binary_body) = request_to_text(req);
                let mut session = EditSession::new(id, &text);
                session.binary_body = binary_body;
                state.edit_session = Some(session);
                state.detail_open = true;
            }
        }

        KeyCode::Char('?') => state.show_help = true,

        KeyCode::Char('r') => {
            if let Some(req) = state.selected_request() {
                if replay_tx.try_send(req.clone()).is_err() {
                    tracing::warn!("Replay channel full, dropping request");
                }
            }
        }

        _ => {}
    }

    false
}

/// Serialise a `ProxiedRequest` as raw HTTP text for inline editing.
///
/// Returns `(text, binary_body)` where Protobuf/MessagePack bodies use a
/// structured JSON marker and other invalid UTF-8 bodies use hexadecimal.
fn request_to_text(req: &proxyapi_models::ProxiedRequest) -> (String, bool) {
    let mut text = format!("{} {} {:?}\n", req.method(), req.uri(), req.version());
    for field in req.headers() {
        text.push_str(std::str::from_utf8(field.name()).expect("header names are ASCII"));
        text.push_str(": ");
        text.push_str(&escape_header_value(field.value()));
        text.push('\n');
    }
    text.push('\n');
    let structured = proxyapi::content::editable_content(req.headers(), req.body())
        .ok()
        .flatten();
    let binary_body = structured.is_some()
        || (!req.body().is_empty() && std::str::from_utf8(req.body()).is_err());
    if !req.body().is_empty() {
        if let Some(editor) = structured {
            text.push_str("@proxelar:");
            text.push_str(editor.format.as_str());
            text.push('\n');
            text.push_str(&editor.text);
        } else if binary_body {
            text.push_str("@proxelar:hex\n");
            for (index, byte) in req.body().iter().enumerate() {
                if index > 0 {
                    text.push(if index % 16 == 0 { '\n' } else { ' ' });
                }
                text.push_str(&format!("{byte:02x}"));
            }
        } else {
            text.push_str(&String::from_utf8_lossy(req.body()));
        }
    }
    (text, binary_body)
}

fn escape_header_value(value: &[u8]) -> String {
    let mut escaped = String::with_capacity(value.len());
    for byte in value {
        match byte {
            b'\\' => escaped.push_str("\\\\"),
            b'\t' => escaped.push_str("\\t"),
            0x20..=0x7e => escaped.push(char::from(*byte)),
            _ => escaped.push_str(&format!("\\x{byte:02x}")),
        }
    }
    escaped
}

fn unescape_header_value(value: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if value[index] != b'\\' {
            decoded.push(value[index]);
            index += 1;
            continue;
        }
        match value.get(index + 1) {
            Some(b'\\') => {
                decoded.push(b'\\');
                index += 2;
            }
            Some(b't') => {
                decoded.push(b'\t');
                index += 2;
            }
            Some(b'x') if index + 3 < value.len() => {
                let digits = std::str::from_utf8(&value[index + 2..index + 4])
                    .map_err(|_| "Invalid header byte escape")?;
                decoded.push(
                    u8::from_str_radix(digits, 16).map_err(|_| "Invalid header byte escape")?,
                );
                index += 4;
            }
            _ => return Err("Header backslashes must use \\\\, \\t, or \\xNN".to_owned()),
        }
    }
    Ok(decoded)
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

/// Parse a raw HTTP request text into (method, uri, headers, body).
///
/// Both `\r\n` and `\n` line endings are accepted.
fn parse_raw_http_request(text: &str) -> Result<(String, String, HeaderBlock, Bytes), String> {
    let normalised = text.replace("\r\n", "\n");
    let mut parts = normalised.splitn(2, "\n\n");

    let header_section = parts.next().unwrap_or("");
    let body_str = parts.next().unwrap_or("");

    let mut header_lines = header_section.lines();

    let request_line = header_lines
        .next()
        .ok_or("Missing request line")?
        .trim_end();
    let mut fields = request_line.split_whitespace();
    let method = fields.next().ok_or("Missing method")?.trim().to_uppercase();
    let uri = fields.next().ok_or("Missing URI")?.trim().to_string();
    let version = fields.next().ok_or("Missing HTTP version")?;
    if fields.next().is_some()
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1" | "HTTP/2.0" | "HTTP/3.0")
    {
        return Err("Request line has an unsupported HTTP version".to_owned());
    }
    method
        .parse::<http::Method>()
        .map_err(|error| format!("Invalid method: {error}"))?;
    uri.parse::<http::Uri>()
        .map_err(|error| format!("Invalid URI: {error}"))?;

    let mut headers = HeaderBlock::new();
    for line in header_lines {
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| format!("Invalid header line: {line}"))?;
        let value = unescape_header_value(trim_ows(value.as_bytes()))?;
        headers
            .add(name.trim(), value)
            .map_err(|error| format!("Invalid header: {error}"))?;
    }

    let body = Bytes::copy_from_slice(body_str.as_bytes());
    Ok((method, uri, headers, body))
}

fn parse_edited_http_request(
    text: &str,
    binary_body: bool,
) -> Result<(String, String, HeaderBlock, Bytes), String> {
    let (method, uri, headers, body) = parse_raw_http_request(text)?;
    if !binary_body {
        return Ok((method, uri, headers, body));
    }
    let body = std::str::from_utf8(&body).map_err(|_| "Hex editor body is not UTF-8")?;
    if let Some(document) = body.strip_prefix("@proxelar:protobuf\n") {
        return proxyapi::content::encode_edit("protobuf", document)
            .map(|body| (method, uri, headers, body))
            .map_err(|error| error.to_string());
    }
    if let Some(document) = body.strip_prefix("@proxelar:messagepack\n") {
        return proxyapi::content::encode_edit("messagepack", document)
            .map(|body| (method, uri, headers, body))
            .map_err(|error| error.to_string());
    }
    let hex = body
        .strip_prefix("@proxelar:hex\n")
        .ok_or("Binary body must keep a supported @proxelar marker")?;
    let compact = hex
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    if compact.len() % 2 != 0 {
        return Err("Hex body must contain pairs of digits".to_owned());
    }
    let decoded = compact
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).map_err(|_| "Invalid hex body")?;
            u8::from_str_radix(pair, 16).map_err(|_| "Invalid hex body")
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((method, uri, headers, Bytes::from(decoded)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;
    use http::{Method, Version};
    use proxyapi::ProxyEvent;
    use proxyapi_models::{HeaderBlock, ProxiedRequest, ProxiedResponse};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn request(body: Bytes) -> ProxiedRequest {
        let mut headers = HeaderBlock::new();
        headers.add("x-test", "one").unwrap();
        headers.add("x-test", "two").unwrap();
        ProxiedRequest::new(
            Method::POST,
            "http://api.test/path?x=1".parse().unwrap(),
            Version::HTTP_11,
            headers,
            body,
            100,
        )
    }

    #[test]
    fn parse_raw_http_request_accepts_crlf_and_repeated_headers() {
        let (method, uri, headers, body) = parse_raw_http_request(
            "patch http://api.test/items HTTP/1.1\r\n\
             x-test: one\r\n\
             x-test: two\r\n\
             \r\n\
             body",
        )
        .unwrap();

        assert_eq!(method, "PATCH");
        assert_eq!(uri, "http://api.test/items");
        assert_eq!(headers.get_all("x-test").count(), 2);
        assert_eq!(body.as_ref(), b"body");
    }

    #[test]
    fn parse_raw_http_request_accepts_captured_http2_and_http3_versions() {
        for version in ["HTTP/2.0", "HTTP/3.0"] {
            let text = format!("GET https://api.test/ {version}\n\nx");
            let (_, _, _, body) = parse_raw_http_request(&text).unwrap();
            assert_eq!(body.as_ref(), b"x");
        }
    }

    #[test]
    fn parse_raw_http_request_rejects_malformed_request_lines_and_headers() {
        for text in [
            "GET /missing-version\n\n",
            "GET %%% HTTP/1.1\n\n",
            "GET / HTTP/9.0\n\n",
            "GET / HTTP/1.1\ninvalid header\n\n",
        ] {
            assert!(
                parse_raw_http_request(text).is_err(),
                "should reject {text:?}"
            );
        }
    }

    #[test]
    fn request_to_text_preserves_headers_and_marks_binary_body() {
        let (text, binary_body) = request_to_text(&request(Bytes::from_static(b"\xff\x00")));

        assert!(text.starts_with("POST http://api.test/path?x=1 HTTP/1.1\n"));
        assert!(text.contains("x-test: one\n"));
        assert!(text.contains("x-test: two\n"));
        assert!(text.ends_with("@proxelar:hex\nff 00"));
        assert!(binary_body);
        let (_, _, _, body) = parse_edited_http_request(&text, binary_body).unwrap();
        assert_eq!(body.as_ref(), b"\xff\x00");
    }

    #[test]
    fn request_to_text_roundtrips_binary_headers_and_http2() {
        let mut headers = HeaderBlock::new();
        headers
            .add("x-binary", [0xff, b'\\', b'x', b'4', b'1', b'\t'])
            .unwrap();
        let request = ProxiedRequest::new(
            Method::GET,
            "https://api.test/".parse().unwrap(),
            Version::HTTP_2,
            headers,
            Bytes::new(),
            100,
        );

        let (text, binary_body) = request_to_text(&request);
        assert!(text.starts_with("GET https://api.test/ HTTP/2.0\n"));
        assert!(text.contains("x-binary: \\xff\\\\x41\\t\n"));
        let (_, _, headers, _) = parse_edited_http_request(&text, binary_body).unwrap();
        assert_eq!(
            headers.get("x-binary"),
            Some([0xff, b'\\', b'x', b'4', b'1', b'\t'].as_slice())
        );
    }

    #[test]
    fn request_to_text_roundtrips_structured_protobuf_fields() {
        let mut headers = HeaderBlock::new();
        headers
            .add("content-type", "application/x-protobuf")
            .unwrap();
        let request = ProxiedRequest::new(
            Method::POST,
            "http://api.test/protobuf".parse().unwrap(),
            Version::HTTP_11,
            headers,
            Bytes::from_static(&[0x08, 0x96, 0x01]),
            100,
        );
        let (text, structured) = request_to_text(&request);
        assert!(structured);
        assert!(text.contains("@proxelar:protobuf\n"));
        assert!(text.contains("\"value\": \"150\""));
        let edited = text.replacen("\"150\"", "\"151\"", 1);
        let (_, _, _, body) = parse_edited_http_request(&edited, true).unwrap();
        assert_eq!(body.as_ref(), &[0x08, 0x97, 0x01]);
    }

    #[test]
    fn handle_key_event_filter_mode_sets_and_clears_filter() {
        let intercept = InterceptConfig::new();
        let (replay_tx, _replay_rx) = mpsc::channel(1);
        let mut state = AppState::new();

        assert!(!handle_key_event(
            key(KeyCode::Char('/')),
            &mut state,
            &intercept,
            &replay_tx
        ));
        assert!(state.filter_mode);

        handle_key_event(key(KeyCode::Char('g')), &mut state, &intercept, &replay_tx);
        handle_key_event(key(KeyCode::Char('e')), &mut state, &intercept, &replay_tx);
        handle_key_event(key(KeyCode::Enter), &mut state, &intercept, &replay_tx);

        assert!(!state.filter_mode);
        assert_eq!(state.filter.as_deref(), Some("ge"));

        handle_key_event(key(KeyCode::Esc), &mut state, &intercept, &replay_tx);
        assert_eq!(state.filter, None);
    }

    #[test]
    fn handle_key_event_replays_selected_request() {
        let intercept = InterceptConfig::new();
        let (replay_tx, mut replay_rx) = mpsc::channel(1);
        let mut state = AppState::new();
        state.add_event(ProxyEvent::RequestComplete {
            id: 1,
            request: Box::new(request(Bytes::from_static(b"body"))),
            response: Box::new(ProxiedResponse::new(
                http::StatusCode::OK,
                Version::HTTP_11,
                HeaderBlock::new(),
                Bytes::new(),
                200,
            )),
        });
        state.select_first();

        handle_key_event(key(KeyCode::Char('r')), &mut state, &intercept, &replay_tx);

        let replayed = replay_rx.try_recv().unwrap();
        assert_eq!(replayed.uri().path(), "/path");
        assert_eq!(replayed.body().as_ref(), b"body");
    }
}
