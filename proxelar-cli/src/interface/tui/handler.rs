use bytes::Bytes;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use proxyapi::{InterceptConfig, InterceptDecision};
use proxyapi_models::ProxiedRequest;
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
                match parse_raw_http_request(&text) {
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
/// Returns `(text, binary_body)` where `binary_body` is true when the body
/// is not valid UTF-8 (the text will contain the lossy representation).
fn request_to_text(req: &proxyapi_models::ProxiedRequest) -> (String, bool) {
    let mut text = format!("{} {} {:?}\n", req.method(), req.uri(), req.version());
    for (name, value) in req.headers() {
        text.push_str(&format!(
            "{}: {}\n",
            name,
            String::from_utf8_lossy(value.as_bytes())
        ));
    }
    text.push('\n');
    let binary_body = !req.body().is_empty() && std::str::from_utf8(req.body()).is_err();
    if !req.body().is_empty() {
        text.push_str(&String::from_utf8_lossy(req.body()));
    }
    (text, binary_body)
}

/// Parse a raw HTTP request text into (method, uri, headers, body).
///
/// Both `\r\n` and `\n` line endings are accepted.
fn parse_raw_http_request(text: &str) -> Result<(String, String, http::HeaderMap, Bytes), String> {
    let normalised = text.replace("\r\n", "\n");
    let mut parts = normalised.splitn(2, "\n\n");

    let header_section = parts.next().unwrap_or("");
    let body_str = parts.next().unwrap_or("");

    let mut header_lines = header_section.lines();

    let request_line = header_lines
        .next()
        .ok_or("Missing request line")?
        .trim_end();
    let mut fields = request_line.splitn(3, ' ');
    let method = fields.next().ok_or("Missing method")?.trim().to_uppercase();
    let uri = fields.next().ok_or("Missing URI")?.trim().to_string();

    let mut headers = http::HeaderMap::new();
    for line in header_lines {
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            if let (Ok(n), Ok(v)) = (
                http::header::HeaderName::from_bytes(name.as_bytes()),
                http::header::HeaderValue::from_str(value),
            ) {
                headers.append(n, v);
            }
        }
    }

    let body = Bytes::copy_from_slice(body_str.as_bytes());
    Ok((method, uri, headers, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;
    use http::{HeaderMap, Method, Version};
    use proxyapi::ProxyEvent;
    use proxyapi_models::{ProxiedRequest, ProxiedResponse};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn request(body: Bytes) -> ProxiedRequest {
        let mut headers = HeaderMap::new();
        headers.append("x-test", "one".parse().unwrap());
        headers.append("x-test", "two".parse().unwrap());
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
        assert_eq!(headers.get_all("x-test").iter().count(), 2);
        assert_eq!(body.as_ref(), b"body");
    }

    #[test]
    fn request_to_text_preserves_headers_and_marks_binary_body() {
        let (text, binary_body) = request_to_text(&request(Bytes::from_static(b"\xff\x00")));

        assert!(text.starts_with("POST http://api.test/path?x=1 HTTP/1.1\n"));
        assert!(text.contains("x-test: one\n"));
        assert!(text.contains("x-test: two\n"));
        assert!(binary_body);
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
                HeaderMap::new(),
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
