use bytes::Bytes;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use proxyapi::{InterceptConfig, InterceptDecision};
use std::sync::Arc;

use super::state::{AppState, EditAction, EditSession};

/// Handle a key event. Returns true if the app should quit.
pub fn handle_key_event(
    key: KeyEvent,
    state: &mut AppState,
    intercept: &Arc<InterceptConfig>,
) -> bool {
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

    match key.code {
        KeyCode::Char('q' | 'Q') => return true,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
        KeyCode::Char('j') | KeyCode::Down => state.select_next(),
        KeyCode::Char('k') | KeyCode::Up => state.select_prev(),
        KeyCode::Char('g') => state.select_first(),
        KeyCode::Char('G') => state.select_last(),
        KeyCode::Enter => state.toggle_detail(),
        KeyCode::Tab => state.toggle_tab(),
        KeyCode::Char('/') => {
            state.filter_mode = true;
            state.filter_input.clear();
        }
        KeyCode::Esc => {
            if state.detail_open {
                state.detail_open = false;
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
                        intercept.resolve(id, InterceptDecision::Modified { method, uri, headers, body });
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
