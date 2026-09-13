use std::collections::VecDeque;

use crossterm::event::{KeyCode, KeyEvent};
use proxyapi::{FlowFilter, ProxyEvent};
use proxyapi_models::{
    CapturedDnsExchange, CapturedTcpStream, CapturedUdpExchange, ProxiedRequest, ProxiedResponse,
    WsFrame,
};
use ratatui::widgets::TableState;

const MAX_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailTab {
    Request,
    Response,
}

/// An entry starts as `Pending` when intercept mode is active, then is
/// promoted to `Complete` in-place once the request has been forwarded
/// and a response received.
pub enum FlowEntry {
    Complete {
        request: Box<ProxiedRequest>,
        response: Box<ProxiedResponse>,
    },
    Pending {
        id: u64,
        request: Box<ProxiedRequest>,
    },
    Error {
        message: String,
    },
    WebSocket {
        id: u64,
        request: Box<ProxiedRequest>,
        _response: Box<ProxiedResponse>,
        frames: VecDeque<WsFrame>,
        closed: bool,
    },
    Tcp {
        stream: CapturedTcpStream,
    },
    Dns {
        exchange: CapturedDnsExchange,
    },
    Udp {
        exchange: CapturedUdpExchange,
    },
}

impl FlowEntry {
    pub fn is_pending(&self) -> bool {
        matches!(self, FlowEntry::Pending { .. })
    }
}

pub enum EditAction {
    None,
    StageEdits,
    Discard,
}

pub struct EditSession {
    pub id: u64,
    pub lines: Vec<String>,
    pub cursor_row: usize,
    pub cursor_col: usize,
    pub scroll: usize,
    pub typing: bool,
    pub parse_error: bool,
    pub binary_body: bool,
}

impl EditSession {
    pub fn new(id: u64, text: &str) -> Self {
        let lines: Vec<String> = text.lines().map(|l| l.to_owned()).collect();
        let lines = if lines.is_empty() {
            vec![String::new()]
        } else {
            lines
        };
        EditSession {
            id,
            lines,
            cursor_row: 0,
            cursor_col: 0,
            scroll: 0,
            typing: true,
            parse_error: false,
            binary_body: false,
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> EditAction {
        if !self.typing {
            // In review mode only Esc is handled here; f/d are handled by the
            // main key handler which checks edit_session directly.
            if key.code == KeyCode::Esc {
                return EditAction::Discard;
            }
            return EditAction::None;
        }

        match key.code {
            KeyCode::Esc => return EditAction::StageEdits,
            KeyCode::Char(c) => self.insert_char(c),
            KeyCode::Enter => self.insert_newline(),
            KeyCode::Backspace => self.backspace(),
            KeyCode::Delete => self.delete_fwd(),
            KeyCode::Left => self.move_left(),
            KeyCode::Right => self.move_right(),
            KeyCode::Up => self.move_up(),
            KeyCode::Down => self.move_down(),
            KeyCode::Home => self.cursor_col = 0,
            KeyCode::End => self.cursor_col = self.current_line_len(),
            _ => {}
        }
        EditAction::None
    }

    pub fn to_text(&self) -> String {
        self.lines.join("\n")
    }

    pub fn scroll_into_view(&mut self, height: usize) {
        if height == 0 {
            return;
        }
        if self.cursor_row < self.scroll {
            self.scroll = self.cursor_row;
        } else if self.cursor_row >= self.scroll + height {
            self.scroll = self.cursor_row - height + 1;
        }
    }

    fn current_line_len(&self) -> usize {
        self.lines
            .get(self.cursor_row)
            .map(|l| l.chars().count())
            .unwrap_or(0)
    }

    fn clamp_col(&mut self) {
        let max = self.current_line_len();
        if self.cursor_col > max {
            self.cursor_col = max;
        }
    }

    fn insert_char(&mut self, c: char) {
        let line = &mut self.lines[self.cursor_row];
        let byte_idx = line
            .char_indices()
            .nth(self.cursor_col)
            .map(|(i, _)| i)
            .unwrap_or(line.len());
        line.insert(byte_idx, c);
        self.cursor_col += 1;
    }

    fn insert_newline(&mut self) {
        let line = &mut self.lines[self.cursor_row];
        let byte_idx = line
            .char_indices()
            .nth(self.cursor_col)
            .map(|(i, _)| i)
            .unwrap_or(line.len());
        let rest = line[byte_idx..].to_owned();
        line.truncate(byte_idx);
        self.lines.insert(self.cursor_row + 1, rest);
        self.cursor_row += 1;
        self.cursor_col = 0;
    }

    fn backspace(&mut self) {
        if self.cursor_col > 0 {
            let line = &mut self.lines[self.cursor_row];
            let byte_idx = line
                .char_indices()
                .nth(self.cursor_col - 1)
                .map(|(i, _)| i)
                .unwrap();
            let end = line
                .char_indices()
                .nth(self.cursor_col)
                .map(|(i, _)| i)
                .unwrap_or(line.len());
            line.drain(byte_idx..end);
            self.cursor_col -= 1;
        } else if self.cursor_row > 0 {
            let line = self.lines.remove(self.cursor_row);
            self.cursor_row -= 1;
            self.cursor_col = self.current_line_len();
            self.lines[self.cursor_row].push_str(&line);
        }
    }

    fn delete_fwd(&mut self) {
        let len = self.current_line_len();
        if self.cursor_col < len {
            let line = &mut self.lines[self.cursor_row];
            let start = line
                .char_indices()
                .nth(self.cursor_col)
                .map(|(i, _)| i)
                .unwrap();
            let end = line
                .char_indices()
                .nth(self.cursor_col + 1)
                .map(|(i, _)| i)
                .unwrap_or(line.len());
            line.drain(start..end);
        } else if self.cursor_row + 1 < self.lines.len() {
            let next = self.lines.remove(self.cursor_row + 1);
            self.lines[self.cursor_row].push_str(&next);
        }
    }

    fn move_left(&mut self) {
        if self.cursor_col > 0 {
            self.cursor_col -= 1;
        } else if self.cursor_row > 0 {
            self.cursor_row -= 1;
            self.cursor_col = self.current_line_len();
        }
    }

    fn move_right(&mut self) {
        if self.cursor_col < self.current_line_len() {
            self.cursor_col += 1;
        } else if self.cursor_row + 1 < self.lines.len() {
            self.cursor_row += 1;
            self.cursor_col = 0;
        }
    }

    fn move_up(&mut self) {
        if self.cursor_row > 0 {
            self.cursor_row -= 1;
            self.clamp_col();
        }
    }

    fn move_down(&mut self) {
        if self.cursor_row + 1 < self.lines.len() {
            self.cursor_row += 1;
            self.clamp_col();
        }
    }
}

pub struct AppState {
    pub(crate) entries: VecDeque<FlowEntry>,
    pub table_state: TableState,
    pub detail_open: bool,
    pub detail_focused: bool,
    pub detail_tab: DetailTab,
    pub filter: Option<String>,
    pub filter_input: String,
    pub filter_mode: bool,
    /// Mirrors `InterceptConfig::is_enabled()` for rendering without locking.
    pub intercept_enabled: bool,
    pub edit_session: Option<EditSession>,
    pub show_help: bool,
    pub detail_scroll: usize,
    /// When true, `detail_scroll` auto-tracks the latest WS frame (tail -f behaviour).
    pub frames_follow: bool,
}

pub(crate) fn matches_filter(entry: &FlowEntry, filter: Option<&str>) -> bool {
    let Some(filter) = filter else {
        return true;
    };
    let raw_filter = filter.to_ascii_lowercase();
    let Ok(filter) = FlowFilter::parse(filter) else {
        return false;
    };

    match entry {
        FlowEntry::Complete {
            request, response, ..
        } => filter.matches(request, Some(response), false),
        FlowEntry::Pending { request, .. } => filter.matches(request, None, false),
        FlowEntry::Error { message } => message.to_ascii_lowercase().contains(&raw_filter),
        FlowEntry::WebSocket {
            request,
            _response: ws_response,
            frames,
            closed,
            ..
        } => {
            let frames = frames.iter().cloned().collect::<Vec<_>>();
            filter.matches_websocket(request, ws_response, &frames, *closed)
        }
        FlowEntry::Tcp { stream } => filter.matches_tcp(stream),
        FlowEntry::Dns { exchange } => filter.matches_dns(exchange),
        FlowEntry::Udp { exchange } => filter.matches_udp(exchange),
    }
}

impl AppState {
    pub fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            table_state: TableState::default(),
            detail_open: false,
            detail_focused: false,
            detail_tab: DetailTab::Request,
            filter: None,
            filter_input: String::new(),
            filter_mode: false,
            intercept_enabled: false,
            edit_session: None,
            show_help: false,
            detail_scroll: 0,
            frames_follow: true,
        }
    }

    pub fn add_event(&mut self, event: ProxyEvent) {
        match event {
            ProxyEvent::RequestIntercepted { id, request } => {
                self.entries.push_back(FlowEntry::Pending { id, request });
            }
            ProxyEvent::RequestComplete {
                id,
                request,
                response,
            } => {
                // Promote Pending → Complete in-place so the row doesn't jump.
                if let Some(entry) = self
                    .entries
                    .iter_mut()
                    .find(|e| matches!(e, FlowEntry::Pending { id: eid, .. } if *eid == id))
                {
                    *entry = FlowEntry::Complete { request, response };
                } else {
                    self.entries
                        .push_back(FlowEntry::Complete { request, response });
                }
            }
            ProxyEvent::Error { message } => {
                self.entries.push_back(FlowEntry::Error { message });
            }
            ProxyEvent::WebSocketConnected {
                id,
                request,
                response,
            } => {
                self.entries.push_back(FlowEntry::WebSocket {
                    id,
                    request,
                    _response: response,
                    frames: VecDeque::new(),
                    closed: false,
                });
            }
            ProxyEvent::WebSocketFrame { conn_id, frame } => {
                const MAX_FRAMES: usize = 10_000;
                if let Some(FlowEntry::WebSocket { frames, .. }) = self
                    .entries
                    .iter_mut()
                    .find(|e| matches!(e, FlowEntry::WebSocket { id, .. } if *id == conn_id))
                {
                    frames.push_back(*frame);
                    if frames.len() > MAX_FRAMES {
                        frames.pop_front();
                    }
                }
            }
            ProxyEvent::WebSocketClosed { conn_id } => {
                if let Some(FlowEntry::WebSocket { closed, .. }) = self
                    .entries
                    .iter_mut()
                    .find(|e| matches!(e, FlowEntry::WebSocket { id, .. } if *id == conn_id))
                {
                    *closed = true;
                }
            }
            ProxyEvent::TcpConnected {
                id,
                target,
                opened_at,
            } => {
                self.entries.push_back(FlowEntry::Tcp {
                    stream: CapturedTcpStream {
                        id,
                        target,
                        opened_at,
                        chunks: Vec::new(),
                        closed: false,
                    },
                });
            }
            ProxyEvent::TcpData { stream_id, chunk } => {
                const MAX_CHUNKS: usize = 10_000;
                if let Some(FlowEntry::Tcp { stream }) = self.entries.iter_mut().find(
                    |entry| matches!(entry, FlowEntry::Tcp { stream } if stream.id == stream_id),
                ) {
                    if stream.chunks.len() < MAX_CHUNKS {
                        stream.chunks.push(*chunk);
                    }
                }
            }
            ProxyEvent::TcpClosed { stream_id } => {
                if let Some(FlowEntry::Tcp { stream }) = self.entries.iter_mut().find(
                    |entry| matches!(entry, FlowEntry::Tcp { stream } if stream.id == stream_id),
                ) {
                    stream.closed = true;
                }
            }
            ProxyEvent::DnsQuery {
                id,
                name,
                query_type,
                time,
            } => {
                self.entries.push_back(FlowEntry::Dns {
                    exchange: CapturedDnsExchange {
                        id,
                        name,
                        query_type,
                        time,
                        answers: Vec::new(),
                        overridden: false,
                        completed: false,
                    },
                });
            }
            ProxyEvent::DnsResponse {
                id,
                answers,
                overridden,
            } => {
                if let Some(FlowEntry::Dns { exchange }) = self
                    .entries
                    .iter_mut()
                    .find(|entry| matches!(entry, FlowEntry::Dns { exchange } if exchange.id == id))
                {
                    exchange.answers = answers;
                    exchange.overridden = overridden;
                    exchange.completed = true;
                }
            }
            ProxyEvent::UdpExchange { exchange } => {
                self.entries.push_back(FlowEntry::Udp {
                    exchange: *exchange,
                });
            }
        }

        if self.entries.len() > MAX_ENTRIES {
            self.entries.pop_front();
            if let Some(idx) = self.table_state.selected() {
                self.table_state.select(Some(idx.saturating_sub(1)));
            }
        }
    }

    fn filtered_count(&self) -> usize {
        let filter = self.filter.as_deref();
        self.entries
            .iter()
            .filter(|e| matches_filter(e, filter))
            .count()
    }

    pub fn pending_count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_pending()).count()
    }

    pub fn selected_pending_id(&self) -> Option<u64> {
        let filter = self.filter.as_deref();
        let filtered: Vec<&FlowEntry> = self
            .entries
            .iter()
            .filter(|e| matches_filter(e, filter))
            .collect();
        let idx = self.table_state.selected()?;
        match filtered.get(idx) {
            Some(FlowEntry::Pending { id, .. }) => Some(*id),
            _ => None,
        }
    }

    pub fn selected_request(&self) -> Option<&ProxiedRequest> {
        let filter = self.filter.as_deref();
        let filtered: Vec<&FlowEntry> = self
            .entries
            .iter()
            .filter(|e| matches_filter(e, filter))
            .collect();
        let idx = self.table_state.selected()?;
        match filtered.get(idx) {
            Some(FlowEntry::Complete { request, .. } | FlowEntry::Pending { request, .. }) => {
                Some(request.as_ref())
            }
            _ => None,
        }
    }

    pub fn selected_pending_request(&self) -> Option<(u64, &ProxiedRequest)> {
        let filter = self.filter.as_deref();
        let filtered: Vec<&FlowEntry> = self
            .entries
            .iter()
            .filter(|e| matches_filter(e, filter))
            .collect();
        let idx = self.table_state.selected()?;
        match filtered.get(idx) {
            Some(FlowEntry::Pending { id, request }) => Some((*id, request.as_ref())),
            _ => None,
        }
    }

    fn reset_detail_scroll(&mut self) {
        self.detail_scroll = 0;
        self.frames_follow = true;
        self.detail_focused = false;
    }

    fn reset_scroll_only(&mut self) {
        self.detail_scroll = 0;
        self.frames_follow = true;
    }

    pub fn select_next(&mut self) {
        let len = self.filtered_count();
        if len == 0 {
            return;
        }
        let i = self
            .table_state
            .selected()
            .map_or(0, |i| (i + 1).min(len - 1));
        self.table_state.select(Some(i));
        self.reset_detail_scroll();
    }

    pub fn select_prev(&mut self) {
        let i = self
            .table_state
            .selected()
            .map_or(0, |i| i.saturating_sub(1));
        self.table_state.select(Some(i));
        self.reset_detail_scroll();
    }

    pub fn select_first(&mut self) {
        if self.filtered_count() > 0 {
            self.table_state.select(Some(0));
            self.reset_detail_scroll();
        }
    }

    pub fn select_last(&mut self) {
        let len = self.filtered_count();
        if len > 0 {
            self.table_state.select(Some(len - 1));
            self.reset_detail_scroll();
        }
    }

    pub fn toggle_tab(&mut self) {
        self.reset_scroll_only();
        self.detail_tab = match self.detail_tab {
            DetailTab::Request => DetailTab::Response,
            DetailTab::Response => DetailTab::Request,
        };
    }

    pub fn remove_pending_by_id(&mut self, id: u64) {
        let pos = self
            .entries
            .iter()
            .position(|e| matches!(e, FlowEntry::Pending { id: eid, .. } if *eid == id));
        if let Some(idx) = pos {
            self.entries.remove(idx);
            let len = self.filtered_count();
            if let Some(sel) = self.table_state.selected() {
                if sel >= len && len > 0 {
                    self.table_state.select(Some(len - 1));
                } else if len == 0 {
                    self.table_state.select(None);
                }
            }
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.table_state.select(None);
        self.detail_open = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use crossterm::event::KeyModifiers;
    use http::{Method, StatusCode, Version};
    use proxyapi_models::{HeaderBlock, WsDirection, WsFrame, WsOpcode};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn request(method: Method, uri: &str, time: i64) -> Box<ProxiedRequest> {
        let mut headers = HeaderBlock::new();
        headers.add("x-test", "state").unwrap();
        Box::new(ProxiedRequest::new(
            method,
            uri.parse().unwrap(),
            Version::HTTP_11,
            headers,
            Bytes::from_static(b"request"),
            time,
        ))
    }

    fn response(
        status: StatusCode,
        content_type: Option<&str>,
        body: Bytes,
        time: i64,
    ) -> Box<ProxiedResponse> {
        let mut headers = HeaderBlock::new();
        if let Some(content_type) = content_type {
            headers.add("content-type", content_type).unwrap();
        }
        Box::new(ProxiedResponse::new(
            status,
            Version::HTTP_11,
            headers,
            body,
            time,
        ))
    }

    #[test]
    fn edit_session_handles_unicode_multiline_editing() {
        let mut session = EditSession::new(9, "ab\ncd");

        assert!(matches!(
            session.handle_key(key(KeyCode::Right)),
            EditAction::None
        ));
        session.handle_key(key(KeyCode::Char('é')));
        session.handle_key(key(KeyCode::End));
        session.handle_key(key(KeyCode::Enter));
        session.handle_key(key(KeyCode::Char('x')));
        session.handle_key(key(KeyCode::Backspace));
        session.handle_key(key(KeyCode::Backspace));
        session.handle_key(key(KeyCode::Delete));

        assert_eq!(session.to_text(), "aébcd");
        assert!(matches!(
            session.handle_key(key(KeyCode::Esc)),
            EditAction::StageEdits
        ));

        session.typing = false;
        assert!(matches!(
            session.handle_key(key(KeyCode::Esc)),
            EditAction::Discard
        ));
    }

    #[test]
    fn edit_session_scrolls_cursor_into_view() {
        let mut session = EditSession::new(1, "a\nb\nc\nd");
        session.cursor_row = 3;
        session.scroll_into_view(2);
        assert_eq!(session.scroll, 2);

        session.cursor_row = 0;
        session.scroll_into_view(2);
        assert_eq!(session.scroll, 0);

        session.scroll = 10;
        session.scroll_into_view(0);
        assert_eq!(session.scroll, 10);
    }

    #[test]
    fn app_state_promotes_pending_flow_in_place() {
        let mut state = AppState::new();
        state.add_event(ProxyEvent::RequestIntercepted {
            id: 7,
            request: request(Method::POST, "http://api.test/pending", 1000),
        });
        state.table_state.select(Some(0));

        assert_eq!(state.pending_count(), 1);
        assert_eq!(state.selected_pending_id(), Some(7));
        assert_eq!(
            state.selected_pending_request().unwrap().1.uri().path(),
            "/pending"
        );

        state.add_event(ProxyEvent::RequestComplete {
            id: 7,
            request: request(Method::POST, "http://api.test/done", 1000),
            response: response(
                StatusCode::CREATED,
                Some("application/json"),
                Bytes::new(),
                1250,
            ),
        });

        assert_eq!(state.pending_count(), 0);
        assert_eq!(state.entries.len(), 1);
        assert_eq!(state.selected_request().unwrap().uri().path(), "/done");
        assert!(matches!(
            state.entries.front().unwrap(),
            FlowEntry::Complete { .. }
        ));
    }

    #[test]
    fn app_state_filters_complete_and_websocket_entries_by_column() {
        let complete = FlowEntry::Complete {
            request: request(Method::GET, "https://api.example.test/items?q=one", 1000),
            response: response(
                StatusCode::CREATED,
                Some("application/json"),
                Bytes::from(vec![0; 2048]),
                2500,
            ),
        };

        assert!(matches_filter(&complete, Some("method:get")));
        assert!(matches_filter(&complete, Some("host:api.example")));
        assert!(matches_filter(&complete, Some("path:/items")));
        assert!(matches_filter(&complete, Some("status:201")));
        assert!(matches_filter(&complete, Some("type:json")));
        assert!(matches_filter(&complete, Some("size:2.0kb")));
        assert!(matches_filter(&complete, Some("duration:1.5s")));
        assert!(matches_filter(&complete, Some("proto:https")));
        assert!(matches_filter(&complete, Some("items?q=one")));
        assert!(!matches_filter(&complete, Some("method:post")));

        let websocket = FlowEntry::WebSocket {
            id: 2,
            request: request(Method::GET, "wss://socket.example.test/live", 3000),
            _response: response(StatusCode::SWITCHING_PROTOCOLS, None, Bytes::new(), 3010),
            frames: VecDeque::new(),
            closed: false,
        };

        assert!(matches_filter(&websocket, Some("proto:wss")));
        assert!(matches_filter(&websocket, Some("method:get")));
        assert!(matches_filter(&websocket, Some("status:101")));
        assert!(matches_filter(&websocket, Some("socket.example")));
        assert!(!matches_filter(&websocket, Some("status:200")));
    }

    #[test]
    fn app_state_tracks_websocket_frames_and_close() {
        let mut state = AppState::new();
        state.add_event(ProxyEvent::WebSocketConnected {
            id: 99,
            request: request(Method::GET, "ws://socket.test/live", 0),
            response: response(StatusCode::SWITCHING_PROTOCOLS, None, Bytes::new(), 1),
        });

        state.add_event(ProxyEvent::WebSocketFrame {
            conn_id: 99,
            frame: Box::new(WsFrame::new(
                WsDirection::ClientToServer,
                WsOpcode::Text,
                2,
                Bytes::from_static(b"hello"),
                false,
            )),
        });
        state.add_event(ProxyEvent::WebSocketClosed { conn_id: 99 });

        match state.entries.front().unwrap() {
            FlowEntry::WebSocket { frames, closed, .. } => {
                assert_eq!(frames.len(), 1);
                assert_eq!(frames[0].payload.as_ref(), b"hello");
                assert!(*closed);
            }
            _ => panic!("expected websocket entry"),
        }
    }

    #[test]
    fn app_state_tracks_and_filters_tcp_dns_and_udp_entries() {
        let mut state = AppState::new();
        state.add_event(ProxyEvent::TcpConnected {
            id: 10,
            target: "cache.example.test:6379".to_owned(),
            opened_at: 1_000,
        });
        state.add_event(ProxyEvent::TcpData {
            stream_id: 10,
            chunk: Box::new(proxyapi_models::TcpChunk {
                direction: proxyapi_models::StreamDirection::ClientToServer,
                time: 1_001,
                payload: Bytes::from_static(b"SET key value"),
                truncated: false,
            }),
        });
        state.add_event(ProxyEvent::TcpClosed { stream_id: 10 });
        state.add_event(ProxyEvent::DnsQuery {
            id: 11,
            name: "api.example.test".to_owned(),
            query_type: 1,
            time: 1_002,
        });
        state.add_event(ProxyEvent::DnsResponse {
            id: 11,
            answers: vec!["127.0.0.1".to_owned()],
            overridden: true,
        });
        state.add_event(ProxyEvent::UdpExchange {
            exchange: Box::new(CapturedUdpExchange {
                id: 12,
                target: "127.0.0.1:9000".to_owned(),
                client: "127.0.0.1:50000".to_owned(),
                time: 1_003,
                request: Bytes::from_static(b"ping"),
                response: Bytes::new(),
                response_received: true,
                request_truncated: false,
                response_truncated: false,
            }),
        });

        assert_eq!(state.entries.len(), 3);
        assert!(matches_filter(
            &state.entries[0],
            Some("proto:tcp & body:value & status:closed")
        ));
        assert!(matches_filter(
            &state.entries[1],
            Some("proto:dns & host:api.example & status:override")
        ));
        assert!(matches_filter(
            &state.entries[2],
            Some("proto:udp & body:ping & status:complete")
        ));
    }

    #[test]
    fn selection_and_remove_pending_respect_filtered_rows() {
        let mut state = AppState::new();
        state.add_event(ProxyEvent::RequestIntercepted {
            id: 1,
            request: request(Method::GET, "http://api.test/one", 0),
        });
        state.add_event(ProxyEvent::RequestIntercepted {
            id: 2,
            request: request(Method::POST, "http://api.test/two", 0),
        });

        state.filter = Some("method:post".to_owned());
        state.select_last();
        assert_eq!(state.selected_pending_id(), Some(2));

        state.remove_pending_by_id(2);
        assert_eq!(state.table_state.selected(), None);

        state.filter = None;
        state.select_first();
        assert_eq!(state.selected_pending_id(), Some(1));

        state.detail_open = true;
        state.clear();
        assert!(state.entries.is_empty());
        assert_eq!(state.table_state.selected(), None);
        assert!(!state.detail_open);
    }
}
