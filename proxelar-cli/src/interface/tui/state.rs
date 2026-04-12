use std::collections::VecDeque;

use chrono::{Local, TimeZone};
use crossterm::event::{KeyCode, KeyEvent};
use proxyapi::ProxyEvent;
use proxyapi_models::{ProxiedRequest, ProxiedResponse, WsFrame};
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
        id: u64,
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
}

impl FlowEntry {
    #[allow(dead_code)]
    pub fn id(&self) -> Option<u64> {
        match self {
            FlowEntry::Complete { id, .. }
            | FlowEntry::Pending { id, .. }
            | FlowEntry::WebSocket { id, .. } => Some(*id),
            FlowEntry::Error { .. } => None,
        }
    }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterColumn {
    Time,
    Proto,
    Method,
    Host,
    Path,
    Status,
    Type,
    Size,
    Duration,
}

fn parse_filter(filter: &str) -> (Option<FilterColumn>, &str) {
    if let Some(pos) = filter.find(':') {
        let col = match filter[..pos].to_ascii_lowercase().as_str() {
            "time" => Some(FilterColumn::Time),
            "proto" => Some(FilterColumn::Proto),
            "method" => Some(FilterColumn::Method),
            "host" => Some(FilterColumn::Host),
            "path" => Some(FilterColumn::Path),
            "status" => Some(FilterColumn::Status),
            "type" => Some(FilterColumn::Type),
            "size" => Some(FilterColumn::Size),
            "duration" => Some(FilterColumn::Duration),
            _ => None,
        };
        if let Some(col) = col {
            return (Some(col), &filter[pos + 1..]);
        }
    }
    (None, filter)
}

fn proto_str(request: &ProxiedRequest, is_ws: bool) -> &'static str {
    let tls = matches!(request.uri().scheme_str(), Some("https") | Some("wss"));
    match (is_ws, tls) {
        (true, true) => "wss",
        (true, false) => "ws",
        (false, true) => "https",
        (false, false) => "http",
    }
}

fn request_matches_column(request: &ProxiedRequest, col: FilterColumn, val: &str, is_ws: bool) -> bool {
    match col {
        FilterColumn::Method => request.method().as_str().to_ascii_lowercase().contains(val),
        FilterColumn::Host => request
            .uri()
            .host()
            .unwrap_or("")
            .to_ascii_lowercase()
            .contains(val),
        FilterColumn::Path => request.uri().path().to_ascii_lowercase().contains(val),
        FilterColumn::Proto => proto_str(request, is_ws).contains(val),
        _ => false,
    }
}

fn request_matches_any(request: &ProxiedRequest, val: &str) -> bool {
    request.uri().to_string().to_ascii_lowercase().contains(val)
        || request.method().as_str().to_ascii_lowercase().contains(val)
}

pub(crate) fn matches_filter(entry: &FlowEntry, filter: Option<&str>) -> bool {
    let Some(filter) = filter else {
        return true;
    };
    let (col, value) = parse_filter(filter);
    let value_lower = value.to_ascii_lowercase();
    let val = value_lower.as_str();

    match entry {
        FlowEntry::Complete {
            request, response, ..
        } => match col {
            Some(FilterColumn::Status) => response.status().as_u16().to_string().contains(val),
            Some(FilterColumn::Size) => crate::interface::format_size(response.body().len())
                .to_ascii_lowercase()
                .contains(val),
            Some(FilterColumn::Type) => response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_ascii_lowercase()
                .contains(val),
            Some(FilterColumn::Duration) => {
                let ms = response.time() - request.time();
                format_duration_filter(ms).contains(val)
            }
            Some(FilterColumn::Time) => format_time_filter(request.time()).contains(val),
            Some(col) => request_matches_column(request, col, val, false),
            None => request_matches_any(request, val),
        },
        FlowEntry::Pending { request, .. } => match col {
            Some(FilterColumn::Time) => format_time_filter(request.time()).contains(val),
            Some(col) => request_matches_column(request, col, val, false),
            None => request_matches_any(request, val),
        },
        FlowEntry::Error { message } => col.is_none() && message.to_ascii_lowercase().contains(val),
        FlowEntry::WebSocket {
            request,
            _response: ws_response,
            ..
        } => match col {
            Some(FilterColumn::Method) => "get".contains(val),
            Some(FilterColumn::Status) => ws_response.status().as_u16().to_string().contains(val),
            Some(FilterColumn::Type) => ws_response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_ascii_lowercase()
                .contains(val),
            Some(FilterColumn::Duration) => {
                let ms = ws_response.time() - request.time();
                format_duration_filter(ms).contains(val)
            }
            Some(FilterColumn::Time) => format_time_filter(request.time()).contains(val),
            Some(col) => request_matches_column(request, col, val, true),
            None => request.uri().to_string().to_ascii_lowercase().contains(val),
        },
    }
}

fn format_time_filter(millis: i64) -> String {
    Local
        .timestamp_millis_opt(millis)
        .single()
        .map(|dt| dt.format("%H:%M:%S").to_string())
        .unwrap_or_default()
}

fn format_duration_filter(ms: i64) -> String {
    if ms < 0 {
        return String::new();
    }
    if ms >= 1000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        format!("{ms}ms")
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
                    *entry = FlowEntry::Complete {
                        id,
                        request,
                        response,
                    };
                } else {
                    self.entries.push_back(FlowEntry::Complete {
                        id,
                        request,
                        response,
                    });
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
