use std::collections::VecDeque;

use crossterm::event::{KeyCode, KeyEvent};
use proxyapi::ProxyEvent;
use proxyapi_models::{ProxiedRequest, ProxiedResponse};
use ratatui::widgets::TableState;

/// Maximum number of stored flow entries before old entries are evicted.
const MAX_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailTab {
    Request,
    Response,
}

/// A single entry in the flow list.
///
/// An entry starts as `Pending` when intercept mode is active, then is
/// promoted to `Complete` in-place once the request has been forwarded
/// and a response received.
pub enum FlowEntry {
    /// A completed request/response pair.
    Complete {
        id: u64,
        request: Box<ProxiedRequest>,
        response: Box<ProxiedResponse>,
    },
    /// A request held pending a UI intercept decision (no response yet).
    Pending {
        id: u64,
        request: Box<ProxiedRequest>,
    },
    /// A proxy error (no request/response pair).
    Error { message: String },
}

impl FlowEntry {
    #[allow(dead_code)]
    pub fn id(&self) -> Option<u64> {
        match self {
            FlowEntry::Complete { id, .. } | FlowEntry::Pending { id, .. } => Some(*id),
            FlowEntry::Error { .. } => None,
        }
    }

    pub fn is_pending(&self) -> bool {
        matches!(self, FlowEntry::Pending { .. })
    }
}

/// What the caller should do after an `EditSession` key event.
pub enum EditAction {
    /// Keep editing — no external action needed.
    None,
    /// User pressed `Esc` while typing — exit typing mode but keep edits staged.
    /// The caller should leave the session open (now in review mode).
    StageEdits,
    /// User pressed `Esc` while already in review mode — discard everything.
    Discard,
}

/// A minimal inline text editor for editing an intercepted HTTP request.
///
/// Has two sub-states:
/// - **typing** (`typing == true`): key events are forwarded to the editor.
///   `Esc` exits typing and stages the edits.
/// - **staged** (`typing == false`): edits are ready; the caller forwards them
///   via the regular `f` key or discards via `Esc`.
pub struct EditSession {
    pub id: u64,
    pub lines: Vec<String>,
    pub cursor_row: usize,
    pub cursor_col: usize,
    /// First visible line index (vertical scroll offset).
    pub scroll: usize,
    /// Whether the user is actively typing (vs reviewing staged edits).
    pub typing: bool,
    /// Set when the last forward attempt failed to parse the edited text.
    pub parse_error: bool,
    /// Set when the original request body was not valid UTF-8.
    pub binary_body: bool,
}

impl EditSession {
    /// Create a new session from raw HTTP text.
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

    /// Handle a single key event. Returns the action the caller should take.
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

    /// Serialise all lines back to a single string (LF-separated).
    pub fn to_text(&self) -> String {
        self.lines.join("\n")
    }

    /// Ensure `scroll` keeps the cursor visible within the given viewport height.
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

    // ── internal helpers ────────────────────────────────────────────────────

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
    pub detail_tab: DetailTab,
    pub filter: Option<String>,
    pub filter_input: String,
    pub filter_mode: bool,
    /// Mirrors `InterceptConfig::is_enabled()` for rendering without locking.
    pub intercept_enabled: bool,
    /// Active inline edit session (set when user presses `e` on a pending row).
    pub edit_session: Option<EditSession>,
    /// Whether the help overlay is visible.
    pub show_help: bool,
}

/// Returns `true` if `entry` matches the given filter string (case-insensitive).
pub(crate) fn matches_filter(entry: &FlowEntry, filter: Option<&str>) -> bool {
    let Some(filter) = filter else {
        return true;
    };
    let filter_lower = filter.to_lowercase();
    match entry {
        FlowEntry::Complete { request, .. } | FlowEntry::Pending { request, .. } => {
            let uri = request.uri().to_string();
            let method = request.method().as_str();
            uri.to_lowercase().contains(&filter_lower)
                || method.to_lowercase().contains(&filter_lower)
        }
        FlowEntry::Error { message } => message.to_lowercase().contains(&filter_lower),
    }
}

impl AppState {
    pub fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            table_state: TableState::default(),
            detail_open: false,
            detail_tab: DetailTab::Request,
            filter: None,
            filter_input: String::new(),
            filter_mode: false,
            intercept_enabled: false,
            edit_session: None,
            show_help: false,
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

    /// Returns the `id` of the currently selected entry if it is pending.
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

    /// Returns a reference to the request of the currently selected entry (Complete or Pending).
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

    /// Returns a reference to the request of the currently selected pending entry.
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
    }

    pub fn select_prev(&mut self) {
        let i = self
            .table_state
            .selected()
            .map_or(0, |i| i.saturating_sub(1));
        self.table_state.select(Some(i));
    }

    pub fn select_first(&mut self) {
        if self.filtered_count() > 0 {
            self.table_state.select(Some(0));
        }
    }

    pub fn select_last(&mut self) {
        let len = self.filtered_count();
        if len > 0 {
            self.table_state.select(Some(len - 1));
        }
    }

    pub fn toggle_detail(&mut self) {
        self.detail_open = !self.detail_open;
    }

    pub fn toggle_tab(&mut self) {
        self.detail_tab = match self.detail_tab {
            DetailTab::Request => DetailTab::Response,
            DetailTab::Response => DetailTab::Request,
        };
    }

    /// Remove a pending entry by ID. Called when the user drops (blocks) an
    /// intercepted request so the row doesn't stay in the list forever.
    pub fn remove_pending_by_id(&mut self, id: u64) {
        let pos = self
            .entries
            .iter()
            .position(|e| matches!(e, FlowEntry::Pending { id: eid, .. } if *eid == id));
        if let Some(idx) = pos {
            self.entries.remove(idx);
            // Keep selection valid.
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
