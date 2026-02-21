use std::collections::VecDeque;

use proxyapi::ProxyEvent;
use ratatui::widgets::TableState;

/// Maximum number of stored requests before old entries are evicted.
const MAX_REQUESTS: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailTab {
    Request,
    Response,
}

pub struct AppState {
    pub(crate) requests: VecDeque<ProxyEvent>,
    pub table_state: TableState,
    pub detail_open: bool,
    pub detail_tab: DetailTab,
    pub filter: Option<String>,
    pub filter_input: String,
    pub filter_mode: bool,
}

/// Returns `true` if `event` matches the given filter string (case-insensitive).
pub(crate) fn matches_filter(event: &ProxyEvent, filter: Option<&str>) -> bool {
    let Some(filter) = filter else {
        return true;
    };
    let filter_lower = filter.to_lowercase();
    match event {
        ProxyEvent::RequestComplete { request, .. } => {
            let uri = request.uri().to_string();
            let method = request.method().as_str();
            uri.to_lowercase().contains(&filter_lower)
                || method.to_lowercase().contains(&filter_lower)
        }
        ProxyEvent::Error { message } => message.to_lowercase().contains(&filter_lower),
    }
}

impl AppState {
    pub fn new() -> Self {
        Self {
            requests: VecDeque::new(),
            table_state: TableState::default(),
            detail_open: false,
            detail_tab: DetailTab::Request,
            filter: None,
            filter_input: String::new(),
            filter_mode: false,
        }
    }

    pub fn add_event(&mut self, event: ProxyEvent) {
        self.requests.push_back(event);
        if self.requests.len() > MAX_REQUESTS {
            self.requests.pop_front();
            if let Some(idx) = self.table_state.selected() {
                self.table_state.select(Some(idx.saturating_sub(1)));
            }
        }
    }

    fn filtered_count(&self) -> usize {
        let filter = self.filter.as_deref();
        self.requests
            .iter()
            .filter(|event| matches_filter(event, filter))
            .count()
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

    pub fn clear(&mut self) {
        self.requests.clear();
        self.table_state.select(None);
        self.detail_open = false;
    }
}
