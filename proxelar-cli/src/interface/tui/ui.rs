use std::collections::VecDeque;

use proxyapi_models::{WsDirection, WsFrame, WsOpcode};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap},
    Frame,
};

use super::state::EditSession;

use super::state::{matches_filter, AppState, DetailTab, FlowEntry};
use crate::interface::format_size;

pub fn draw(f: &mut Frame, state: &mut AppState) {
    let filter = state.filter.as_deref();
    let filtered: Vec<(usize, &FlowEntry)> = state
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| matches_filter(entry, filter))
        .collect();
    let req_count = filtered.len();
    let pending_count = state.pending_count();

    let chunks = if state.detail_open {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(8),
                Constraint::Percentage(40),
                Constraint::Length(1),
            ])
            .split(f.area())
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(8), Constraint::Length(1)])
            .split(f.area())
    };

    let title = format!(
        " Proxelar v{} \u{2500} {req_count} reqs ",
        env!("CARGO_PKG_VERSION")
    );

    // Request table
    let header = Row::new(vec![
        Cell::from("#"),
        Cell::from("Method"),
        Cell::from("Status"),
        Cell::from("Host"),
        Cell::from("Path"),
        Cell::from("Size"),
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = filtered
        .iter()
        .map(|(_idx, entry)| match entry {
            FlowEntry::Complete {
                id,
                request,
                response,
            } => {
                let method = request.method().as_str();
                let status = response.status().as_u16();
                let uri = request.uri();
                let host = uri.host().unwrap_or("-");
                let path = uri.path();
                let size = format_size(response.body().len());

                let method_color = method_color(method);
                let status_color = status_color(status);

                Row::new(vec![
                    Cell::from(id.to_string()),
                    Cell::from(method).style(Style::default().fg(method_color)),
                    Cell::from(status.to_string()).style(Style::default().fg(status_color)),
                    Cell::from(host),
                    Cell::from(path),
                    Cell::from(size),
                ])
            }
            FlowEntry::Pending { id, request } => {
                let method = request.method().as_str();
                let uri = request.uri();
                let host = uri.host().unwrap_or("-");
                let path = uri.path();
                let id_str = format!("\u{23f8}{id}"); // ⏸ prefix

                Row::new(vec![
                    Cell::from(id_str).style(Style::default().fg(Color::Yellow)),
                    Cell::from(method).style(
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Cell::from("\u{00b7}\u{00b7}\u{00b7}")
                        .style(Style::default().fg(Color::Yellow)), // ···
                    Cell::from(host).style(Style::default().fg(Color::Yellow)),
                    Cell::from(path).style(Style::default().fg(Color::Yellow)),
                    Cell::from("-").style(Style::default().fg(Color::Yellow)),
                ])
            }
            FlowEntry::Error { message } => Row::new(vec![
                Cell::from(_idx.to_string()),
                Cell::from("ERR").style(Style::default().fg(Color::Red)),
                Cell::from("-"),
                Cell::from(message.as_str()),
                Cell::from("-"),
                Cell::from("-"),
            ]),
            FlowEntry::WebSocket {
                id,
                request,
                frames,
                closed,
                ..
            } => {
                let uri = request.uri();
                let host = uri.host().unwrap_or("-");
                let path = uri.path();
                // WS✓ (closed) or WS⇄ (live)
                let status_str = if *closed { "WS\u{2713}" } else { "WS\u{21c4}" };
                let frame_count = format!("{}fr", frames.len());

                Row::new(vec![
                    Cell::from(id.to_string()),
                    Cell::from("GET").style(Style::default().fg(Color::Green)),
                    Cell::from(status_str).style(Style::default().fg(Color::Cyan)),
                    Cell::from(host),
                    Cell::from(path),
                    Cell::from(frame_count).style(Style::default().fg(Color::Cyan)),
                ])
            }
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Length(7),
            Constraint::Length(6),
            Constraint::Percentage(30),
            Constraint::Percentage(40),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title))
    .row_highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    );

    f.render_stateful_widget(table, chunks[0], &mut state.table_state);

    // Detail panel
    if state.detail_open && chunks.len() > 2 {
        if let Some(ref mut session) = state.edit_session {
            draw_editor(f, session, chunks[1]);
        } else {
            draw_detail(f, state, chunks[1], &filtered);
        }
    }

    // Status bar
    let status_chunk = if state.detail_open && chunks.len() > 2 {
        chunks[2]
    } else {
        chunks[1]
    };

    draw_status_bar(f, state, status_chunk, pending_count);

    if state.show_help {
        draw_help_modal(f);
    }
}

fn draw_status_bar(f: &mut Frame, state: &AppState, area: Rect, pending_count: usize) {
    if state.filter_mode {
        let text = format!(" Filter: {}_ ", state.filter_input);
        let bar = Paragraph::new(text.as_str())
            .style(Style::default().bg(Color::DarkGray).fg(Color::White));
        f.render_widget(bar, area);
        return;
    }

    // Build status bar spans
    let mut spans: Vec<Span> = Vec::new();

    if state.intercept_enabled {
        spans.push(Span::styled(
            " INTERCEPT ",
            Style::default()
                .bg(Color::Red)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ));
        if pending_count > 0 {
            spans.push(Span::styled(
                format!(" \u{00b7} {pending_count} pending "),
                Style::default().fg(Color::Yellow),
            ));
        }
        spans.push(Span::raw("  "));
    }

    let hint = if let Some(ref s) = state.edit_session {
        if s.typing {
            " Esc: done editing ".to_string()
        } else {
            " f: forward  |  e: edit  |  d: drop  |  Esc: discard edits ".to_string()
        }
    } else if state.detail_focused {
        " j/k: scroll  Tab: switch tab  Enter/Esc: back to table ".to_string()
    } else if let Some(ref filter) = state.filter {
        format!(" Filter: {filter}  |  q:quit  i:intercept  r:replay  /:filter  j/k:nav  Enter:open/focus  Tab:req/res  g/G:top/bot  c:clear  ?:help ")
    } else {
        " q:quit  i:intercept  r:replay  /:filter  j/k:nav  Enter:open/focus  Tab:req/res  g/G:top/bot  c:clear  ?:help "
            .to_string()
    };
    spans.push(Span::raw(hint));

    let line = Line::from(spans);
    let bar = Paragraph::new(line).style(Style::default().bg(Color::DarkGray).fg(Color::White));
    f.render_widget(bar, area);
}

fn draw_detail(f: &mut Frame, state: &AppState, area: Rect, filtered: &[(usize, &FlowEntry)]) {
    let selected = state.table_state.selected().unwrap_or(0);
    let focused = state.detail_focused;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };

    if let Some((_, entry)) = filtered.get(selected) {
        match entry {
            FlowEntry::Complete {
                request, response, ..
            } => {
                let tab_title = match state.detail_tab {
                    DetailTab::Request => " [Request] Response ",
                    DetailTab::Response => " Request [Response] ",
                };

                let content = match state.detail_tab {
                    DetailTab::Request => build_request_lines(request),
                    DetailTab::Response => build_response_lines(response),
                };

                let detail = Paragraph::new(content)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(tab_title)
                            .border_style(border_style),
                    )
                    .scroll((state.detail_scroll as u16, 0))
                    .wrap(Wrap { trim: false });

                f.render_widget(detail, area);
            }
            FlowEntry::Pending { request, .. } => {
                draw_intercept_pane(f, area, request);
            }
            FlowEntry::Error { message } => {
                let detail = Paragraph::new(message.as_str())
                    .block(Block::default().borders(Borders::ALL).title(" Error "))
                    .wrap(Wrap { trim: false });
                f.render_widget(detail, area);
            }
            FlowEntry::WebSocket {
                request,
                frames,
                closed,
                ..
            } => {
                // "Response" tab slot is repurposed as "Frames" for WebSocket entries.
                let tab_title = match state.detail_tab {
                    DetailTab::Request => " [Request] Frames ",
                    DetailTab::Response => " Request [Frames] ",
                };

                // In follow mode, pin scroll to the tail of the frame list.
                let visible_height = area.height.saturating_sub(2) as usize;
                let effective_scroll = if state.frames_follow {
                    frames.len().saturating_sub(visible_height)
                } else {
                    state.detail_scroll
                };

                let (content, para_scroll) = match state.detail_tab {
                    DetailTab::Request => (build_request_lines(request), state.detail_scroll as u16),
                    DetailTab::Response => (
                        build_frames_lines(frames, *closed, effective_scroll, state.frames_follow),
                        0, // frames already skipped inside build_frames_lines
                    ),
                };

                let detail = Paragraph::new(content)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(tab_title)
                            .border_style(border_style),
                    )
                    .scroll((para_scroll, 0))
                    .wrap(Wrap { trim: false });
                f.render_widget(detail, area);
            }
        }
    }
}

/// Render the inline request editor.
///
/// Lines are displayed verbatim; the cursor is shown as a reversed-style
/// block on the character under the cursor (or a space if at end-of-line).
fn draw_editor(f: &mut Frame, session: &mut EditSession, area: Rect) {
    // Reserve 1 line for the action hint at the bottom.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(1)])
        .split(area);

    let inner_height = chunks[0].height.saturating_sub(2) as usize; // subtract borders
    session.scroll_into_view(inner_height.max(1));

    let mut lines: Vec<Line<'static>> = Vec::new();
    for (row_idx, line_str) in session
        .lines
        .iter()
        .enumerate()
        .skip(session.scroll)
        .take(inner_height + 1)
    {
        if row_idx == session.cursor_row {
            // Build a line with a cursor block at cursor_col.
            let chars: Vec<char> = line_str.chars().collect();
            let before: String = chars[..session.cursor_col.min(chars.len())]
                .iter()
                .collect();
            let cursor_char: String = chars
                .get(session.cursor_col)
                .map(|c| c.to_string())
                .unwrap_or_else(|| " ".to_string());
            let after: String = if session.cursor_col + 1 < chars.len() {
                chars[session.cursor_col + 1..].iter().collect()
            } else {
                String::new()
            };

            lines.push(Line::from(vec![
                Span::raw(before),
                Span::styled(
                    cursor_char,
                    Style::default()
                        .bg(Color::White)
                        .fg(Color::Black)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(after),
            ]));
        } else {
            lines.push(Line::from(line_str.clone()));
        }
    }

    let (title, hint_text, border_color) = if session.parse_error {
        (
            " \u{270e} Editing Request — parse error: check request line ",
            "  fix the request line (METHOD URI HTTP/1.x), then Esc  ",
            Color::Red,
        )
    } else if session.typing {
        let t = if session.binary_body {
            " \u{270e} Editing Request (\u{26a0} binary body) — Esc when done "
        } else {
            " \u{270e} Editing Request — Esc when done "
        };
        (
            t,
            "  arrows/Home/End: move  Enter: newline  Backspace/Del: delete  Esc: done editing  ",
            Color::Cyan,
        )
    } else {
        (
            " \u{270e} Request ready ",
            "  f: forward  e: edit  d: drop  Esc: discard edits  ",
            Color::Yellow,
        )
    };

    let editor = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(border_color)),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(editor, chunks[0]);

    let hint =
        Paragraph::new(hint_text).style(Style::default().bg(Color::DarkGray).fg(Color::White));
    f.render_widget(hint, chunks[1]);
}

fn draw_intercept_pane(f: &mut Frame, area: Rect, request: &proxyapi_models::ProxiedRequest) {
    // Split the pane: request content on top, action hint at bottom
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(1)])
        .split(area);

    let mut lines = build_request_lines(request);

    // Add a blank line before the hint so it doesn't crowd the body
    lines.push(Line::from(""));

    let content = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" \u{23f8} Intercepted Request ")
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(content, chunks[0]);

    let action_bar = Paragraph::new("  [f] Forward    [d] Drop (504)    [e] Edit  ").style(
        Style::default()
            .bg(Color::Yellow)
            .fg(Color::Black)
            .add_modifier(Modifier::BOLD),
    );
    f.render_widget(action_bar, chunks[1]);
}

fn build_request_lines(request: &proxyapi_models::ProxiedRequest) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                request.method().as_str().to_owned(),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::raw(request.uri().to_string()),
            Span::raw(" "),
            Span::raw(format!("{:?}", request.version())),
        ]),
        Line::from(""),
    ];

    for (name, value) in request.headers() {
        lines.push(Line::from(vec![
            Span::styled(name.as_str().to_owned(), Style::default().fg(Color::Cyan)),
            Span::raw(": "),
            Span::raw(String::from_utf8_lossy(value.as_bytes()).into_owned()),
        ]));
    }

    if !request.body().is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(
            String::from_utf8_lossy(request.body()).into_owned(),
        ));
    }

    lines
}

fn build_response_lines(response: &proxyapi_models::ProxiedResponse) -> Vec<Line<'static>> {
    let status = response.status();
    let status_color = status_color(status.as_u16());

    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                status.to_string(),
                Style::default()
                    .fg(status_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::raw(format!("{:?}", response.version())),
        ]),
        Line::from(""),
    ];

    for (name, value) in response.headers() {
        lines.push(Line::from(vec![
            Span::styled(name.as_str().to_owned(), Style::default().fg(Color::Cyan)),
            Span::raw(": "),
            Span::raw(String::from_utf8_lossy(value.as_bytes()).into_owned()),
        ]));
    }

    if !response.body().is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(
            String::from_utf8_lossy(response.body()).into_owned(),
        ));
    }

    lines
}

fn build_frames_lines(
    frames: &VecDeque<WsFrame>,
    closed: bool,
    scroll: usize,
    follow: bool,
) -> Vec<Line<'static>> {
    if frames.is_empty() {
        return vec![Line::from(if closed {
            "No frames captured (connection closed)"
        } else {
            "Waiting for frames..."
        })];
    }

    let mut lines: Vec<Line<'static>> = frames
        .iter()
        .skip(scroll)
        .map(|f| {
            let (dir_sym, dir_color) = match f.direction {
                WsDirection::ClientToServer => ("\u{2191}", Color::Yellow), // ↑
                WsDirection::ServerToClient => ("\u{2193}", Color::Cyan),   // ↓
            };
            let op = match f.opcode {
                WsOpcode::Text => "txt ",
                WsOpcode::Binary => "bin ",
                WsOpcode::Ping => "ping",
                WsOpcode::Pong => "pong",
                WsOpcode::Close => "clse",
                WsOpcode::Continuation => "cont",
            };
            let payload_preview: String = if f.opcode == WsOpcode::Text {
                String::from_utf8_lossy(&f.payload)
                    .chars()
                    .take(120)
                    .collect()
            } else {
                f.payload
                    .iter()
                    .take(32)
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            let truncated = if f.truncated { " [trunc]" } else { "" };

            Line::from(vec![
                Span::styled(dir_sym, Style::default().fg(dir_color)),
                Span::raw(" "),
                Span::styled(op, Style::default().fg(Color::DarkGray)),
                Span::raw(format!(" {}B{} ", f.payload.len(), truncated)),
                Span::raw(payload_preview),
            ])
        })
        .collect();

    if closed {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "\u{2500}\u{2500} Connection closed \u{2500}\u{2500}",
            Style::default().fg(Color::Red),
        )));
    } else if follow {
        lines.push(Line::from(Span::styled(
            "[FOLLOW]",
            Style::default().fg(Color::DarkGray),
        )));
    }
    lines
}

fn method_color(method: &str) -> Color {
    match method {
        "GET" => Color::Green,
        "POST" => Color::Yellow,
        "PUT" => Color::Blue,
        "DELETE" => Color::Red,
        "PATCH" => Color::Magenta,
        _ => Color::White,
    }
}

fn status_color(status: u16) -> Color {
    match status {
        200..=299 => Color::Green,
        300..=399 => Color::Cyan,
        400..=499 => Color::Yellow,
        500..=599 => Color::Red,
        _ => Color::White,
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let vert = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vert[1])[1]
}

fn draw_help_modal(f: &mut Frame) {
    let area = centered_rect(62, 85, f.area());
    f.render_widget(Clear, area);

    // Each entry: (key, description). Empty description = section header.
    let entries: &[(&str, &str)] = &[
        ("--- Navigation ---", ""),
        ("j / ↓", "Select next row"),
        ("k / ↑", "Select previous row"),
        ("g", "Jump to first row"),
        ("G", "Jump to last row"),
        ("", ""),
        ("--- Actions ---", ""),
        ("Enter", "Open detail panel / focus it"),
        ("Enter / Esc (focused)", "Return focus to table"),
        ("j / k (focused)", "Scroll detail content"),
        ("Tab", "Switch Request / Response (or Frames) tab"),
        ("r", "Replay selected request"),
        ("c", "Clear all entries"),
        ("q / Q  Ctrl+C", "Quit"),
        ("", ""),
        ("--- Filter ---", ""),
        ("/", "Enter filter mode"),
        ("Enter", "Apply filter"),
        ("Esc", "Cancel filter / close detail"),
        ("column:value", "Filter by column (e.g. status:200)"),
        ("method / status / host", "Recognised column names"),
        ("path / size", "Recognised column names (cont.)"),
        ("", ""),
        ("--- Intercept ---", ""),
        ("i", "Toggle intercept ON / OFF"),
        ("f", "Forward intercepted request"),
        ("d", "Drop request (returns 504)"),
        ("e", "Edit intercepted request"),
        ("", ""),
        ("--- Request Editor ---", ""),
        ("↑ ↓ ← →", "Move cursor"),
        ("Home / End", "Jump to line start / end"),
        ("Enter", "Insert newline"),
        ("Backspace / Del", "Delete character"),
        ("Esc", "Finish editing (stage edits)"),
        ("f", "Forward edited request"),
        ("Esc (staged)", "Discard edits and close"),
        ("", ""),
        ("? / Esc", "Close this help"),
    ];

    let lines: Vec<Line<'static>> = entries
        .iter()
        .map(|(key, desc)| {
            if desc.is_empty() && key.is_empty() {
                Line::from("")
            } else if desc.is_empty() {
                // Section header
                Line::from(Span::styled(
                    key.to_string(),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ))
            } else {
                Line::from(vec![
                    Span::styled(format!("  {:<22}", key), Style::default().fg(Color::Cyan)),
                    Span::raw(desc.to_string()),
                ])
            }
        })
        .collect();

    let help = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Keybindings — ? or Esc to close ")
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(help, area);
}
