use std::collections::VecDeque;
use std::ops::Range;

use chrono::{Local, TimeZone};
use http::Uri;
use proxyapi_models::{
    CapturedDnsExchange, CapturedTcpStream, CapturedUdpExchange, HeaderBlock, StreamDirection,
    WsDirection, WsFrame, WsOpcode,
};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Wrap},
    Frame,
};

use super::state::EditSession;

use super::state::{matches_filter, AppState, DetailTab, FlowEntry};
use crate::interface::format_size;
use crate::wireguard_setup::WireGuardSetup;

pub fn draw(f: &mut Frame, state: &mut AppState, wireguard_setup: Option<&WireGuardSetup>) {
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
        " Proxelar v{} \u{2500} {req_count} flows ",
        env!("CARGO_PKG_VERSION")
    );

    // `Table` owns and collects every supplied row. Limit construction to the
    // current terminal viewport while keeping selection/offset in global
    // filtered coordinates.
    let visible_capacity = usize::from(chunks[0].height.saturating_sub(3)).max(1);
    let visible_range = visible_row_range(
        req_count,
        state.table_state.selected(),
        state.table_state.offset(),
        visible_capacity,
    );
    *state.table_state.offset_mut() = visible_range.start;
    let mut visible_table_state = TableState::default();
    visible_table_state.select(
        state
            .table_state
            .selected()
            .filter(|selected| visible_range.contains(selected))
            .map(|selected| selected - visible_range.start),
    );

    // Request table
    let header = Row::new(vec![
        Cell::from("Time"),
        Cell::from("Proto"),
        Cell::from("Method"),
        Cell::from("Host"),
        Cell::from("Path"),
        Cell::from("Status"),
        Cell::from("Type"),
        Cell::from("Size"),
        Cell::from("Duration"),
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = filtered[visible_range.clone()]
        .iter()
        .map(|(_idx, entry)| match entry {
            FlowEntry::Complete {
                request, response, ..
            } => {
                let method = request.method().as_str();
                let status = response.status().as_u16();
                let uri = request.uri();
                let host = uri.host().unwrap_or("-");
                let path = path_and_query(uri);
                let body_len = response.body().len();
                let size = format_size(body_len);
                let time_str = format_time(request.time());
                let proto = proto_from_uri(uri, false);
                let content_type = abbrev_content_type(response.headers());
                let dur_ms = response.time() - request.time();
                let duration = format_duration(dur_ms);

                Row::new(vec![
                    Cell::from(time_str),
                    Cell::from(proto).style(Style::default().fg(proto_color(proto))),
                    Cell::from(method).style(Style::default().fg(method_color(method))),
                    Cell::from(host),
                    Cell::from(path),
                    Cell::from(status.to_string()).style(status_style(status)),
                    Cell::from(content_type.clone())
                        .style(Style::default().fg(content_type_color(&content_type))),
                    Cell::from(size).style(Style::default().fg(size_color(body_len))),
                    Cell::from(duration).style(Style::default().fg(duration_color(dur_ms))),
                ])
            }
            FlowEntry::Pending { request, .. } => {
                let method = request.method().as_str();
                let uri = request.uri();
                let host = uri.host().unwrap_or("-");
                let path = path_and_query(uri);
                let time_str = format_time(request.time());
                let proto = proto_from_uri(uri, false);

                Row::new(vec![
                    Cell::from(time_str).style(Style::default().fg(Color::Yellow)),
                    Cell::from(proto).style(Style::default().fg(Color::Yellow)),
                    Cell::from(method).style(
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Cell::from(host).style(Style::default().fg(Color::Yellow)),
                    Cell::from(path).style(Style::default().fg(Color::Yellow)),
                    Cell::from("\u{00b7}\u{00b7}\u{00b7}")
                        .style(Style::default().fg(Color::Yellow)),
                    Cell::from("-").style(Style::default().fg(Color::Yellow)),
                    Cell::from("-").style(Style::default().fg(Color::Yellow)),
                    Cell::from("-").style(Style::default().fg(Color::Yellow)),
                ])
            }
            FlowEntry::Error { message } => Row::new(vec![
                Cell::from("-"),
                Cell::from("-"),
                Cell::from("ERR").style(Style::default().fg(Color::Red)),
                Cell::from(message.as_str()),
                Cell::from("-"),
                Cell::from("-"),
                Cell::from("-"),
                Cell::from("-"),
                Cell::from("-"),
            ]),
            FlowEntry::WebSocket {
                request,
                _response: ws_response,
                frames,
                closed,
                ..
            } => {
                let uri = request.uri();
                let host = uri.host().unwrap_or("-");
                let path = path_and_query(uri);
                let time_str = format_time(request.time());
                let proto = proto_from_uri(uri, true);
                let status = ws_response.status().as_u16();
                let content_type = abbrev_content_type(ws_response.headers());
                let ws_suffix = if *closed { "\u{2713}" } else { "\u{21c4}" };
                let frame_str = format!("{}fr{ws_suffix}", frames.len());
                let dur_ms = ws_response.time() - request.time();
                let duration = format_duration(dur_ms);

                Row::new(vec![
                    Cell::from(time_str),
                    Cell::from(proto).style(Style::default().fg(proto_color(proto))),
                    Cell::from("GET").style(Style::default().fg(method_color("GET"))),
                    Cell::from(host),
                    Cell::from(path),
                    Cell::from(status.to_string()).style(status_style(status)),
                    Cell::from(content_type.clone())
                        .style(Style::default().fg(content_type_color(&content_type))),
                    Cell::from(frame_str).style(Style::default().fg(Color::LightCyan)),
                    Cell::from(duration).style(Style::default().fg(duration_color(dur_ms))),
                ])
            }
            FlowEntry::Tcp { stream } => {
                let size = stream
                    .chunks
                    .iter()
                    .map(|chunk| chunk.payload.len())
                    .sum::<usize>();
                let status = if stream.closed { "closed" } else { "live" };
                Row::new(vec![
                    Cell::from(format_time(stream.opened_at)),
                    Cell::from("TCP").style(Style::default().fg(proto_color("TCP"))),
                    Cell::from("STREAM").style(Style::default().fg(Color::LightMagenta)),
                    Cell::from(stream.target.as_str()),
                    Cell::from("-"),
                    Cell::from(status).style(Style::default().fg(if stream.closed {
                        Color::DarkGray
                    } else {
                        Color::LightGreen
                    })),
                    Cell::from("binary").style(Style::default().fg(Color::DarkGray)),
                    Cell::from(format_size(size)).style(Style::default().fg(size_color(size))),
                    Cell::from(format!("{}ch", stream.chunks.len())),
                ])
            }
            FlowEntry::Dns { exchange } => {
                let status = if !exchange.completed {
                    "pending"
                } else if exchange.overridden {
                    "override"
                } else {
                    "upstream"
                };
                Row::new(vec![
                    Cell::from(format_time(exchange.time)),
                    Cell::from("DNS").style(Style::default().fg(proto_color("DNS"))),
                    Cell::from(dns_query_type(exchange.query_type))
                        .style(Style::default().fg(Color::LightBlue)),
                    Cell::from(exchange.name.as_str()),
                    Cell::from("-"),
                    Cell::from(status).style(Style::default().fg(if exchange.overridden {
                        Color::Yellow
                    } else {
                        Color::LightGreen
                    })),
                    Cell::from("dns"),
                    Cell::from(format!("{}ans", exchange.answers.len())),
                    Cell::from("-"),
                ])
            }
            FlowEntry::Udp { exchange } => {
                let size = exchange.request.len() + exchange.response.len();
                let status = if exchange.response_received {
                    "complete"
                } else {
                    "no-resp"
                };
                Row::new(vec![
                    Cell::from(format_time(exchange.time)),
                    Cell::from("UDP").style(Style::default().fg(proto_color("UDP"))),
                    Cell::from("DGRAM").style(Style::default().fg(Color::LightMagenta)),
                    Cell::from(exchange.target.as_str()),
                    Cell::from(exchange.client.as_str()),
                    Cell::from(status).style(Style::default().fg(if exchange.response_received {
                        Color::LightGreen
                    } else {
                        Color::Yellow
                    })),
                    Cell::from("binary").style(Style::default().fg(Color::DarkGray)),
                    Cell::from(format_size(size)).style(Style::default().fg(size_color(size))),
                    Cell::from("-"),
                ])
            }
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(5),
            Constraint::Length(7),
            Constraint::Percentage(18),
            Constraint::Percentage(30),
            Constraint::Length(6),
            Constraint::Percentage(18),
            Constraint::Length(7),
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

    if state.entries.is_empty() {
        if let Some(setup) = wireguard_setup {
            draw_wireguard_setup(f, chunks[0], setup);
        } else {
            f.render_stateful_widget(table, chunks[0], &mut visible_table_state);
        }
    } else {
        f.render_stateful_widget(table, chunks[0], &mut visible_table_state);
    }

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

fn visible_row_range(
    total: usize,
    selected: Option<usize>,
    current_offset: usize,
    capacity: usize,
) -> Range<usize> {
    if total == 0 {
        return 0..0;
    }
    let capacity = capacity.max(1).min(total);
    let max_start = total - capacity;
    let mut start = current_offset.min(max_start);
    if let Some(selected) = selected.map(|selected| selected.min(total - 1)) {
        if selected < start {
            start = selected;
        } else if selected >= start + capacity {
            start = selected + 1 - capacity;
        }
    }
    start..(start + capacity).min(total)
}

fn draw_wireguard_setup(f: &mut Frame, area: Rect, setup: &WireGuardSetup) {
    let block = Block::default().borders(Borders::ALL).title(format!(
        " Proxelar v{} ─ WireGuard setup ",
        env!("CARGO_PKG_VERSION")
    ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let qr_width = setup
        .terminal_lines()
        .iter()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(0);
    let content_height = setup.terminal_lines().len().saturating_add(4);
    if qr_width > inner.width as usize || content_height > inner.height as usize {
        let message = Paragraph::new(vec![
            Line::from("WireGuard profile is ready."),
            Line::from("Enlarge the terminal to display its QR code."),
            Line::from(format!("Config: {}", setup.config_path().display())),
        ])
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: false });
        f.render_widget(message, inner);
        return;
    }

    let centered = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(content_height as u16),
        Constraint::Fill(1),
    ])
    .split(inner)[1];
    let mut lines = vec![
        Line::from(format!(
            "Scan \"{}\" with the WireGuard app",
            setup.profile_name()
        )),
        Line::from(""),
    ];
    lines.extend(setup.terminal_lines().iter().map(|line| {
        Line::styled(
            line.as_str(),
            Style::default()
                .fg(Color::Rgb(0, 0, 0))
                .bg(Color::Rgb(255, 255, 255)),
        )
    }));
    lines.push(Line::from(""));
    lines.push(Line::from(
        "The QR disappears after the first captured flow.",
    ));
    let qr = Paragraph::new(lines).alignment(Alignment::Center);
    f.render_widget(qr, centered);
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
                    DetailTab::Request => {
                        (build_request_lines(request), state.detail_scroll as u16)
                    }
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
            FlowEntry::Tcp { stream } => {
                let detail = Paragraph::new(build_tcp_lines(stream))
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(" Raw TCP stream ")
                            .border_style(border_style),
                    )
                    .scroll((state.detail_scroll as u16, 0))
                    .wrap(Wrap { trim: false });
                f.render_widget(detail, area);
            }
            FlowEntry::Dns { exchange } => {
                let detail = Paragraph::new(build_dns_lines(exchange))
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(" DNS exchange ")
                            .border_style(border_style),
                    )
                    .scroll((state.detail_scroll as u16, 0))
                    .wrap(Wrap { trim: false });
                f.render_widget(detail, area);
            }
            FlowEntry::Udp { exchange } => {
                let detail = Paragraph::new(build_udp_lines(exchange))
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(" UDP exchange ")
                            .border_style(border_style),
                    )
                    .scroll((state.detail_scroll as u16, 0))
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
            " \u{270e} Editing Request (structured binary/hex body) — Esc when done "
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

    for field in request.headers() {
        lines.push(Line::from(vec![
            Span::styled(
                String::from_utf8_lossy(field.name()).into_owned(),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw(": "),
            Span::raw(String::from_utf8_lossy(field.value()).into_owned()),
        ]));
    }

    if !request.body().is_empty() {
        lines.push(Line::from(""));
        let metadata = request.body_metadata();
        if metadata.truncated {
            lines.push(Line::from(Span::styled(
                format!(
                    "[truncated: captured {} of {} wire bytes]",
                    request.body().len(),
                    metadata.total_seen
                ),
                Style::default().fg(Color::Yellow),
            )));
        }
        lines.push(Line::from(render_body(request.headers(), request.body())));
    }

    lines
}

fn build_response_lines(response: &proxyapi_models::ProxiedResponse) -> Vec<Line<'static>> {
    let status = response.status();

    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                status.to_string(),
                status_style(status.as_u16()).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::raw(format!("{:?}", response.version())),
        ]),
        Line::from(""),
    ];

    for field in response.headers() {
        lines.push(Line::from(vec![
            Span::styled(
                String::from_utf8_lossy(field.name()).into_owned(),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw(": "),
            Span::raw(String::from_utf8_lossy(field.value()).into_owned()),
        ]));
    }

    if !response.body().is_empty() {
        lines.push(Line::from(""));
        let metadata = response.body_metadata();
        if metadata.truncated {
            lines.push(Line::from(Span::styled(
                format!(
                    "[truncated: captured {} of {} wire bytes]",
                    response.body().len(),
                    metadata.total_seen
                ),
                Style::default().fg(Color::Yellow),
            )));
        }
        lines.push(Line::from(render_body(response.headers(), response.body())));
    }

    lines
}

fn render_body(headers: &HeaderBlock, body: &[u8]) -> String {
    match proxyapi::content::content_view(headers, body) {
        Ok(view) => view.text,
        Err(error) => format!(
            "[content decoding failed: {error}]\n{}",
            String::from_utf8_lossy(body)
        ),
    }
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

fn build_tcp_lines(stream: &CapturedTcpStream) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(vec![
            Span::styled("Target: ", Style::default().fg(Color::Cyan)),
            Span::raw(stream.target.clone()),
        ]),
        Line::from(format!(
            "State: {} · {} chunks",
            if stream.closed { "closed" } else { "live" },
            stream.chunks.len()
        )),
        Line::from(""),
    ];
    for chunk in &stream.chunks {
        let (symbol, color) = match chunk.direction {
            StreamDirection::ClientToServer => ("↑", Color::Yellow),
            StreamDirection::ServerToClient => ("↓", Color::Cyan),
        };
        let text_preview = std::str::from_utf8(&chunk.payload)
            .ok()
            .filter(|value| !value.chars().any(char::is_control))
            .map(|value| value.chars().take(160).collect::<String>());
        let preview = text_preview.unwrap_or_else(|| {
            chunk
                .payload
                .iter()
                .take(48)
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(" ")
        });
        lines.push(Line::from(vec![
            Span::styled(symbol, Style::default().fg(color)),
            Span::raw(format!(
                " {} {}B{} ",
                format_time(chunk.time),
                chunk.payload.len(),
                if chunk.truncated {
                    " [capture limit]"
                } else {
                    ""
                }
            )),
            Span::raw(preview),
        ]));
    }
    lines
}

fn build_dns_lines(exchange: &CapturedDnsExchange) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                dns_query_type(exchange.query_type),
                Style::default()
                    .fg(Color::LightBlue)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::raw(exchange.name.clone()),
        ]),
        Line::from(format!(
            "Source: {} · State: {}",
            if exchange.overridden {
                "local override"
            } else {
                "upstream resolver"
            },
            if exchange.completed {
                "complete"
            } else {
                "pending"
            }
        )),
        Line::from(""),
    ];
    if exchange.answers.is_empty() {
        lines.push(Line::from("No IP answers"));
    } else {
        lines.extend(
            exchange
                .answers
                .iter()
                .map(|answer| Line::from(format!("• {answer}"))),
        );
    }
    lines
}

fn build_udp_lines(exchange: &CapturedUdpExchange) -> Vec<Line<'static>> {
    vec![
        Line::from(vec![
            Span::styled("Client: ", Style::default().fg(Color::Cyan)),
            Span::raw(exchange.client.clone()),
        ]),
        Line::from(vec![
            Span::styled("Target: ", Style::default().fg(Color::Cyan)),
            Span::raw(exchange.target.clone()),
        ]),
        Line::from(format!(
            "Request: {}B{}",
            exchange.request.len(),
            if exchange.request_truncated {
                " [capture limit]"
            } else {
                ""
            }
        )),
        Line::from(hex_preview(&exchange.request)),
        Line::from(""),
        Line::from(format!(
            "Response: {}B{}",
            exchange.response.len(),
            if exchange.response_truncated {
                " [capture limit]"
            } else {
                ""
            }
        )),
        Line::from(hex_preview(&exchange.response)),
    ]
}

fn hex_preview(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "[no payload]".to_owned();
    }
    bytes
        .iter()
        .take(512)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn dns_query_type(query_type: u16) -> &'static str {
    match query_type {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        65 => "HTTPS",
        _ => "OTHER",
    }
}

fn format_time(millis: i64) -> String {
    Local
        .timestamp_millis_opt(millis)
        .single()
        .map(|dt| dt.format("%H:%M:%S").to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn path_and_query(uri: &Uri) -> String {
    uri.path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| uri.path().to_owned())
}

fn proto_from_uri(uri: &Uri, is_ws: bool) -> &'static str {
    let tls = matches!(uri.scheme_str(), Some("https") | Some("wss"));
    match (is_ws, tls) {
        (true, true) => "WSS",
        (true, false) => "WS",
        (false, true) => "HTTPS",
        (false, false) => "HTTP",
    }
}

fn abbrev_content_type(headers: &HeaderBlock) -> String {
    headers
        .get(http::header::CONTENT_TYPE.as_str())
        .and_then(|value| std::str::from_utf8(value).ok())
        .map(|s| s.split(';').next().unwrap_or(s).trim().to_owned())
        .unwrap_or_else(|| "[no content]".to_owned())
}

fn format_duration(ms: i64) -> String {
    if ms < 0 {
        return "-".to_string();
    }
    if ms >= 1000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        format!("{ms}ms")
    }
}

fn proto_color(proto: &str) -> Color {
    match proto {
        "HTTPS" => Color::LightGreen,
        "WSS" => Color::LightCyan,
        "HTTP" => Color::Yellow,
        "WS" => Color::LightMagenta,
        "TCP" => Color::LightBlue,
        "UDP" => Color::LightCyan,
        "DNS" => Color::LightMagenta,
        _ => Color::White,
    }
}

fn method_color(method: &str) -> Color {
    match method {
        "GET" => Color::LightGreen,
        "POST" => Color::Yellow,
        "PUT" => Color::LightBlue,
        "DELETE" => Color::LightRed,
        "PATCH" => Color::LightMagenta,
        "HEAD" | "OPTIONS" => Color::Gray,
        _ => Color::White,
    }
}

fn status_style(status: u16) -> Style {
    match status {
        100..=199 => Style::default().fg(Color::Gray),
        200..=299 => Style::default().fg(Color::LightGreen),
        300..=399 => Style::default().fg(Color::LightBlue),
        400..=499 => Style::default().fg(Color::LightRed),
        500..=599 => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        _ => Style::default().fg(Color::White),
    }
}

fn content_type_color(ct: &str) -> Color {
    if ct == "[no content]" {
        return Color::DarkGray;
    }
    let base = ct.split(';').next().unwrap_or(ct).trim();
    match base {
        t if t.contains("json") => Color::LightCyan,
        t if t.starts_with("text/html") => Color::LightYellow,
        t if t.contains("javascript") || t.contains("ecmascript") => Color::LightBlue,
        t if t.starts_with("text/css") => Color::LightMagenta,
        t if t.starts_with("text/") => Color::Gray,
        t if t.starts_with("image/") => Color::Magenta,
        t if t.starts_with("font/") => Color::Blue,
        t if t.contains("xml") => Color::Cyan,
        t if t.starts_with("multipart/") => Color::Yellow,
        t if t.starts_with("application/octet-stream") => Color::DarkGray,
        _ => Color::White,
    }
}

fn size_color(bytes: usize) -> Color {
    match bytes {
        0 => Color::DarkGray,
        1..=1_023 => Color::Gray,
        1_024..=10_239 => Color::White,
        10_240..=102_399 => Color::LightYellow,
        102_400..=1_048_575 => Color::Yellow,
        _ => Color::LightRed,
    }
}

fn duration_color(ms: i64) -> Color {
    match ms {
        ms if ms < 0 => Color::DarkGray,
        0..=99 => Color::LightGreen,
        100..=299 => Color::Green,
        300..=699 => Color::Yellow,
        700..=1_999 => Color::LightRed,
        _ => Color::Red,
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
        ("time / proto / method / host", "Recognised column names"),
        (
            "path / status / type / size / duration",
            "Recognised column names (cont.)",
        ),
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

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{Method, StatusCode, Version};
    use proxyapi_models::{HeaderBlock, ProxiedRequest, ProxiedResponse};
    use ratatui::{backend::TestBackend, buffer::Buffer, Terminal};

    fn request(method: Method, uri: &str, body: Bytes, time: i64) -> Box<ProxiedRequest> {
        let mut headers = HeaderBlock::new();
        headers.add("content-type", "application/json").unwrap();
        headers.add("x-test", "ui").unwrap();
        Box::new(ProxiedRequest::new(
            method,
            uri.parse().unwrap(),
            Version::HTTP_11,
            headers,
            body,
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

    fn render(state: &mut AppState) -> String {
        render_with_setup(state, None)
    }

    fn render_with_setup(state: &mut AppState, wireguard_setup: Option<&WireGuardSetup>) -> String {
        let backend = TestBackend::new(160, 42);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| draw(frame, state, wireguard_setup))
            .unwrap();
        buffer_text(terminal.backend().buffer())
    }

    fn buffer_text(buffer: &Buffer) -> String {
        buffer
            .content
            .chunks(buffer.area.width as usize)
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn visible_rows_are_bounded_and_follow_selection() {
        assert_eq!(visible_row_range(0, None, 0, 10), 0..0);
        assert_eq!(visible_row_range(5, None, 0, 10), 0..5);
        assert_eq!(visible_row_range(10_000, None, 0, 20), 0..20);
        assert_eq!(visible_row_range(100, Some(75), 0, 20), 56..76);
        assert_eq!(visible_row_range(100, Some(10), 56, 20), 10..30);
        assert_eq!(visible_row_range(100, Some(99), 90, 20), 80..100);
    }

    #[test]
    fn format_and_color_helpers_cover_protocol_status_size_duration_variants() {
        let http_uri: Uri = "http://example.test/path?q=1".parse().unwrap();
        let https_uri: Uri = "https://secure.test/".parse().unwrap();
        let wss_uri: Uri = "wss://socket.test/live".parse().unwrap();

        assert_eq!(path_and_query(&http_uri), "/path?q=1");
        assert_eq!(proto_from_uri(&http_uri, false), "HTTP");
        assert_eq!(proto_from_uri(&https_uri, false), "HTTPS");
        assert_eq!(proto_from_uri(&http_uri, true), "WS");
        assert_eq!(proto_from_uri(&wss_uri, true), "WSS");

        assert_eq!(format_duration(-1), "-");
        assert_eq!(format_duration(42), "42ms");
        assert_eq!(format_duration(1_250), "1.2s");
        assert_eq!(format_time(i64::MAX), "-");

        assert_eq!(proto_color("HTTPS"), Color::LightGreen);
        assert_eq!(proto_color("WSS"), Color::LightCyan);
        assert_eq!(proto_color("HTTP"), Color::Yellow);
        assert_eq!(proto_color("WS"), Color::LightMagenta);
        assert_eq!(proto_color("OTHER"), Color::White);

        assert_eq!(method_color("GET"), Color::LightGreen);
        assert_eq!(method_color("POST"), Color::Yellow);
        assert_eq!(method_color("PUT"), Color::LightBlue);
        assert_eq!(method_color("DELETE"), Color::LightRed);
        assert_eq!(method_color("PATCH"), Color::LightMagenta);
        assert_eq!(method_color("HEAD"), Color::Gray);
        assert_eq!(method_color("CUSTOM"), Color::White);

        assert_eq!(content_type_color("[no content]"), Color::DarkGray);
        assert_eq!(content_type_color("application/json"), Color::LightCyan);
        assert_eq!(content_type_color("text/html"), Color::LightYellow);
        assert_eq!(content_type_color("text/css"), Color::LightMagenta);
        assert_eq!(content_type_color("image/png"), Color::Magenta);
        assert_eq!(content_type_color("font/woff2"), Color::Blue);
        assert_eq!(content_type_color("application/xml"), Color::Cyan);
        assert_eq!(content_type_color("multipart/form-data"), Color::Yellow);
        assert_eq!(
            content_type_color("application/octet-stream"),
            Color::DarkGray
        );
        assert_eq!(content_type_color("application/x-custom"), Color::White);

        assert_eq!(size_color(0), Color::DarkGray);
        assert_eq!(size_color(512), Color::Gray);
        assert_eq!(size_color(2_048), Color::White);
        assert_eq!(size_color(20_000), Color::LightYellow);
        assert_eq!(size_color(200_000), Color::Yellow);
        assert_eq!(size_color(2_000_000), Color::LightRed);

        assert_eq!(duration_color(-1), Color::DarkGray);
        assert_eq!(duration_color(50), Color::LightGreen);
        assert_eq!(duration_color(150), Color::Green);
        assert_eq!(duration_color(500), Color::Yellow);
        assert_eq!(duration_color(1_000), Color::LightRed);
        assert_eq!(duration_color(3_000), Color::Red);

        assert_eq!(status_style(100).fg, Some(Color::Gray));
        assert_eq!(status_style(204).fg, Some(Color::LightGreen));
        assert_eq!(status_style(302).fg, Some(Color::LightBlue));
        assert_eq!(status_style(404).fg, Some(Color::LightRed));
        assert_eq!(status_style(503).fg, Some(Color::Red));
        assert_eq!(status_style(700).fg, Some(Color::White));
    }

    #[test]
    fn build_detail_lines_include_headers_bodies_and_frame_states() {
        let req = request(
            Method::PATCH,
            "https://api.test/items",
            Bytes::from_static(b"{\"ok\":true}"),
            0,
        );
        let res = response(
            StatusCode::CREATED,
            Some("application/json; charset=utf-8"),
            Bytes::from_static(b"created"),
            100,
        );
        let mut frames = VecDeque::new();
        frames.push_back(WsFrame::new(
            WsDirection::ClientToServer,
            WsOpcode::Text,
            1,
            Bytes::from_static(b"hello websocket"),
            false,
        ));
        frames.push_back(WsFrame::new(
            WsDirection::ServerToClient,
            WsOpcode::Binary,
            2,
            Bytes::from_static(&[0, 1, 2, 3]),
            true,
        ));
        frames.push_back(WsFrame::new(
            WsDirection::ServerToClient,
            WsOpcode::Pong,
            3,
            Bytes::from_static(b"pong"),
            false,
        ));

        assert!(build_request_lines(&req)
            .iter()
            .any(|line| line.to_string().contains("PATCH")));
        assert!(build_response_lines(&res)
            .iter()
            .any(|line| line.to_string().contains("201")));
        assert!(abbrev_content_type(res.headers()).contains("application/json"));

        let open_empty = build_frames_lines(&VecDeque::new(), false, 0, false);
        assert_eq!(open_empty[0].to_string(), "Waiting for frames...");
        let closed_empty = build_frames_lines(&VecDeque::new(), true, 0, false);
        assert_eq!(
            closed_empty[0].to_string(),
            "No frames captured (connection closed)"
        );

        let followed = build_frames_lines(&frames, false, 0, true);
        let followed_text = followed
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(followed_text.contains("hello websocket"));
        assert!(followed_text.contains("[trunc]"));
        assert!(followed_text.contains("[FOLLOW]"));

        let closed = build_frames_lines(&frames, true, 1, false);
        let closed_text = closed
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(closed_text.contains("00 01 02 03"));
        assert!(closed_text.contains("Connection closed"));
    }

    #[test]
    fn draw_renders_complete_response_detail_and_websocket_frames() {
        let mut state = AppState::new();
        state.entries.push_back(FlowEntry::Complete {
            request: request(
                Method::GET,
                "https://api.test/items?q=1",
                Bytes::new(),
                1_000,
            ),
            response: response(
                StatusCode::OK,
                Some("application/json"),
                Bytes::from_static(b"{\"items\":[]}"),
                1_050,
            ),
        });
        state.entries.push_back(FlowEntry::WebSocket {
            id: 2,
            request: request(Method::GET, "wss://socket.test/live", Bytes::new(), 2_000),
            _response: response(StatusCode::SWITCHING_PROTOCOLS, None, Bytes::new(), 2_010),
            frames: VecDeque::from([
                WsFrame::new(
                    WsDirection::ClientToServer,
                    WsOpcode::Text,
                    2_020,
                    Bytes::from_static(b"client"),
                    false,
                ),
                WsFrame::new(
                    WsDirection::ServerToClient,
                    WsOpcode::Ping,
                    2_021,
                    Bytes::from_static(b"ping"),
                    false,
                ),
                WsFrame::new(
                    WsDirection::ServerToClient,
                    WsOpcode::Close,
                    2_022,
                    Bytes::new(),
                    false,
                ),
            ]),
            closed: true,
        });
        state.detail_open = true;
        state.table_state.select(Some(0));

        let rendered = render(&mut state);
        assert!(rendered.contains("Proxelar"));
        assert!(rendered.contains("api.test"));
        assert!(rendered.contains("GET"));

        state.detail_tab = DetailTab::Response;
        let rendered = render(&mut state);
        assert!(rendered.contains("application/json"));
        assert!(rendered.contains("\"items\": []"));

        state.table_state.select(Some(1));
        state.detail_tab = DetailTab::Response;
        let rendered = render(&mut state);
        assert!(rendered.contains("socket.test"));
        assert!(rendered.contains("client"));
        assert!(rendered.contains("Connection closed"));
    }

    #[test]
    fn draw_shows_wireguard_qr_only_while_capture_is_empty() {
        let setup = WireGuardSetup::from_bytes(
            "proxelar-wg".to_owned(),
            std::path::PathBuf::from("/tmp/proxelar-wg.conf"),
            b"[Interface]\nPrivateKey = test\n\n[Peer]\nPublicKey = peer\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n",
        )
        .unwrap();
        let mut state = AppState::new();

        let rendered = render_with_setup(&mut state, Some(&setup));
        assert!(rendered.contains("WireGuard setup"));
        assert!(rendered.contains("Scan \"proxelar-wg\""));

        let backend = TestBackend::new(160, 42);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| draw(frame, &mut state, Some(&setup)))
            .unwrap();
        let dark_module = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .find(|cell| cell.symbol() == "█")
            .expect("QR code should contain a dark module");
        assert_eq!(dark_module.fg, Color::Rgb(0, 0, 0));
        assert_eq!(dark_module.bg, Color::Rgb(255, 255, 255));

        state.entries.push_back(FlowEntry::Error {
            message: "captured error".to_owned(),
        });
        let rendered = render_with_setup(&mut state, Some(&setup));
        assert!(!rendered.contains("Scan \"proxelar-wg\""));
        assert!(rendered.contains("captured error"));
    }

    #[test]
    fn draw_renders_pending_error_filter_help_and_editor_states() {
        let mut state = AppState::new();
        state.entries.push_back(FlowEntry::Pending {
            id: 10,
            request: request(
                Method::POST,
                "http://pending.test/submit",
                Bytes::from_static(b"body"),
                1,
            ),
        });
        state.entries.push_back(FlowEntry::Error {
            message: "proxy failed".to_owned(),
        });
        state.table_state.select(Some(0));
        state.detail_open = true;
        state.intercept_enabled = true;
        state.filter_mode = true;
        state.filter_input = "status:500".to_owned();
        state.show_help = true;

        let rendered = render(&mut state);
        assert!(rendered.contains("Intercepted Request"));
        assert!(rendered.contains("Filter: status:500_"));
        assert!(rendered.contains("Keybindings"));

        state.show_help = false;
        state.filter_mode = false;
        state.edit_session = Some(EditSession {
            id: 10,
            lines: vec!["GET / HTTP/1.1".to_owned(), "Host: example.test".to_owned()],
            cursor_row: 0,
            cursor_col: 3,
            scroll: 0,
            typing: true,
            parse_error: false,
            binary_body: false,
        });

        let rendered = render(&mut state);
        assert!(rendered.contains("Editing Request"));
        assert!(rendered.contains("Host: example.test"));

        let session = state.edit_session.as_mut().unwrap();
        session.typing = false;
        session.parse_error = true;
        session.binary_body = true;
        let rendered = render(&mut state);
        assert!(rendered.contains("parse error"));
        assert!(rendered.contains("fix the request line"));

        state.edit_session = None;
        state.table_state.select(Some(1));
        let rendered = render(&mut state);
        assert!(rendered.contains("proxy failed"));
    }

    #[test]
    fn centered_rect_returns_area_inside_parent() {
        let parent = Rect::new(0, 0, 100, 40);
        let area = centered_rect(50, 50, parent);

        assert_eq!(area.x, 25);
        assert_eq!(area.y, 10);
        assert_eq!(area.width, 50);
        assert_eq!(area.height, 20);
    }
}
