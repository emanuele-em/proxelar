use proxyapi::ProxyEvent;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap},
    Frame,
};

use super::state::{matches_filter, AppState, DetailTab};
use crate::interface::format_size;

pub fn draw(f: &mut Frame, state: &mut AppState) {
    // Use direct field access so the borrow checker can split the borrows:
    // `state.requests` + `state.filter` are borrowed immutably while
    // `state.table_state` remains available for mutable access later.
    let filter = state.filter.as_deref();
    let filtered: Vec<(usize, &ProxyEvent)> = state
        .requests
        .iter()
        .enumerate()
        .filter(|(_, event)| matches_filter(event, filter))
        .collect();
    let req_count = filtered.len();

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
        .map(|(_idx, event)| match event {
            ProxyEvent::RequestComplete {
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

                let method_color = match method {
                    "GET" => Color::Green,
                    "POST" => Color::Yellow,
                    "PUT" => Color::Blue,
                    "DELETE" => Color::Red,
                    "PATCH" => Color::Magenta,
                    _ => Color::White,
                };

                let status_color = match status {
                    200..=299 => Color::Green,
                    300..=399 => Color::Cyan,
                    400..=499 => Color::Yellow,
                    500..=599 => Color::Red,
                    _ => Color::White,
                };

                Row::new(vec![
                    Cell::from(id.to_string()),
                    Cell::from(method).style(Style::default().fg(method_color)),
                    Cell::from(status.to_string()).style(Style::default().fg(status_color)),
                    Cell::from(host),
                    Cell::from(path),
                    Cell::from(size),
                ])
            }
            ProxyEvent::Error { message } => Row::new(vec![
                Cell::from(_idx.to_string()),
                Cell::from("ERR").style(Style::default().fg(Color::Red)),
                Cell::from("-"),
                Cell::from(message.as_str()),
                Cell::from("-"),
                Cell::from("-"),
            ]),
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(5),
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
        draw_detail(f, state, chunks[1], &filtered);
    }

    // Status bar
    let status_chunk = if state.detail_open && chunks.len() > 2 {
        chunks[2]
    } else {
        chunks[1]
    };

    let status_text = if state.filter_mode {
        format!(" Filter: {}_ ", state.filter_input)
    } else if let Some(ref filter) = state.filter {
        format!(
            " q:quit  /:filter  j/k:nav  Enter:details  Tab:req/res  c:clear | Filter: {filter} "
        )
    } else {
        " q:quit  /:filter  j/k:nav  Enter:details  Tab:req/res  g/G:top/bottom  c:clear ".into()
    };

    let status_bar = Paragraph::new(status_text.as_str())
        .style(Style::default().bg(Color::DarkGray).fg(Color::White));
    f.render_widget(status_bar, status_chunk);
}

fn draw_detail(f: &mut Frame, state: &AppState, area: Rect, filtered: &[(usize, &ProxyEvent)]) {
    let selected = state.table_state.selected().unwrap_or(0);

    if let Some((_, event)) = filtered.get(selected) {
        match event {
            ProxyEvent::RequestComplete {
                request, response, ..
            } => {
                let tab_title = match state.detail_tab {
                    DetailTab::Request => " [Request] Response ",
                    DetailTab::Response => " Request [Response] ",
                };

                let content = match state.detail_tab {
                    DetailTab::Request => {
                        let mut lines = vec![
                            Line::from(vec![
                                Span::styled(
                                    request.method().as_str(),
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
                                Span::styled(name.as_str(), Style::default().fg(Color::Cyan)),
                                Span::raw(": "),
                                Span::raw(String::from_utf8_lossy(value.as_bytes())),
                            ]));
                        }

                        if !request.body().is_empty() {
                            lines.push(Line::from(""));
                            lines.push(Line::from(String::from_utf8_lossy(request.body())));
                        }

                        lines
                    }
                    DetailTab::Response => {
                        let status = response.status();
                        let status_color = match status.as_u16() {
                            200..=299 => Color::Green,
                            300..=399 => Color::Cyan,
                            400..=499 => Color::Yellow,
                            500..=599 => Color::Red,
                            _ => Color::White,
                        };

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
                                Span::styled(name.as_str(), Style::default().fg(Color::Cyan)),
                                Span::raw(": "),
                                Span::raw(String::from_utf8_lossy(value.as_bytes())),
                            ]));
                        }

                        if !response.body().is_empty() {
                            lines.push(Line::from(""));
                            lines.push(Line::from(String::from_utf8_lossy(response.body())));
                        }

                        lines
                    }
                };

                let detail = Paragraph::new(content)
                    .block(Block::default().borders(Borders::ALL).title(tab_title))
                    .wrap(Wrap { trim: false });

                f.render_widget(detail, area);
            }
            ProxyEvent::Error { message } => {
                let detail = Paragraph::new(message.as_str())
                    .block(Block::default().borders(Borders::ALL).title(" Error "))
                    .wrap(Wrap { trim: false });
                f.render_widget(detail, area);
            }
        }
    }
}
