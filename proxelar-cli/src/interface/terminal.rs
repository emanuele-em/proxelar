use crossterm::style::{Color, Stylize};
use proxyapi::ProxyEvent;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::interface::format_size;

enum TerminalOutput {
    Stdout(String),
    Stderr(String),
    Ignore,
}

pub async fn run(mut event_rx: mpsc::Receiver<ProxyEvent>, cancel: CancellationToken) {
    println!("{}", "Proxelar proxy running. Press Ctrl+C to stop.".bold());
    println!();

    loop {
        let event = tokio::select! {
            event = event_rx.recv() => match event {
                Some(e) => e,
                None => break,
            },
            () = cancel.cancelled() => break,
        };

        match render_event(&event) {
            TerminalOutput::Stdout(line) => println!("{line}"),
            TerminalOutput::Stderr(line) => eprintln!("{line}"),
            TerminalOutput::Ignore => {}
        }
    }
}

fn render_event(event: &ProxyEvent) -> TerminalOutput {
    match event {
        ProxyEvent::RequestComplete {
            id,
            request,
            response,
        } => {
            let now = chrono::Local::now().format("%H:%M:%S");
            let method = request.method().as_str();
            let status = response.status().as_u16();
            let uri = request.uri().to_string();
            let body_len = response.body().len();

            let method_colored = match method {
                "GET" => method.with(Color::Green),
                "POST" => method.with(Color::Yellow),
                "PUT" => method.with(Color::Blue),
                "DELETE" => method.with(Color::Red),
                "PATCH" => method.with(Color::Magenta),
                _ => method.with(Color::White),
            };

            let status_colored = match status {
                200..=299 => status.to_string().with(Color::Green),
                300..=399 => status.to_string().with(Color::Cyan),
                400..=499 => status.to_string().with(Color::Yellow),
                500..=599 => status.to_string().with(Color::Red),
                _ => status.to_string().with(Color::White),
            };

            let size = format_size(body_len);

            TerminalOutput::Stdout(format!(
                "[{now}] #{id} {method_colored} {status_colored} {uri} ({size})"
            ))
        }
        ProxyEvent::RequestIntercepted { .. } => {
            // Terminal mode does not support interactive intercept;
            // intercept is disabled when running in terminal mode.
            TerminalOutput::Ignore
        }
        ProxyEvent::Error { message } => TerminalOutput::Stderr(format!(
            "[{}] {}",
            chrono::Local::now().format("%H:%M:%S"),
            message.as_str().with(Color::Red)
        )),
        ProxyEvent::WebSocketConnected { id, request, .. } => {
            let now = chrono::Local::now().format("%H:%M:%S");
            let uri = request.uri().to_string();
            TerminalOutput::Stdout(format!(
                "[{now}] #{id} {} WS\u{21c4} {uri}",
                "GET".with(Color::Green)
            ))
        }
        ProxyEvent::WebSocketFrame { .. } | ProxyEvent::WebSocketClosed { .. } => {
            TerminalOutput::Ignore
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{HeaderMap, Method, StatusCode, Version};
    use proxyapi_models::{ProxiedRequest, ProxiedResponse, WsDirection, WsFrame, WsOpcode};

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(512), "512B");
        assert_eq!(format_size(2048), "2.0KB");
        assert_eq!(format_size(1048576), "1.0MB");
    }

    #[test]
    fn render_event_formats_terminal_output_and_ignores_internal_events() {
        let request = Box::new(ProxiedRequest::new(
            Method::GET,
            "http://api.test/terminal".parse().unwrap(),
            Version::HTTP_11,
            HeaderMap::new(),
            Bytes::new(),
            1,
        ));
        let response = Box::new(ProxiedResponse::new(
            StatusCode::OK,
            Version::HTTP_11,
            HeaderMap::new(),
            Bytes::from_static(b"ok"),
            2,
        ));

        match render_event(&ProxyEvent::RequestComplete {
            id: 7,
            request: request.clone(),
            response: response.clone(),
        }) {
            TerminalOutput::Stdout(line) => {
                assert!(line.contains("#7"));
                assert!(line.contains("GET"));
                assert!(line.contains("200"));
                assert!(line.contains("http://api.test/terminal"));
                assert!(line.contains("(2B)"));
            }
            TerminalOutput::Stderr(_) | TerminalOutput::Ignore => {
                panic!("expected request completion on stdout")
            }
        }

        match render_event(&ProxyEvent::WebSocketConnected {
            id: 8,
            request: request.clone(),
            response,
        }) {
            TerminalOutput::Stdout(line) => {
                assert!(line.contains("#8"));
                assert!(line.contains("WS\u{21c4}"));
                assert!(line.contains("http://api.test/terminal"));
            }
            TerminalOutput::Stderr(_) | TerminalOutput::Ignore => {
                panic!("expected websocket connection on stdout")
            }
        }

        match render_event(&ProxyEvent::Error {
            message: "terminal error".to_owned(),
        }) {
            TerminalOutput::Stderr(line) => assert!(line.contains("terminal error")),
            TerminalOutput::Stdout(_) | TerminalOutput::Ignore => {
                panic!("expected error on stderr")
            }
        }

        assert!(matches!(
            render_event(&ProxyEvent::RequestIntercepted { id: 9, request }),
            TerminalOutput::Ignore
        ));
        assert!(matches!(
            render_event(&ProxyEvent::WebSocketClosed { conn_id: 8 }),
            TerminalOutput::Ignore
        ));
    }

    #[tokio::test]
    async fn run_consumes_terminal_supported_events_until_channel_closes() {
        let (tx, rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let request = Box::new(ProxiedRequest::new(
            Method::GET,
            "http://api.test/terminal".parse().unwrap(),
            Version::HTTP_11,
            HeaderMap::new(),
            Bytes::new(),
            1,
        ));
        let response = Box::new(ProxiedResponse::new(
            StatusCode::OK,
            Version::HTTP_11,
            HeaderMap::new(),
            Bytes::from_static(b"ok"),
            2,
        ));

        tx.send(ProxyEvent::RequestComplete {
            id: 1,
            request: request.clone(),
            response,
        })
        .await
        .unwrap();
        tx.send(ProxyEvent::RequestIntercepted {
            id: 2,
            request: request.clone(),
        })
        .await
        .unwrap();
        tx.send(ProxyEvent::WebSocketConnected {
            id: 3,
            request,
            response: Box::new(ProxiedResponse::new(
                StatusCode::SWITCHING_PROTOCOLS,
                Version::HTTP_11,
                HeaderMap::new(),
                Bytes::new(),
                3,
            )),
        })
        .await
        .unwrap();
        tx.send(ProxyEvent::WebSocketFrame {
            conn_id: 3,
            frame: Box::new(WsFrame::new(
                WsDirection::ClientToServer,
                WsOpcode::Text,
                4,
                Bytes::from_static(b"hello"),
                false,
            )),
        })
        .await
        .unwrap();
        tx.send(ProxyEvent::WebSocketClosed { conn_id: 3 })
            .await
            .unwrap();
        tx.send(ProxyEvent::Error {
            message: "terminal error".to_owned(),
        })
        .await
        .unwrap();
        drop(tx);

        tokio::time::timeout(std::time::Duration::from_secs(1), run(rx, cancel))
            .await
            .unwrap();
    }
}
