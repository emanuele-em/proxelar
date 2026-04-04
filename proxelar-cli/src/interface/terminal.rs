use crossterm::style::{Color, Stylize};
use proxyapi::ProxyEvent;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::interface::format_size;

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

        match &event {
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

                println!("[{now}] #{id} {method_colored} {status_colored} {uri} ({size})");
            }
            ProxyEvent::RequestIntercepted { .. } => {
                // Terminal mode does not support interactive intercept;
                // intercept is disabled when running in terminal mode.
            }
            ProxyEvent::Error { message } => {
                eprintln!(
                    "[{}] {}",
                    chrono::Local::now().format("%H:%M:%S"),
                    message.as_str().with(Color::Red)
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(512), "512B");
        assert_eq!(format_size(2048), "2.0KB");
        assert_eq!(format_size(1048576), "1.0MB");
    }
}
