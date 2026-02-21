mod event;
mod handler;
mod state;
mod ui;

use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use proxyapi::ProxyEvent;
use ratatui::prelude::*;
use std::io;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use event::{spawn_event_loop, AppEvent};
use handler::handle_key_event;
use state::AppState;
use ui::draw;

/// Guard that restores the terminal on drop, even during panics.
struct RawModeGuard;

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

pub async fn run(event_rx: mpsc::Receiver<ProxyEvent>, cancel: CancellationToken) {
    if let Err(e) = run_inner(event_rx, cancel).await {
        eprintln!("TUI error: {e}");
    }
}

async fn run_inner(
    event_rx: mpsc::Receiver<ProxyEvent>,
    cancel: CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let _guard = RawModeGuard;

    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = AppState::new();
    let mut app_events = spawn_event_loop(event_rx);

    loop {
        let event = tokio::select! {
            event = app_events.recv() => match event {
                Some(e) => e,
                None => break,
            },
            () = cancel.cancelled() => break,
        };

        match event {
            AppEvent::Input(key_event) => {
                if handle_key_event(key_event, &mut state) {
                    break;
                }
            }
            AppEvent::Proxy(proxy_event) => {
                state.add_event(proxy_event);
            }
            AppEvent::Render => {
                terminal.draw(|f| draw(f, &mut state))?;
            }
        }
    }

    // RawModeGuard handles cleanup on drop
    Ok(())
}
