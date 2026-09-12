mod handler;
mod state;
mod ui;

use crossterm::{
    event::{Event, EventStream},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures::StreamExt as _;
use proxyapi::{InterceptConfig, ProxyEvent};
use proxyapi_models::ProxiedRequest;
use ratatui::prelude::*;
use std::io;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::wireguard_setup::WireGuardSetup;
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

pub async fn run(
    event_rx: mpsc::Receiver<ProxyEvent>,
    intercept: Arc<InterceptConfig>,
    replay_tx: mpsc::Sender<ProxiedRequest>,
    wireguard_setup: Option<Arc<WireGuardSetup>>,
    cancel: CancellationToken,
) {
    if let Err(e) = run_inner(event_rx, intercept, replay_tx, wireguard_setup, cancel).await {
        eprintln!("TUI error: {e}");
    }
}

async fn run_inner(
    mut event_rx: mpsc::Receiver<ProxyEvent>,
    intercept: Arc<InterceptConfig>,
    replay_tx: mpsc::Sender<ProxiedRequest>,
    wireguard_setup: Option<Arc<WireGuardSetup>>,
    cancel: CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let _guard = RawModeGuard;

    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = AppState::new();
    let mut terminal_events = EventStream::new();
    let mut render_interval = tokio::time::interval(tokio::time::Duration::from_millis(50));
    render_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut dirty = true;

    loop {
        tokio::select! {
            proxy_event = event_rx.recv() => match proxy_event {
                Some(proxy_event) => {
                    state.add_event(proxy_event);
                    dirty = true;
                }
                None => break,
            },
            terminal_event = terminal_events.next() => match terminal_event {
                Some(Ok(Event::Key(key_event))) => {
                    if handle_key_event(key_event, &mut state, &intercept, &replay_tx) {
                        break;
                    }
                    dirty = true;
                }
                Some(Ok(Event::Resize(_, _))) => dirty = true,
                Some(Ok(_)) => {}
                Some(Err(error)) => return Err(error.into()),
                None => break,
            },
            _ = render_interval.tick() => {
                if dirty {
                    terminal.draw(|frame| draw(frame, &mut state, wireguard_setup.as_deref()))?;
                    dirty = false;
                }
            },
            () = cancel.cancelled() => break,
        }
    }

    // RawModeGuard handles cleanup on drop
    Ok(())
}
