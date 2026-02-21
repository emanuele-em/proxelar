use crossterm::event::{Event, EventStream, KeyEvent};
use futures::StreamExt;
use proxyapi::ProxyEvent;
use tokio::sync::mpsc;

#[derive(Debug)]
pub enum AppEvent {
    Input(KeyEvent),
    Proxy(ProxyEvent),
    Render,
}

/// Merge terminal input, proxy events, and render ticks into a single stream.
pub fn spawn_event_loop(
    mut proxy_rx: mpsc::Receiver<ProxyEvent>,
) -> mpsc::UnboundedReceiver<AppEvent> {
    let (tx, rx) = mpsc::unbounded_channel();

    tokio::spawn(async move {
        let mut reader = EventStream::new();
        let mut render_interval = tokio::time::interval(tokio::time::Duration::from_millis(50));

        loop {
            let crossterm_event = reader.next();
            tokio::pin!(crossterm_event);

            tokio::select! {
                Some(Ok(Event::Key(key))) = &mut crossterm_event => {
                    if tx.send(AppEvent::Input(key)).is_err() {
                        break;
                    }
                }
                Some(proxy_evt) = proxy_rx.recv() => {
                    if tx.send(AppEvent::Proxy(proxy_evt)).is_err() {
                        break;
                    }
                }
                _ = render_interval.tick() => {
                    if tx.send(AppEvent::Render).is_err() {
                        break;
                    }
                }
            }
        }
    });

    rx
}
