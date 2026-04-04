mod cli;
mod interface;

use clap::Parser;
use cli::{Args, Interface, Mode};
use http::Uri;
use proxyapi::{InterceptConfig, Proxy, ProxyConfig, ProxyMode};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Capacity of the event channel between the proxy core and the UI.
const EVENT_CHANNEL_CAPACITY: usize = 10_000;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|e| format!("Failed to install rustls crypto provider: {e:?}"))?;

    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let (event_tx, event_rx) = tokio::sync::mpsc::channel(EVENT_CHANNEL_CAPACITY);
    let (replay_tx, replay_rx) = tokio::sync::mpsc::channel(100);
    let cancel = CancellationToken::new();
    let intercept = InterceptConfig::new();

    let ca_dir = args.ca_dir.unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| {
                tracing::warn!("Could not determine home directory, using current directory");
                std::path::PathBuf::from(".")
            })
            .join(".proxelar")
    });

    let proxy_mode = match args.mode {
        Mode::Forward => ProxyMode::Forward,
        Mode::Reverse => {
            let target_str = args.target.as_deref().expect("clap enforces --target");
            let target: Uri = target_str.parse()?;
            if target.scheme().is_none() || target.authority().is_none() {
                return Err(
                    "Reverse proxy target must include scheme and authority (e.g. http://localhost:3000)".into(),
                );
            }
            ProxyMode::Reverse { target }
        }
    };

    let proxy_config = ProxyConfig {
        addr: SocketAddr::new(args.addr, args.port),
        mode: proxy_mode,
        event_tx,
        ca_dir,
        intercept: Some(Arc::clone(&intercept)),
        #[cfg(feature = "scripting")]
        script_path: args.script,
        replay_rx: Some(replay_rx),
    };

    let proxy = Proxy::new(proxy_config);

    // Ctrl+C cancels everything
    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        cancel_clone.cancel();
    });

    // Spawn the proxy; cancel the token on failure so the UI exits too
    let cancel_for_proxy = cancel.clone();
    tokio::spawn(async move {
        if let Err(e) = proxy
            .start(cancel_for_proxy.clone().cancelled_owned())
            .await
        {
            tracing::error!("Proxy error: {e}");
            cancel_for_proxy.cancel();
        }
    });

    // Brief delay to catch immediate startup failures (bind errors, CA errors)
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    if cancel.is_cancelled() {
        return Err("Proxy failed to start (check logs for details)".into());
    }

    match args.interface {
        Interface::Terminal => interface::terminal::run(event_rx, cancel).await,
        Interface::Tui => {
            interface::tui::run(event_rx, Arc::clone(&intercept), replay_tx, cancel).await
        }
        Interface::Gui => {
            interface::web::run(
                event_rx,
                Arc::clone(&intercept),
                replay_tx,
                args.gui_port,
                cancel,
            )
            .await
        }
    }

    Ok(())
}
