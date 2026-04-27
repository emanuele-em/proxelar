pub(crate) mod forward;
pub(crate) mod reverse;

use std::{future::Future, net::SocketAddr, path::PathBuf, sync::Arc};

use hyper::Uri;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use proxyapi_models::ProxiedRequest;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::body::ProxyBody;
use crate::ca::Ssl;
use crate::error::Error;
use crate::event::ProxyEvent;
use crate::handler::CapturingHandler;
use crate::intercept::InterceptConfig;
#[cfg(feature = "scripting")]
use crate::scripting::ScriptEngine;

/// Shared HTTP(S) client type used by both forward and reverse proxy.
pub(crate) type Client =
    hyper_util::client::legacy::Client<hyper_rustls::HttpsConnector<HttpConnector>, ProxyBody>;

/// Check if an error is a benign "shutting down" or "connection closed" error.
///
/// hyper emits these when the client closes the connection before the server
/// finishes its shutdown handshake. They are not actionable.
pub(crate) fn is_benign_shutdown_error(e: &dyn std::error::Error) -> bool {
    let msg = e.to_string();
    msg.contains("shutting down") || msg.contains("connection was not closed cleanly")
}

/// Configuration for creating a [`Proxy`].
pub struct ProxyConfig {
    /// Address to listen on.
    pub addr: SocketAddr,
    /// Forward or reverse proxy mode.
    pub mode: ProxyMode,
    /// Channel for emitting captured proxy events.
    pub event_tx: mpsc::Sender<ProxyEvent>,
    /// Directory for CA certificate and key files.
    pub ca_dir: PathBuf,
    /// Optional intercept controller for interactive request/response editing.
    pub intercept: Option<Arc<InterceptConfig>>,
    /// Optional path to a Lua script for request/response hooks.
    #[cfg(feature = "scripting")]
    pub script_path: Option<PathBuf>,
    /// Optional channel for receiving replay requests from the UI.
    pub replay_rx: Option<mpsc::Receiver<ProxiedRequest>>,
}

/// Whether the proxy operates in forward (CONNECT tunneling) or reverse mode.
#[derive(Debug, Clone)]
pub enum ProxyMode {
    /// Forward proxy: clients send CONNECT requests, proxy tunnels and intercepts.
    Forward,
    /// Reverse proxy: all requests are rewritten to the given target URI.
    Reverse {
        /// Target upstream (must include scheme and authority, e.g. `http://localhost:3000`).
        target: Uri,
    },
}

/// The proxy server.
pub struct Proxy {
    config: ProxyConfig,
}

impl Proxy {
    /// Create a new proxy with the given configuration.
    pub const fn new(config: ProxyConfig) -> Self {
        Self { config }
    }

    /// Start the proxy and run until the `shutdown` future resolves.
    pub async fn start(self, shutdown: impl Future<Output = ()>) -> Result<(), Error> {
        let listener = TcpListener::bind(self.config.addr).await?;
        tracing::info!("Proxy listening on {}", self.config.addr);

        // Load Lua script engine if a script path was provided.
        #[cfg(feature = "scripting")]
        let script_engine: Option<Arc<ScriptEngine>> = self
            .config
            .script_path
            .as_ref()
            .map(|p| {
                tracing::info!("Loading Lua script: {}", p.display());
                ScriptEngine::new(p).map(Arc::new)
            })
            .transpose()?;

        let ca_dir = self.config.ca_dir.clone();
        let ca =
            Arc::new(tokio::task::spawn_blocking(move || Ssl::load_or_generate(&ca_dir)).await??);

        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build();

        let client = Arc::new(
            hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build(https),
        );

        let mut replay_rx = self.config.replay_rx;

        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, remote_addr) = match result {
                        Ok(conn) => conn,
                        Err(e) => {
                            tracing::warn!("Failed to accept connection: {e}");
                            continue;
                        }
                    };
                    let mut handler = CapturingHandler::new(self.config.event_tx.clone());
                    if let Some(ref ic) = self.config.intercept {
                        handler = handler.with_intercept(Arc::clone(ic));
                    }
                    #[cfg(feature = "scripting")]
                    if let Some(ref engine) = script_engine {
                        handler = handler.with_script_engine(Arc::clone(engine));
                    }
                    let ca = Arc::clone(&ca);
                    let client = Arc::clone(&client);

                    match &self.config.mode {
                        ProxyMode::Forward => {
                            let listen_addr = self.config.addr;
                            tokio::spawn(forward::handle_connection(
                                stream, remote_addr, handler, ca, client, listen_addr,
                            ));
                        }
                        ProxyMode::Reverse { target } => {
                            let target = target.clone();
                            tokio::spawn(reverse::handle_connection(
                                stream, remote_addr, handler, target, client,
                            ));
                        }
                    }
                }
                Some(req) = recv_replay(&mut replay_rx) => {
                    let mut handler = CapturingHandler::new(self.config.event_tx.clone());
                    if let Some(ref ic) = self.config.intercept {
                        handler = handler.with_intercept(Arc::clone(ic));
                    }
                    #[cfg(feature = "scripting")]
                    if let Some(ref engine) = script_engine {
                        handler = handler.with_script_engine(Arc::clone(engine));
                    }
                    tokio::spawn(forward::handle_replay(req, handler, Arc::clone(&client)));
                }
                () = &mut shutdown => {
                    tracing::info!("Proxy shutting down");
                    break;
                }
            }
        }

        Ok(())
    }
}

/// Receive the next replay request, or wait forever when no channel is present.
///
/// Used in the `select!` loop to make the replay arm a no-op when the UI
/// hasn't provided a replay channel.
async fn recv_replay(rx: &mut Option<mpsc::Receiver<ProxiedRequest>>) -> Option<ProxiedRequest> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{HeaderMap, Method, Version};
    use std::io;

    #[test]
    fn benign_shutdown_error_detection_matches_expected_messages() {
        let shutting_down = io::Error::other("connection is shutting down");
        let unclean = io::Error::other("connection was not closed cleanly");
        let refused = io::Error::other("connection refused");

        assert!(is_benign_shutdown_error(&shutting_down));
        assert!(is_benign_shutdown_error(&unclean));
        assert!(!is_benign_shutdown_error(&refused));
    }

    #[test]
    fn proxy_new_stores_config() {
        let (event_tx, _event_rx) = mpsc::channel(1);
        let config = ProxyConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            mode: ProxyMode::Reverse {
                target: "http://example.test".parse().unwrap(),
            },
            event_tx,
            ca_dir: PathBuf::from("."),
            intercept: None,
            #[cfg(feature = "scripting")]
            script_path: None,
            replay_rx: None,
        };

        let proxy = Proxy::new(config);

        assert_eq!(proxy.config.addr.port(), 0);
        assert!(matches!(proxy.config.mode, ProxyMode::Reverse { .. }));
    }

    #[tokio::test]
    async fn recv_replay_reads_from_channel() {
        let (tx, rx) = mpsc::channel(1);
        let req = ProxiedRequest::new(
            Method::GET,
            "http://example.test/replay".parse().unwrap(),
            Version::HTTP_11,
            HeaderMap::new(),
            Bytes::new(),
            1,
        );
        tx.send(req).await.unwrap();
        let mut rx = Some(rx);

        let received = recv_replay(&mut rx).await.unwrap();

        assert_eq!(received.uri().path(), "/replay");
    }

    #[tokio::test]
    async fn recv_replay_without_channel_waits_forever() {
        let mut rx = None;
        let result =
            tokio::time::timeout(std::time::Duration::from_millis(10), recv_replay(&mut rx)).await;

        assert!(result.is_err());
    }
}
