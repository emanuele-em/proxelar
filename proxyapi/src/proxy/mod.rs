pub(crate) mod forward;
pub(crate) mod reverse;

use std::{future::Future, net::SocketAddr, path::PathBuf, sync::Arc};

use hyper::Uri;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::body::ProxyBody;
use crate::ca::Ssl;
use crate::error::Error;
use crate::event::ProxyEvent;
use crate::handler::CapturingHandler;
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
    /// Optional path to a Lua script for request/response hooks.
    #[cfg(feature = "scripting")]
    pub script_path: Option<PathBuf>,
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
                    #[allow(unused_mut)]
                    let mut handler = CapturingHandler::new(self.config.event_tx.clone());
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
                () = &mut shutdown => {
                    tracing::info!("Proxy shutting down");
                    break;
                }
            }
        }

        Ok(())
    }
}
