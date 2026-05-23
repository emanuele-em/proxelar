pub(crate) mod forward;
pub(crate) mod reverse;

use std::{error::Error as StdError, future::Future, net::SocketAddr, path::PathBuf, sync::Arc};

use hyper::body::{Body as HttpBody, Incoming};
use hyper::header::{
    HeaderName, CONNECTION, COOKIE, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE,
    TRANSFER_ENCODING, UPGRADE,
};
use hyper::rt::{Read, Write};
use hyper::service::Service;
use hyper::{HeaderMap, Request, Response, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto;
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
pub(crate) type BoxError = Box<dyn StdError + Send + Sync>;

const KEEP_ALIVE: HeaderName = HeaderName::from_static("keep-alive");
const PROXY_CONNECTION: HeaderName = HeaderName::from_static("proxy-connection");

/// Check if an error is a benign "shutting down" or "connection closed" error.
///
/// hyper emits these when the client closes the connection before the server
/// finishes its shutdown handshake. They are not actionable.
pub(crate) fn is_benign_shutdown_error(e: &dyn std::error::Error) -> bool {
    let msg = e.to_string();
    msg.contains("shutting down") || msg.contains("connection was not closed cleanly")
}

/// Serve an HTTP connection using Hyper's protocol auto-detection.
///
/// The upgrade-capable path is required for HTTP/1 CONNECT, WebSocket upgrades,
/// and Hyper's HTTP/2 CONNECT upgrade adapter.
pub(crate) async fn serve_auto_connection<I, S, B>(io: I, service: S) -> Result<(), BoxError>
where
    I: Read + Write + Unpin + Send + 'static,
    S: Service<Request<Incoming>, Response = Response<B>>,
    S::Future: 'static,
    S::Error: Into<BoxError>,
    B: HttpBody + 'static,
    B::Error: Into<BoxError>,
    TokioExecutor: auto::HttpServerConnExec<S::Future, B>,
{
    let builder = auto::Builder::new(TokioExecutor::new())
        .preserve_header_case(true)
        .title_case_headers(true);

    builder.serve_connection_with_upgrades(io, service).await
}

/// Prepare a captured request for the upstream HTTP/1.1 client.
///
/// This centralizes the proxy's existing invariants and strips hop-by-hop
/// metadata that must not be forwarded across protocol boundaries.
pub(crate) fn prepare_upstream_request(mut req: Request<ProxyBody>) -> Request<ProxyBody> {
    strip_hop_by_hop_headers(req.headers_mut());
    req.headers_mut().remove(HOST);
    req.headers_mut().remove(PROXY_AUTHORIZATION);
    req.headers_mut().remove(TE);
    join_cookie_headers(req.headers_mut());
    *req.version_mut() = hyper::Version::HTTP_11;
    req
}

/// Prepare an HTTP/1.1 protocol-upgrade request for the upstream client.
///
/// Upgrade handshakes intentionally keep `Connection` and `Upgrade`; stripping
/// them would turn WebSocket forwarding into an ordinary HTTP request.
pub(crate) fn prepare_upstream_upgrade_request(mut req: Request<ProxyBody>) -> Request<ProxyBody> {
    req.headers_mut().remove(HOST);
    req.headers_mut().remove(PROXY_AUTHORIZATION);
    join_cookie_headers(req.headers_mut());
    *req.version_mut() = hyper::Version::HTTP_11;
    req
}

/// Remove response headers that are illegal on HTTP/2 connections.
fn sanitize_response_for_http2<B>(res: &mut Response<B>) {
    strip_hop_by_hop_headers(res.headers_mut());
    res.headers_mut().remove(PROXY_AUTHENTICATE);
    res.headers_mut().remove(TE);
}

pub(crate) fn sanitize_response_for_client<B>(res: &mut Response<B>, version: hyper::Version) {
    if version == hyper::Version::HTTP_2 {
        sanitize_response_for_http2(res);
    }
}

fn join_cookie_headers(headers: &mut HeaderMap) {
    if let http::header::Entry::Occupied(mut cookies) = headers.entry(COOKIE) {
        let joined_cookies = bstr::join(b"; ", cookies.iter());
        match joined_cookies.try_into() {
            Ok(value) => {
                cookies.insert(value);
            }
            Err(e) => {
                tracing::warn!("Failed to join cookies, removing header: {e}");
                cookies.remove();
            }
        }
    }
}

fn strip_hop_by_hop_headers(headers: &mut HeaderMap) {
    let connection_tokens = connection_tokens(headers);
    headers.remove(CONNECTION);

    for name in connection_tokens {
        headers.remove(name);
    }

    headers.remove(KEEP_ALIVE);
    headers.remove(PROXY_CONNECTION);
    headers.remove(TRANSFER_ENCODING);
    headers.remove(UPGRADE);
}

fn connection_tokens(headers: &HeaderMap) -> Vec<HeaderName> {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect()
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
    /// Maximum body bytes buffered for capture/editing before streaming passthrough.
    ///
    /// `None` means unlimited capture.
    pub body_capture_limit: Option<usize>,
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
                    let mut handler = CapturingHandler::new(self.config.event_tx.clone())
                        .with_body_capture_limit(self.config.body_capture_limit);
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
                    let mut handler = CapturingHandler::new(self.config.event_tx.clone())
                        .with_body_capture_limit(self.config.body_capture_limit);
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
    use crate::handler::DEFAULT_BODY_CAPTURE_LIMIT;
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
            body_capture_limit: DEFAULT_BODY_CAPTURE_LIMIT,
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

    #[test]
    fn prepare_upstream_request_preserves_invariants_and_strips_hop_by_hop_headers() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://upstream.test/path")
            .version(Version::HTTP_2)
            .header(HOST, "wrong-host.test")
            .header(COOKIE, "a=1")
            .header(COOKIE, "b=2")
            .header(CONNECTION, "x-remove, keep-alive")
            .header("x-remove", "yes")
            .header(KEEP_ALIVE, "timeout=5")
            .header(PROXY_CONNECTION, "keep-alive")
            .header(TRANSFER_ENCODING, "chunked")
            .header(UPGRADE, "websocket")
            .header(PROXY_AUTHORIZATION, "Basic secret")
            .header(TE, "trailers")
            .body(crate::body::empty())
            .unwrap();

        let req = prepare_upstream_request(req);

        assert_eq!(req.version(), Version::HTTP_11);
        assert!(!req.headers().contains_key(HOST));
        assert!(!req.headers().contains_key(CONNECTION));
        assert!(!req.headers().contains_key("x-remove"));
        assert!(!req.headers().contains_key(KEEP_ALIVE));
        assert!(!req.headers().contains_key(PROXY_CONNECTION));
        assert!(!req.headers().contains_key(TRANSFER_ENCODING));
        assert!(!req.headers().contains_key(UPGRADE));
        assert!(!req.headers().contains_key(PROXY_AUTHORIZATION));
        assert!(!req.headers().contains_key(TE));
        assert_eq!(
            req.headers().get_all(COOKIE).iter().count(),
            1,
            "duplicate Cookie headers should be collapsed"
        );
        assert_eq!(req.headers()[COOKIE], "a=1; b=2");
    }

    #[test]
    fn prepare_upstream_upgrade_request_preserves_upgrade_headers() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://upstream.test/ws")
            .version(Version::HTTP_2)
            .header(HOST, "wrong-host.test")
            .header(CONNECTION, "Upgrade")
            .header(UPGRADE, "websocket")
            .header(PROXY_AUTHORIZATION, "Basic secret")
            .body(crate::body::empty())
            .unwrap();

        let req = prepare_upstream_upgrade_request(req);

        assert_eq!(req.version(), Version::HTTP_11);
        assert!(!req.headers().contains_key(HOST));
        assert!(!req.headers().contains_key(PROXY_AUTHORIZATION));
        assert_eq!(req.headers()[CONNECTION], "Upgrade");
        assert_eq!(req.headers()[UPGRADE], "websocket");
    }

    #[test]
    fn sanitize_response_for_http2_strips_connection_metadata() {
        let mut response = Response::builder()
            .status(http::StatusCode::OK)
            .header(CONNECTION, "x-remove, upgrade")
            .header("x-remove", "yes")
            .header(KEEP_ALIVE, "timeout=5")
            .header(PROXY_CONNECTION, "keep-alive")
            .header(TRANSFER_ENCODING, "chunked")
            .header(UPGRADE, "websocket")
            .header(PROXY_AUTHENTICATE, "Basic")
            .header(TE, "trailers")
            .body(crate::body::empty())
            .unwrap();

        sanitize_response_for_http2(&mut response);

        assert!(!response.headers().contains_key(CONNECTION));
        assert!(!response.headers().contains_key("x-remove"));
        assert!(!response.headers().contains_key(KEEP_ALIVE));
        assert!(!response.headers().contains_key(PROXY_CONNECTION));
        assert!(!response.headers().contains_key(TRANSFER_ENCODING));
        assert!(!response.headers().contains_key(UPGRADE));
        assert!(!response.headers().contains_key(PROXY_AUTHENTICATE));
        assert!(!response.headers().contains_key(TE));
    }

    #[test]
    fn connection_tokens_ignores_invalid_header_names() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, "x-valid, bad header".parse().unwrap());

        let tokens = connection_tokens(&headers);

        assert_eq!(tokens, vec![HeaderName::from_static("x-valid")]);
    }
}
