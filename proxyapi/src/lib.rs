//! `proxyapi` — core library for the Proxelar MITM proxy.
//!
//! Provides HTTP/HTTPS, WireGuard, SOCKS5, DNS, and fixed-target UDP proxy
//! functionality with request/response interception via [`HttpHandler`].

#![forbid(unsafe_code)]

#[cfg(feature = "scripting")]
pub mod addon;
pub mod body;
pub mod ca;
pub mod content;
#[cfg(feature = "scripting")]
pub(crate) mod encoding;
pub mod error;
pub mod event;
pub mod filter;
pub(crate) mod handler;
pub mod header;
pub mod intercept;
pub mod proxy;
mod rewind;
pub mod rules;
#[cfg(feature = "scripting")]
pub mod scripting;
pub mod session;

pub use proxelar_proto::{
    BodyFrame, ProtocolError, ProxyBody, ProxyRequest, ProxyResponse, RequestHead, ResponseHead,
};
use proxyapi_models::ProxiedRequest;
pub use proxyapi_models::{DnsName, DnsNameError};
use std::net::SocketAddr;
#[cfg(feature = "scripting")]
use std::sync::Arc;
use tokio::sync::mpsc;

#[cfg(feature = "scripting")]
pub use addon::{
    discover_addons, find_addon, install_addon, AddonError, AddonHook, AddonManifest, AddonPackage,
    ADDON_MANIFEST_FILE, ADDON_SCHEMA_VERSION,
};
pub use error::Error;
pub use event::ProxyEvent;
pub use filter::{FilterParseError, FlowFilter};
pub use handler::{CapturingHandler, DEFAULT_BODY_CAPTURE_LIMIT};
pub use intercept::{InterceptConfig, InterceptDecision};
pub use proxy::{
    DnsConfig, DnsDecision, DnsHandler, Listener, Proxy, ProxyConfig, ProxyMode,
    UpstreamProxyConfig, UpstreamTlsConfig, WireGuardConfig,
};
pub use rules::{RouteRule, RouteRules, RuleError, RuleHeader, RuleOutcome};
pub use session::{RedactionPolicy, SessionError, SessionRecorder};

/// Returned by [`HttpHandler::handle_request`] to either forward or short-circuit.
pub enum RequestOrResponse {
    Request(ProxyRequest),
    Response(ProxyResponse),
}

/// Returned by [`HttpHandler::handle_tunnel`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TunnelDecision {
    /// Connect to the target and relay the tunnel unchanged.
    Forward,
    /// Close the tunnel without contacting the target.
    Close,
}

/// Metadata about the incoming connection.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct HttpContext {
    /// The client that opened the connection.
    pub client: ClientInfo,
}

impl HttpContext {
    /// Create the context of a connection opened by `client`.
    pub const fn new(client: ClientInfo) -> Self {
        Self { client }
    }
}

/// The client of a proxied connection, as identified by the proxy.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ClientInfo {
    /// A client connected over IP, with its address and port as seen by
    /// the proxy. In WireGuard mode, this is the source address inside the
    /// tunnel.
    Ip(SocketAddr),
    /// A client connected over a Unix socket, identified by its process.
    Unix(UnixClient),
}

/// The process that connected to a Unix socket, as of its `connect()` call.
///
/// On platforms where peer credentials are unavailable (ESP-IDF, Fuchsia,
/// GNU Hurd, NuttX and PlayStation Vita), every client is reported with
/// `uid` and `gid` 0: do not base access decisions on them there.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct UnixClient {
    /// Effective user ID of the process.
    pub uid: u32,
    /// Effective group ID of the process.
    pub gid: u32,
    /// Process ID, where the platform reports it. A hint only: process IDs
    /// are reused once a process exits.
    pub pid: Option<i32>,
}

impl UnixClient {
    /// Create the identity of a Unix socket client.
    pub const fn new(uid: u32, gid: u32, pid: Option<i32>) -> Self {
        Self { uid, gid, pid }
    }
}

/// Trait for intercepting and modifying proxied HTTP traffic.
///
/// Implementations must be `Clone` because the proxy clones the handler
/// for each connection/request pair.
///
/// Override `handle_tunnel` to filter raw TCP tunnels; the default
/// forwards them. The remaining methods are plumbing hooks called by the
/// built-in proxy loop. Their defaults are capture-free, so a handler that
/// only implements `handle_request` and `handle_response` needs nothing
/// else; override them to participate in capture and event emission.
#[async_trait::async_trait]
pub trait HttpHandler: Clone + Send + Sync + 'static {
    async fn handle_request(&mut self, ctx: &HttpContext, req: ProxyRequest) -> RequestOrResponse;

    async fn handle_response(&mut self, ctx: &HttpContext, res: ProxyResponse) -> ProxyResponse;

    /// Decide whether a raw TCP tunnel is forwarded or closed.
    ///
    /// Called when the payload of a CONNECT tunnel is neither TLS nor HTTP,
    /// so [`handle_request`](HttpHandler::handle_request) never sees it.
    /// `authority` is the CONNECT target: exactly what the proxy dials on
    /// [`TunnelDecision::Forward`], the default.
    ///
    /// [`TunnelDecision::Close`] closes the tunnel without contacting
    /// `authority`. The CONNECT request has already been answered with a
    /// success response by then, so the client sees the tunnel close, not
    /// an HTTP error.
    async fn handle_tunnel(
        &mut self,
        _ctx: &HttpContext,
        _authority: &http::uri::Authority,
    ) -> TunnelDecision {
        TunnelDecision::Forward
    }

    /// Build a protocol-level response for upstream failures or rejected
    /// upgrades.
    ///
    /// The default builds the response without capture side effects.
    fn synthetic_protocol_response(
        &mut self,
        status: http::StatusCode,
        headers: http::HeaderMap,
        body: bytes::Bytes,
    ) -> ProxyResponse {
        crate::handler::pure_synthetic_protocol_response(status, headers, body)
    }

    /// Take the flow ID assigned while handling the current request.
    ///
    /// Returns `None` by default; callers fall back to a fresh ID.
    fn take_pending_id(&mut self) -> Option<u64> {
        None
    }

    /// Take the request captured for the current flow, if any.
    ///
    /// Returns `None` by default.
    fn take_captured_request(&mut self) -> Option<ProxiedRequest> {
        None
    }

    /// Emit a proxy event.
    ///
    /// The default discards the event.
    fn send_event(&self, _event: ProxyEvent) {}

    /// Clone the event sender used by long-lived spawned tasks such as raw
    /// TCP tunnels and WebSocket frame pumps.
    ///
    /// The default returns a sender whose receiver is dropped, so every
    /// event sent through it is discarded.
    fn event_tx_clone(&self) -> mpsc::Sender<ProxyEvent> {
        mpsc::channel(1).0
    }

    /// Clone the attached Lua script engine, if any.
    ///
    /// Returns `None` by default.
    #[cfg(feature = "scripting")]
    fn script_engine_clone(&self) -> Option<Arc<crate::scripting::ScriptEngine>> {
        None
    }
}
