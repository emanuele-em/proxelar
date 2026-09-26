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
    DnsConfig, Proxy, ProxyConfig, ProxyMode, UpstreamProxyConfig, UpstreamTlsConfig,
    WireGuardConfig,
};
pub use rules::{RouteRule, RouteRules, RuleError, RuleHeader, RuleOutcome};
pub use session::{RedactionPolicy, SessionError, SessionRecorder};

/// Returned by [`HttpHandler::handle_request`] to either forward or short-circuit.
pub enum RequestOrResponse {
    Request(ProxyRequest),
    Response(ProxyResponse),
}

/// Metadata about the incoming connection.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct HttpContext {
    pub remote_addr: SocketAddr,
}

/// Trait for intercepting and modifying proxied HTTP traffic.
///
/// Implementations must be `Clone` because the proxy clones the handler
/// for each connection/request pair.
///
/// The remaining methods are plumbing hooks called by the built-in proxy
/// loop. Their defaults are capture-free, so a handler that only
/// implements `handle_request` and `handle_response` needs nothing else;
/// override them to participate in capture and event emission.
#[async_trait::async_trait]
pub trait HttpHandler: Clone + Send + Sync + 'static {
    async fn handle_request(&mut self, ctx: &HttpContext, req: ProxyRequest) -> RequestOrResponse;

    async fn handle_response(&mut self, ctx: &HttpContext, res: ProxyResponse) -> ProxyResponse;

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
