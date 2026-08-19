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
mod hyper_adapter;
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
use std::net::SocketAddr;

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
#[async_trait::async_trait]
pub trait HttpHandler: Clone + Send + Sync + 'static {
    async fn handle_request(&mut self, ctx: &HttpContext, req: ProxyRequest) -> RequestOrResponse;

    async fn handle_response(&mut self, ctx: &HttpContext, res: ProxyResponse) -> ProxyResponse;
}
