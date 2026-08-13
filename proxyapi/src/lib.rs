//! `proxyapi` — core library for the Proxelar MITM proxy.
//!
//! Provides HTTP/HTTPS, WireGuard, SOCKS5, DNS, and fixed-target UDP proxy
//! functionality with request/response interception via [`CapturingHandler`].

#![forbid(unsafe_code)]

#[cfg(feature = "scripting")]
pub mod addon;
pub mod ca;
pub mod content;
#[cfg(feature = "scripting")]
pub(crate) mod encoding;
pub mod error;
pub mod event;
pub mod filter;
pub(crate) mod handler;
pub mod intercept;
pub mod proxy;
pub mod rules;
#[cfg(feature = "scripting")]
pub mod scripting;
pub mod session;

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
    DnsConfig, Proxy, ProxyConfig, ProxyMode, UpstreamHttpVersion, UpstreamProxyConfig,
    UpstreamTlsConfig, WireGuardConfig,
};
pub use rules::{RouteRule, RouteRules, RuleError, RuleHeader, RuleOutcome};
pub use session::{RedactionPolicy, SessionError, SessionRecorder};
