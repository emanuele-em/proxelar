//! `proxyapi` — core library for the Proxelar MITM proxy.
//!
//! Provides HTTP/HTTPS forward and reverse proxy functionality with
//! request/response interception via the [`HttpHandler`] trait.

#![forbid(unsafe_code)]

pub mod body;
pub mod ca;
pub mod error;
pub mod event;
pub(crate) mod handler;
pub mod intercept;
pub mod proxy;
mod rewind;
#[cfg(feature = "scripting")]
pub mod scripting;

use body::ProxyBody;
use hyper::{Request, Response};
use std::net::SocketAddr;

pub use error::Error;
pub use event::ProxyEvent;
pub use handler::{CapturingHandler, DEFAULT_BODY_CAPTURE_LIMIT};
pub use intercept::{InterceptConfig, InterceptDecision};
pub use proxy::{Proxy, ProxyConfig, ProxyMode};

/// Returned by [`HttpHandler::handle_request`] to either forward or short-circuit.
pub enum RequestOrResponse {
    Request(Request<ProxyBody>),
    Response(Response<ProxyBody>),
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
    async fn handle_request(
        &mut self,
        ctx: &HttpContext,
        req: Request<hyper::body::Incoming>,
    ) -> RequestOrResponse;

    async fn handle_response(
        &mut self,
        ctx: &HttpContext,
        res: Response<hyper::body::Incoming>,
    ) -> Response<ProxyBody>;
}
