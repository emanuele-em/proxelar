//! Example: forward proxy with hardcoded host allowlist.
//!
//! Uses [`Proxy::start_with_handler`] with a handler that only
//! implements `handle_request` and `handle_response`:
//!
//! - requests for hosts outside the allowlist are answered with `403`
//! - after a given count, requests are rejected with `429` (e.g., quota
//!   enforcement)
//! - allowed requests gain an `x-via` header before being forwarded.
//!
//! Start a local upstream (e.g. `python3 -m http.server 8000`), run this
//! example, and point an HTTP client at the proxy:
//!
//! ```console
//! $ curl --noproxy '*' -x http://127.0.0.1:8118 http://127.0.0.1:8000/
//! $ curl --noproxy '*' -x http://127.0.0.1:8118 http://example.test/
//! ```

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use tokio::sync::mpsc;

use proxyapi::{
    HttpContext, HttpHandler, Proxy, ProxyConfig, ProxyMode, ProxyRequest, ProxyResponse,
    RequestOrResponse, UpstreamTlsConfig,
};

const LISTEN: &str = "127.0.0.1:8118";
const ALLOWED_HOSTS: &[&str] = &["127.0.0.1"];
const ALLOWED_REQUEST_QUOTA: u64 = 3;

#[derive(Clone)]
struct AllowlistHandler {
    allowed_hosts: &'static [&'static str],
    allowed_requests: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl HttpHandler for AllowlistHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        mut request: ProxyRequest,
    ) -> RequestOrResponse {
        let Some(host) = request.head.uri.host() else {
            return RequestOrResponse::Response(self.synthetic_protocol_response(
                StatusCode::BAD_REQUEST,
                HeaderMap::new(),
                Bytes::from_static(b"request is missing a host"),
            ));
        };
        if !self.allowed_hosts.contains(&host) {
            return RequestOrResponse::Response(self.synthetic_protocol_response(
                StatusCode::FORBIDDEN,
                HeaderMap::new(),
                Bytes::from_static(b"blocked: host is not allowlisted"),
            ));
        }
        if self.allowed_requests.fetch_add(1, Ordering::Relaxed) >= ALLOWED_REQUEST_QUOTA {
            return RequestOrResponse::Response(self.synthetic_protocol_response(
                StatusCode::TOO_MANY_REQUESTS,
                HeaderMap::new(),
                Bytes::from_static(b"blocked: request quota exhausted"),
            ));
        }
        request
            .head
            .headers
            .set("x-via", b"allowlist-example")
            .expect("static header name is valid");
        RequestOrResponse::Request(request)
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        response: ProxyResponse,
    ) -> ProxyResponse {
        response
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // This handler never emits events; the channel exists only because
    // ProxyConfig requires a sender. Dropping the receiver makes any
    // event a no-op.
    let (event_tx, _event_rx) = mpsc::channel(64);
    let config = ProxyConfig {
        addr: LISTEN.parse::<SocketAddr>()?,
        mode: ProxyMode::Forward,
        event_tx,
        ca_dir: std::env::temp_dir().join("proxyapi-allowlist-example-ca"),
        upstream_tls: UpstreamTlsConfig::Default,
        intercept: None,
        body_capture_limit: None,
        #[cfg(feature = "scripting")]
        script_path: None,
        replay_rx: None,
    };
    let handler = AllowlistHandler {
        allowed_hosts: ALLOWED_HOSTS,
        allowed_requests: Arc::new(AtomicU64::new(0)),
    };
    println!("allowlist proxy listening on http://{LISTEN}");
    Proxy::new(config)
        .start_with_handler(handler, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
