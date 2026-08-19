use rama::telemetry::tracing;
use std::convert::Infallible;
use std::sync::Arc;

use rama::bytes::Bytes;

use rama::http::headers::{HeaderMapExt as _, Host as HostHeader};
use rama::http::{HeaderMap, Request, Response, StatusCode};
use rama::net::address::{Authority, HostWithOptPort};
use rama::net::uri::Uri;
use rama::net::Protocol;
use rama::Service;

use crate::handler::{CapturingHandler, RequestOrResponse};

use super::{sanitize_forwarded_request_headers, sanitize_response_for_client, UpstreamClient};

/// Reverse-proxy service: rewrites every request to the configured target,
/// forwards it, and captures the exchange.
#[derive(Clone)]
pub(crate) struct ReverseProxyService {
    handler: CapturingHandler,
    client: Arc<UpstreamClient>,
    target: Uri,
}

impl ReverseProxyService {
    pub(crate) fn new(handler: CapturingHandler, client: Arc<UpstreamClient>, target: Uri) -> Self {
        Self {
            handler,
            client,
            target,
        }
    }
}

impl Service<Request> for ReverseProxyService {
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        let client_version = req.version();
        let mut handler = self.handler.clone();

        let req = match handler.handle_request(req).await {
            RequestOrResponse::Request(req) => req,
            RequestOrResponse::Response(mut res) => {
                sanitize_response_for_client(&mut res, client_version);
                return Ok(res);
            }
        };

        let mut req = match rewrite_uri(req, &self.target) {
            Ok(req) => req,
            Err(()) => {
                tracing::error!("Failed to rewrite URI to reverse-proxy target");
                let mut res = handler.synthetic_response(
                    StatusCode::BAD_GATEWAY,
                    HeaderMap::new(),
                    Bytes::from_static(b"Bad Gateway: URI rewrite failed"),
                );
                sanitize_response_for_client(&mut res, client_version);
                return Ok(res);
            }
        };
        // Strip per-hop / proxy-only headers before forwarding, exactly as the
        // forward path does — `rewrite_uri` has already set the target `Host`.
        sanitize_forwarded_request_headers(req.headers_mut());

        match self.client.serve(req).await {
            Ok(res) => {
                let mut res = handler.handle_upstream_response(res).await;
                sanitize_response_for_client(&mut res, client_version);
                Ok(res)
            }
            Err(err) => {
                tracing::error!("Reverse proxy error: {err}");
                let mut res = handler.synthetic_response(
                    StatusCode::BAD_GATEWAY,
                    HeaderMap::new(),
                    Bytes::from_static(b"Bad Gateway"),
                );
                sanitize_response_for_client(&mut res, client_version);
                Ok(res)
            }
        }
    }
}

/// Rewrite the request URI to point at the reverse-proxy target, preserving the
/// original path and query, and update the `Host` header to match.
fn rewrite_uri(mut req: Request, target: &Uri) -> Result<Request, ()> {
    let Some(authority) = target.authority() else {
        return Err(());
    };

    // Replace typed URI components in-place so rama retains the request's
    // exact path/query representation and renders IPv6 authority brackets.
    // Userinfo is intentionally not copied to either the request target or
    // Host header; reverse-proxy credentials belong in authorization headers.
    let host = HostWithOptPort {
        host: authority.host().into_owned(),
        port: authority.port(),
    };
    let mut uri = req.uri().clone();
    uri.set_scheme(target.scheme().cloned().unwrap_or(Protocol::HTTP));
    uri.set_authority(Authority::new(host.clone()));
    *req.uri_mut() = uri;
    req.headers_mut().typed_insert(HostHeader(host));

    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::http::Body;

    #[test]
    fn rewrite_uri_uses_typed_ipv6_authority() {
        let request = Request::builder()
            .uri("/items?view=full")
            .body(Body::empty())
            .unwrap();
        let target: Uri = "http://[::1]:8080".parse().unwrap();

        let request = rewrite_uri(request, &target).unwrap();

        assert_eq!(
            request.uri().to_string(),
            "http://[::1]:8080/items?view=full"
        );
        assert_eq!(request.headers()[rama::http::header::HOST], "[::1]:8080");
    }
}
