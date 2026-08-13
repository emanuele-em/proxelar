use rama::telemetry::tracing;
use std::convert::Infallible;
use std::sync::Arc;

use rama::bytes::Bytes;

use rama::http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
use rama::net::uri::Uri;
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
    let Some(host) = target.host_str() else {
        return Ok(req);
    };
    let scheme = target.scheme_str().unwrap_or("http");
    let authority = match target.port_u16() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };

    let new_uri = if req.uri().query_or_empty().is_empty() {
        format!("{scheme}://{authority}{}", req.uri().path_or_root())
    } else {
        format!(
            "{scheme}://{authority}{}?{}",
            req.uri().path_or_root(),
            req.uri().query_or_empty()
        )
    };

    *req.uri_mut() = Uri::parse(new_uri).map_err(|_| ())?;

    match HeaderValue::from_str(&authority) {
        Ok(host_value) => {
            req.headers_mut()
                .insert(rama::http::header::HOST, host_value);
        }
        Err(error) => {
            tracing::warn!("Invalid target authority for Host header: {error}");
        }
    }

    Ok(req)
}
