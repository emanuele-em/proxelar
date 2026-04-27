use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use hyper::service::service_fn;
use hyper::{Request, Response, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use crate::body::{self, ProxyBody};
use crate::handler::{collect_and_emit, collect_body, CapturingHandler};
use crate::{HttpContext, HttpHandler, RequestOrResponse};

use super::{is_benign_shutdown_error, Client};

pub async fn handle_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    handler: CapturingHandler,
    target: Uri,
    client: Arc<Client>,
) {
    let io = TokioIo::new(stream);

    let service = service_fn(move |req: Request<hyper::body::Incoming>| {
        let mut handler = handler.clone();
        let client = Arc::clone(&client);
        let target = target.clone();

        async move {
            let ctx = HttpContext { remote_addr };

            let req = match handler.handle_request(&ctx, req).await {
                RequestOrResponse::Request(req) => req,
                RequestOrResponse::Response(res) => return Ok::<_, hyper::Error>(res),
            };

            // Rewrite URI to target, preserving path and query
            let req = match rewrite_uri(req, &target) {
                Ok(req) => req,
                Err(e) => {
                    tracing::error!("Failed to rewrite URI to target: {e}");
                    return Ok(Response::builder()
                        .status(502)
                        .body(body::full(Bytes::from("Bad Gateway: URI rewrite failed")))
                        .unwrap_or_else(|_| Response::new(body::empty())));
                }
            };

            match client.request(req).await {
                Ok(res) => {
                    let (parts, body) = res.into_parts();
                    let body_bytes = collect_body(body).await;
                    Ok(collect_and_emit(&mut handler, parts, body_bytes))
                }
                Err(e) => {
                    tracing::error!("Reverse proxy error: {e}");
                    Ok(Response::builder()
                        .status(502)
                        .body(body::full(Bytes::from("Bad Gateway")))
                        .unwrap_or_else(|_| Response::new(body::empty())))
                }
            }
        }
    });

    if let Err(e) = hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(io, service)
        .with_upgrades()
        .await
    {
        if !is_benign_shutdown_error(&e) {
            tracing::debug!("Reverse proxy connection error: {e}");
        }
    }
}

/// Rewrite the request URI to point at the reverse proxy target, preserving
/// the original path and query. Also updates the `Host` header to match.
fn rewrite_uri(
    mut req: Request<ProxyBody>,
    target: &Uri,
) -> Result<Request<ProxyBody>, http::Error> {
    let mut uri_parts = req.uri().clone().into_parts();
    uri_parts.scheme = target.scheme().cloned();
    uri_parts.authority = target.authority().cloned();
    *req.uri_mut() = Uri::from_parts(uri_parts)?;

    // Update Host header to match the target so virtual hosting works correctly
    if let Some(authority) = target.authority() {
        match authority.as_str().parse() {
            Ok(host_value) => {
                req.headers_mut().insert(hyper::header::HOST, host_value);
            }
            Err(e) => {
                tracing::warn!("Invalid target authority for Host header: {e}");
            }
        }
    }

    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body;

    #[test]
    fn rewrite_uri_preserves_path_query_and_sets_target_host() {
        let req = Request::builder()
            .uri("/api/items?name=one")
            .header(hyper::header::HOST, "client.example")
            .body(body::empty())
            .unwrap();
        let target: Uri = "https://upstream.example:8443".parse().unwrap();

        let req = rewrite_uri(req, &target).unwrap();

        assert_eq!(req.uri().scheme_str(), Some("https"));
        assert_eq!(
            req.uri().authority().map(|a| a.as_str()),
            Some("upstream.example:8443")
        );
        assert_eq!(req.uri().path(), "/api/items");
        assert_eq!(req.uri().query(), Some("name=one"));
        assert_eq!(req.headers()[hyper::header::HOST], "upstream.example:8443");
    }

    #[test]
    fn rewrite_uri_leaves_host_when_target_has_no_authority() {
        let req = Request::builder()
            .uri("/local")
            .header(hyper::header::HOST, "client.example")
            .body(body::empty())
            .unwrap();
        let target: Uri = "/target-only".parse().unwrap();

        let req = rewrite_uri(req, &target).unwrap();

        assert_eq!(req.uri().path(), "/local");
        assert_eq!(req.headers()[hyper::header::HOST], "client.example");
    }
}
