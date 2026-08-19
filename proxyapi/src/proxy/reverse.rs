use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use hyper::service::service_fn;
use hyper::{Request, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use crate::handler::CapturingHandler;
use crate::hyper_adapter::{
    from_hyper_request, from_hyper_response, to_hyper_request, to_hyper_response, HyperBody,
};
use crate::{HttpContext, HttpHandler, RequestOrResponse};

use super::{
    is_benign_shutdown_error, prepare_upstream_request, sanitize_response_for_client,
    serve_auto_connection, Client,
};

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
            let client_version = req.version();
            let ctx = HttpContext { remote_addr };

            let req = match handler.handle_request(&ctx, from_hyper_request(req)).await {
                RequestOrResponse::Request(req) => req,
                RequestOrResponse::Response(res) => {
                    let mut res = protocol_response_to_hyper(res);
                    sanitize_response_for_client(&mut res, client_version);
                    return Ok::<_, hyper::Error>(res);
                }
            };

            // Rewrite URI to target, preserving path and query
            let req = match rewrite_uri(req, &target) {
                Ok(req) => req,
                Err(e) => {
                    tracing::error!("Failed to rewrite URI to target: {e}");
                    return Ok(protocol_response_to_hyper(
                        handler.synthetic_protocol_response(
                            http::StatusCode::BAD_GATEWAY,
                            http::HeaderMap::new(),
                            Bytes::from_static(b"Bad Gateway: URI rewrite failed"),
                        ),
                    ));
                }
            };

            let req = match to_hyper_request(req) {
                Ok(request) => request,
                Err(error) => {
                    tracing::warn!("Could not adapt reverse request for Hyper: {error}");
                    return Ok(protocol_response_to_hyper(
                        handler.synthetic_protocol_response(
                            http::StatusCode::BAD_REQUEST,
                            http::HeaderMap::new(),
                            Bytes::from_static(b"Invalid request headers"),
                        ),
                    ));
                }
            };

            match client.request(prepare_upstream_request(req)).await {
                Ok(res) => {
                    let response = handler
                        .handle_response(&ctx, from_hyper_response(res))
                        .await;
                    let mut res = protocol_response_to_hyper(response);
                    sanitize_response_for_client(&mut res, client_version);
                    Ok(res)
                }
                Err(e) => {
                    tracing::error!("Reverse proxy error: {e}");
                    let mut res = protocol_response_to_hyper(handler.synthetic_protocol_response(
                        http::StatusCode::BAD_GATEWAY,
                        http::HeaderMap::new(),
                        Bytes::from_static(b"Bad Gateway"),
                    ));
                    sanitize_response_for_client(&mut res, client_version);
                    Ok(res)
                }
            }
        }
    });

    if let Err(e) = serve_auto_connection(io, service).await {
        if !is_benign_shutdown_error(e.as_ref()) {
            tracing::debug!("Reverse proxy connection error: {e}");
        }
    }
}

/// Rewrite the request URI to point at the reverse proxy target, preserving
/// the original path and query. Also updates the `Host` header to match.
fn rewrite_uri(
    mut req: crate::ProxyRequest,
    target: &Uri,
) -> Result<crate::ProxyRequest, http::Error> {
    let mut uri_parts = req.head.uri.clone().into_parts();
    uri_parts.scheme = target.scheme().cloned();
    uri_parts.authority = target.authority().cloned();
    req.head.uri = Uri::from_parts(uri_parts)?;

    // Update Host header to match the target so virtual hosting works correctly
    if let Some(authority) = target.authority() {
        if let Err(error) = req.head.headers.set("host", authority.as_str()) {
            tracing::warn!("Invalid target authority for Host header: {error}");
        }
    }

    Ok(req)
}

fn protocol_response_to_hyper(response: crate::ProxyResponse) -> http::Response<HyperBody> {
    to_hyper_response(response).unwrap_or_else(|error| {
        tracing::warn!("Could not adapt reverse response for Hyper: {error}");
        http::Response::builder()
            .status(http::StatusCode::BAD_GATEWAY)
            .body(HyperBody::full(Bytes::from_static(
                b"Invalid response headers",
            )))
            .unwrap_or_else(|_| http::Response::new(HyperBody::empty()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxyapi_models::HeaderBlock;

    fn request(uri: &str, host: &str) -> crate::ProxyRequest {
        let mut headers = HeaderBlock::new();
        headers.add("host", host).unwrap();
        crate::ProxyRequest::new(
            crate::RequestHead::new(
                http::Method::GET,
                uri.parse().unwrap(),
                http::Version::HTTP_11,
                headers,
            ),
            crate::ProxyBody::empty(),
        )
    }

    #[test]
    fn rewrite_uri_preserves_path_query_and_sets_target_host() {
        let req = request("/api/items?name=one", "client.example");
        let target: Uri = "https://upstream.example:8443".parse().unwrap();

        let req = rewrite_uri(req, &target).unwrap();

        assert_eq!(req.head.uri.scheme_str(), Some("https"));
        assert_eq!(
            req.head.uri.authority().map(|a| a.as_str()),
            Some("upstream.example:8443")
        );
        assert_eq!(req.head.uri.path(), "/api/items");
        assert_eq!(req.head.uri.query(), Some("name=one"));
        assert_eq!(
            req.head.headers.get("host"),
            Some(b"upstream.example:8443".as_slice())
        );
    }

    #[test]
    fn rewrite_uri_leaves_host_when_target_has_no_authority() {
        let req = request("/local", "client.example");
        let target: Uri = "/target-only".parse().unwrap();

        let req = rewrite_uri(req, &target).unwrap();

        assert_eq!(req.head.uri.path(), "/local");
        assert_eq!(
            req.head.headers.get("host"),
            Some(b"client.example".as_slice())
        );
    }
}
