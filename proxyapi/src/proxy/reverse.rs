use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use hyper::service::service_fn;
use hyper::{Request, Uri};
use hyper_util::rt::TokioIo;
use proxelar_proto::http1::{
    serve_connection_with_upgrades, ConnectionConfig, ServerConnection, UpgradeReceiver,
};
use proxelar_proto::{BoxFuture, HttpService, ProtocolError, ProxyRequest, ProxyResponse};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::handler::CapturingHandler;
use crate::hyper_adapter::{
    from_hyper_request, from_hyper_response, to_hyper_request, to_hyper_response, HyperBody,
};
use crate::rewind::Rewind;
use crate::{HttpContext, HttpHandler, RequestOrResponse};

use super::{
    forward::{
        is_h2_preface, is_protocol_websocket_upgrade, pump_native_websocket, sniff_stream_protocol,
    },
    http1::{NativePool, NativeUpstream},
    is_benign_shutdown_error, prepare_upstream_request, sanitize_response_for_client,
    serve_auto_connection, BoxError, Client,
};

pub(super) async fn handle_connection(
    mut stream: TcpStream,
    remote_addr: SocketAddr,
    handler: CapturingHandler,
    target: Uri,
    _client: Arc<Client>,
    native_pool: Arc<NativePool>,
    route: Option<String>,
) {
    let (_, buffered) = match sniff_stream_protocol(&mut stream).await {
        Ok(detected) => detected,
        Err(error) => {
            tracing::debug!("Reverse proxy protocol detection failed: {error}");
            return;
        }
    };
    let h2 = is_h2_preface(&buffered);
    let stream = Rewind::new_buffered(stream, buffered);
    if !h2 {
        let upgrade = Arc::new(Mutex::new(None));
        let service = ReverseHttp1Service {
            remote_addr,
            handler,
            target,
            upstream: NativeUpstream::shared(native_pool, route),
            upgrade: Arc::clone(&upgrade),
        };
        match serve_connection_with_upgrades(stream, service, ConnectionConfig::default()).await {
            Ok(ServerConnection::Upgraded(client)) => {
                if let Some(ReverseUpgrade {
                    upstream,
                    handler,
                    conn_id,
                }) = upgrade.lock().await.take()
                {
                    match upstream.wait().await {
                        Ok(server) => pump_native_websocket(conn_id, client, server, handler).await,
                        Err(error) => {
                            tracing::debug!("Reverse WebSocket upgrade failed: {error}");
                        }
                    }
                }
            }
            Ok(ServerConnection::Closed) => {}
            Err(error) => tracing::debug!("Reverse HTTP/1 connection error: {error}"),
        }
        return;
    }

    if let Err(error) = super::http2::serve_reverse(
        stream,
        remote_addr,
        handler,
        target,
        NativeUpstream::shared(native_pool, route),
    )
    .await
    {
        if !is_benign_shutdown_error(error.as_ref()) {
            tracing::debug!("Reverse HTTP/2 connection error: {error}");
        }
    }
}

#[allow(dead_code)]
async fn serve_hyper_connection<I>(
    stream: I,
    remote_addr: SocketAddr,
    handler: CapturingHandler,
    target: Uri,
    client: Arc<Client>,
) -> Result<(), BoxError>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
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

    serve_auto_connection(io, service).await
}

struct ReverseHttp1Service {
    remote_addr: SocketAddr,
    handler: CapturingHandler,
    target: Uri,
    upstream: NativeUpstream,
    upgrade: Arc<Mutex<Option<ReverseUpgrade>>>,
}

struct ReverseUpgrade {
    upstream: UpgradeReceiver,
    handler: CapturingHandler,
    conn_id: u64,
}

impl HttpService for ReverseHttp1Service {
    fn call(
        &mut self,
        request: ProxyRequest,
    ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
        let mut handler = self.handler.clone();
        let target = self.target.clone();
        let upstream = self.upstream.clone();
        let upgrade = Arc::clone(&self.upgrade);
        let remote_addr = self.remote_addr;
        Box::pin(async move {
            let ctx = HttpContext { remote_addr };
            let request = match handler.handle_request(&ctx, request).await {
                RequestOrResponse::Request(request) => request,
                RequestOrResponse::Response(response) => return Ok(response),
            };
            let websocket = is_protocol_websocket_upgrade(&request);
            let request = match rewrite_uri(request, &target) {
                Ok(request) => request,
                Err(error) => {
                    tracing::error!("Failed to rewrite native H1 URI: {error}");
                    return Ok(handler.synthetic_protocol_response(
                        http::StatusCode::BAD_GATEWAY,
                        http::HeaderMap::new(),
                        Bytes::from_static(b"Bad Gateway: URI rewrite failed"),
                    ));
                }
            };
            match upstream.send(request, websocket).await {
                Ok(mut response)
                    if websocket
                        && response.response.head.status
                            == http::StatusCode::SWITCHING_PROTOCOLS =>
                {
                    let Some(upstream) = response.upgrade.take() else {
                        return Ok(handler.synthetic_protocol_response(
                            http::StatusCode::BAD_GATEWAY,
                            http::HeaderMap::new(),
                            Bytes::from_static(b"Bad Gateway: missing WebSocket upgrade"),
                        ));
                    };
                    let ws_response = proxyapi_models::ProxiedResponse::new(
                        response.response.head.status,
                        response.response.head.version,
                        response.response.head.headers.clone(),
                        Bytes::new(),
                        crate::handler::now_millis(),
                    );
                    let conn_id = handler
                        .take_pending_id()
                        .unwrap_or_else(crate::event::next_id);
                    if let Some(captured_req) = handler.take_captured_request() {
                        handler.send_event(crate::event::ProxyEvent::WebSocketConnected {
                            id: conn_id,
                            request: Box::new(captured_req),
                            response: Box::new(ws_response),
                        });
                    }
                    *upgrade.lock().await = Some(ReverseUpgrade {
                        upstream,
                        handler,
                        conn_id,
                    });
                    Ok(response.response)
                }
                Ok(response) => Ok(handler.handle_response(&ctx, response.response).await),
                Err(error) => {
                    tracing::error!("Native reverse HTTP/1 error: {error}");
                    Ok(handler.synthetic_protocol_response(
                        http::StatusCode::BAD_GATEWAY,
                        http::HeaderMap::new(),
                        Bytes::from_static(b"Bad Gateway"),
                    ))
                }
            }
        })
    }
}

/// Rewrite the request URI to point at the reverse proxy target, preserving
/// the original path and query. Also updates the `Host` header to match.
pub(super) fn rewrite_uri(
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
