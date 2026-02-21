use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Limited};
use hyper::{Request, Response};
use proxyapi_models::{ProxiedRequest, ProxiedResponse};
use tokio::sync::mpsc;

use crate::body::{self, ProxyBody};
use crate::event::{next_id, ProxyEvent};
use crate::{HttpContext, HttpHandler, RequestOrResponse};

/// Maximum body size the proxy will collect (100 MB).
///
/// Bodies exceeding this limit are replaced with an empty body in the
/// captured event. The proxied traffic itself is unaffected.
const MAX_BODY_SIZE: usize = 100 * 1024 * 1024;

fn now_millis() -> i64 {
    chrono::Local::now().timestamp_millis()
}

/// Collect the response body, emit a [`ProxyEvent`], and return the reconstructed response.
///
/// This is the single source of truth for response capture, used by both
/// forward and reverse proxy paths.
pub fn collect_and_emit(
    handler: &mut CapturingHandler,
    parts: http::response::Parts,
    body_bytes: Bytes,
) -> Response<ProxyBody> {
    let proxied_response = ProxiedResponse::new(
        parts.status,
        parts.version,
        parts.headers.clone(),
        body_bytes.clone(),
        now_millis(),
    );

    if let Some(request) = handler.take_captured_request() {
        let event = ProxyEvent::RequestComplete {
            id: next_id(),
            request: Box::new(request),
            response: Box::new(proxied_response),
        };
        handler.send_event(event);
    }

    Response::from_parts(parts, body::full(body_bytes))
}

/// Collect response body bytes up to [`MAX_BODY_SIZE`], logging a warning on failure.
pub async fn collect_body(body: hyper::body::Incoming) -> Bytes {
    Limited::new(body, MAX_BODY_SIZE)
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .unwrap_or_else(|e| {
            tracing::warn!(
                "Failed to collect response body (possibly exceeds {}MB limit): {e}",
                MAX_BODY_SIZE / (1024 * 1024)
            );
            Bytes::new()
        })
}

/// Default handler that captures request/response pairs and emits [`ProxyEvent`]s.
#[derive(Clone, Debug)]
pub struct CapturingHandler {
    event_tx: mpsc::Sender<ProxyEvent>,
    captured_request: Option<ProxiedRequest>,
}

impl CapturingHandler {
    /// Create a new handler that sends events to the given channel.
    #[must_use]
    pub fn new(event_tx: mpsc::Sender<ProxyEvent>) -> Self {
        Self {
            event_tx,
            captured_request: None,
        }
    }

    pub(crate) fn take_captured_request(&mut self) -> Option<ProxiedRequest> {
        self.captured_request.take()
    }

    pub(crate) fn send_event(&self, event: ProxyEvent) {
        match self.event_tx.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!("Event channel full, dropping event");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::debug!("Event channel closed");
            }
        }
    }
}

#[async_trait]
impl HttpHandler for CapturingHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<hyper::body::Incoming>,
    ) -> RequestOrResponse {
        let (parts, incoming) = req.into_parts();
        let body_bytes = Limited::new(incoming, MAX_BODY_SIZE)
            .collect()
            .await
            .map(http_body_util::Collected::to_bytes)
            .unwrap_or_else(|e| {
                tracing::warn!("Failed to collect request body: {e}");
                Bytes::new()
            });

        let proxied_request = ProxiedRequest::new(
            parts.method.clone(),
            parts.uri.clone(),
            parts.version,
            parts.headers.clone(),
            body_bytes.clone(),
            now_millis(),
        );
        self.captured_request = Some(proxied_request);

        let req = Request::from_parts(parts, body::full(body_bytes));
        RequestOrResponse::Request(req)
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        res: Response<hyper::body::Incoming>,
    ) -> Response<ProxyBody> {
        let (parts, incoming) = res.into_parts();
        let body_bytes = collect_body(incoming).await;
        collect_and_emit(self, parts, body_bytes)
    }
}
