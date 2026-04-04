use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Limited};
use hyper::{Request, Response};
use proxyapi_models::{ProxiedRequest, ProxiedResponse};
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::body::{self, ProxyBody};
use crate::event::{next_id, ProxyEvent};
use crate::intercept::{InterceptConfig, InterceptDecision};
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
/// forward and reverse proxy paths. When scripting is enabled, the Lua
/// `on_response` hook is called here before building the final response.
pub fn collect_and_emit(
    handler: &mut CapturingHandler,
    #[allow(unused_mut)] mut parts: http::response::Parts,
    #[allow(unused_mut)] mut body_bytes: Bytes,
) -> Response<ProxyBody> {
    // Run Lua on_response hook (if scripting is enabled and a script is loaded).
    #[cfg(feature = "scripting")]
    if let Some(ref engine) = handler.script_engine {
        let (req_method, req_url) = handler
            .captured_request
            .as_ref()
            .map(|r| (r.method().as_str().to_owned(), r.uri().to_string()))
            .unwrap_or_default();

        match engine.on_response(
            &req_method,
            &req_url,
            parts.status.as_u16(),
            &parts.headers,
            &body_bytes,
        ) {
            Ok(crate::scripting::ScriptResponseAction::Modified {
                status,
                headers,
                body,
            }) => {
                if let Ok(s) = http::StatusCode::from_u16(status) {
                    parts.status = s;
                }
                parts.headers = headers;
                body_bytes = body;
            }
            Ok(crate::scripting::ScriptResponseAction::PassThrough) => {}
            Err(e) => {
                tracing::warn!("Lua on_response error (passing through): {e}");
            }
        }
    }

    let proxied_response = ProxiedResponse::new(
        parts.status,
        parts.version,
        parts.headers.clone(),
        body_bytes.clone(),
        now_millis(),
    );

    if let Some(request) = handler.take_captured_request() {
        // Use the ID assigned at the start of handle_request (intercept flow)
        // so that RequestIntercepted and RequestComplete share the same ID.
        // Fall back to next_id() for the normal (non-intercept) path.
        let id = handler.pending_id.take().unwrap_or_else(next_id);
        let event = ProxyEvent::RequestComplete {
            id,
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
///
/// When the `scripting` feature is enabled and a [`ScriptEngine`] is attached,
/// Lua `on_request` / `on_response` hooks are called for every request/response.
#[derive(Clone)]
pub struct CapturingHandler {
    event_tx: mpsc::Sender<ProxyEvent>,
    captured_request: Option<ProxiedRequest>,
    /// ID assigned at the start of `handle_request`. Carried through to
    /// `collect_and_emit` so that `RequestIntercepted` and `RequestComplete`
    /// events share the same ID and the UI can correlate them.
    pending_id: Option<u64>,
    intercept: Option<Arc<InterceptConfig>>,
    #[cfg(feature = "scripting")]
    script_engine: Option<Arc<crate::scripting::ScriptEngine>>,
}

impl std::fmt::Debug for CapturingHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapturingHandler")
            .field("event_tx", &self.event_tx)
            .field("captured_request", &self.captured_request)
            .field("pending_id", &self.pending_id)
            .finish_non_exhaustive()
    }
}

impl CapturingHandler {
    /// Create a new handler that sends events to the given channel.
    #[must_use]
    pub fn new(event_tx: mpsc::Sender<ProxyEvent>) -> Self {
        Self {
            event_tx,
            captured_request: None,
            pending_id: None,
            intercept: None,
            #[cfg(feature = "scripting")]
            script_engine: None,
        }
    }

    /// Attach an intercept controller for interactive request/response editing.
    #[must_use]
    pub fn with_intercept(mut self, cfg: Arc<InterceptConfig>) -> Self {
        self.intercept = Some(cfg);
        self
    }

    /// Attach a Lua script engine for request/response transformation.
    #[cfg(feature = "scripting")]
    #[must_use]
    pub fn with_script_engine(mut self, engine: Arc<crate::scripting::ScriptEngine>) -> Self {
        self.script_engine = Some(engine);
        self
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
        // Assign a stable ID at request start so that RequestIntercepted and
        // RequestComplete events for the same flow share the same ID.
        let id = next_id();
        self.pending_id = Some(id);

        let (mut parts, incoming) = req.into_parts();
        let mut body_bytes = Limited::new(incoming, MAX_BODY_SIZE)
            .collect()
            .await
            .map(http_body_util::Collected::to_bytes)
            .unwrap_or_else(|e| {
                tracing::warn!("Failed to collect request body: {e}");
                Bytes::new()
            });

        // Run Lua on_request hook (if scripting is enabled and a script is loaded).
        // This runs synchronously — the body has already been collected above.
        #[cfg(feature = "scripting")]
        if let Some(ref engine) = self.script_engine {
            match engine.on_request(
                parts.method.as_str(),
                &parts.uri.to_string(),
                &parts.headers,
                &body_bytes,
            ) {
                Ok(crate::scripting::ScriptRequestAction::Forward {
                    method,
                    url,
                    headers,
                    body,
                }) => {
                    if let Ok(m) = method.parse() {
                        parts.method = m;
                    }
                    if let Ok(u) = url.parse() {
                        parts.uri = u;
                    }
                    parts.headers = headers;
                    body_bytes = body;
                }
                Ok(crate::scripting::ScriptRequestAction::ShortCircuit {
                    status,
                    headers,
                    body,
                }) => {
                    // Capture the original request before short-circuiting
                    let proxied_request = ProxiedRequest::new(
                        parts.method.clone(),
                        parts.uri.clone(),
                        parts.version,
                        parts.headers.clone(),
                        body_bytes.clone(),
                        now_millis(),
                    );
                    self.captured_request = Some(proxied_request);

                    let status_code = http::StatusCode::from_u16(status)
                        .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
                    let mut builder = Response::builder().status(status_code);
                    if let Some(h) = builder.headers_mut() {
                        *h = headers;
                    }
                    let response = builder
                        .body(body::full(body))
                        .unwrap_or_else(|_| Response::new(body::empty()));
                    return RequestOrResponse::Response(response);
                }
                Ok(crate::scripting::ScriptRequestAction::PassThrough) => {}
                Err(e) => {
                    tracing::warn!("Lua on_request error (passing through): {e}");
                }
            }
        }

        // Intercept mode: pause the request and wait for a UI decision.
        if let Some(ref cfg) = self.intercept {
            if cfg.is_enabled() {
                let snapshot = ProxiedRequest::new(
                    parts.method.clone(),
                    parts.uri.clone(),
                    parts.version,
                    parts.headers.clone(),
                    body_bytes.clone(),
                    now_millis(),
                );
                // Register before sending the event so the UI can always resolve.
                let rx = cfg.register(id);
                let event = ProxyEvent::RequestIntercepted {
                    id,
                    request: Box::new(snapshot.clone()),
                };
                // Non-blocking send: if the channel is full, skip interception
                // and fall through to normal forwarding so the request isn't lost.
                if self.event_tx.try_send(event).is_err() {
                    cfg.resolve(id, InterceptDecision::Forward);
                    tracing::warn!("Event channel full, skipping intercept for id={id}");
                } else {
                    self.captured_request = Some(snapshot);

                    match tokio::time::timeout(std::time::Duration::from_secs(300), rx).await {
                        Ok(Ok(InterceptDecision::Forward)) => {
                            // Pass through unchanged — fall to the return below.
                        }
                        Ok(Ok(InterceptDecision::Modified {
                            method,
                            uri,
                            headers,
                            body,
                        })) => {
                            if let Ok(m) = method.parse() {
                                parts.method = m;
                            }
                            if let Ok(u) = uri.parse() {
                                parts.uri = u;
                            }
                            parts.headers = headers;
                            body_bytes = body;
                            // Update the captured snapshot to reflect the edits.
                            self.captured_request = Some(ProxiedRequest::new(
                                parts.method.clone(),
                                parts.uri.clone(),
                                parts.version,
                                parts.headers.clone(),
                                body_bytes.clone(),
                                now_millis(),
                            ));
                        }
                        Ok(Ok(InterceptDecision::Block { status, body })) => {
                            // Short-circuit: captured_request is already set above.
                            let status_code = http::StatusCode::from_u16(status)
                                .unwrap_or(http::StatusCode::BAD_GATEWAY);
                            let response = Response::builder()
                                .status(status_code)
                                .body(body::full(body))
                                .unwrap_or_else(|_| Response::new(body::empty()));
                            return RequestOrResponse::Response(response);
                        }
                        _ => {
                            // Timeout or sender dropped (intercept turned off):
                            // return 504 so the client gets a clear error.
                            tracing::warn!("Intercept timed out for id={id}, returning 504");
                            let response = Response::builder()
                                .status(http::StatusCode::GATEWAY_TIMEOUT)
                                .body(body::empty())
                                .unwrap_or_else(|_| Response::new(body::empty()));
                            return RequestOrResponse::Response(response);
                        }
                    }

                    let req = Request::from_parts(parts, body::full(body_bytes));
                    return RequestOrResponse::Request(req);
                }
            }
        }

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
