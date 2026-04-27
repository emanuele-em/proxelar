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

pub(crate) fn now_millis() -> i64 {
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
/// When the `scripting` feature is enabled and a script engine is attached,
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
            .field("captured_request", &self.captured_request.is_some())
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

    /// Take the pending flow ID so the WS path can claim it before
    /// `collect_and_emit` would use it.
    pub(crate) fn take_pending_id(&mut self) -> Option<u64> {
        self.pending_id.take()
    }

    /// Clone the event sender for use in long-lived spawned tasks (e.g. WS frame pump).
    pub(crate) fn event_tx_clone(&self) -> mpsc::Sender<ProxyEvent> {
        self.event_tx.clone()
    }

    /// Run intercept logic for a replayed request and return it ready to forward.
    ///
    /// Unlike [`HttpHandler::handle_request`], this takes an already-captured
    /// [`ProxiedRequest`] so no body collection is needed. Returns `None` if the
    /// request was blocked or the intercept timed out.
    pub(crate) async fn handle_replayed_request(
        &mut self,
        req: ProxiedRequest,
    ) -> Option<Request<ProxyBody>> {
        let id = next_id();
        self.pending_id = Some(id);

        let mut method = req.method().clone();
        let mut uri = req.uri().clone();
        let version = req.version();
        let mut headers = req.headers().clone();
        let mut body_bytes = req.body().clone();

        self.captured_request = Some(ProxiedRequest::new(
            method.clone(),
            uri.clone(),
            version,
            headers.clone(),
            body_bytes.clone(),
            now_millis(),
        ));

        if let Some(ref cfg) = self.intercept {
            if cfg.is_enabled() {
                let snapshot = self.captured_request.clone().unwrap();
                let rx = cfg.register(id);
                if self
                    .event_tx
                    .try_send(ProxyEvent::RequestIntercepted {
                        id,
                        request: Box::new(snapshot),
                    })
                    .is_err()
                {
                    cfg.resolve(id, InterceptDecision::Forward);
                    tracing::warn!("Event channel full, skipping intercept for replay id={id}");
                } else {
                    match tokio::time::timeout(std::time::Duration::from_secs(300), rx).await {
                        Ok(Ok(InterceptDecision::Forward)) => {}
                        Ok(Ok(InterceptDecision::Modified {
                            method: m,
                            uri: u,
                            headers: h,
                            body: b,
                        })) => {
                            if let Ok(m) = m.parse() {
                                method = m;
                            }
                            if let Ok(u) = u.parse() {
                                uri = u;
                            }
                            headers = h;
                            body_bytes = b;
                            self.captured_request = Some(ProxiedRequest::new(
                                method.clone(),
                                uri.clone(),
                                version,
                                headers.clone(),
                                body_bytes.clone(),
                                now_millis(),
                            ));
                        }
                        Ok(Ok(InterceptDecision::Block { status, body })) => {
                            let status_code = http::StatusCode::from_u16(status)
                                .unwrap_or(http::StatusCode::BAD_GATEWAY);
                            let (parts, _) = Response::<()>::builder()
                                .status(status_code)
                                .body(())
                                .unwrap()
                                .into_parts();
                            collect_and_emit(self, parts, body);
                            return None;
                        }
                        _ => {
                            tracing::warn!("Intercept timed out for replay id={id}");
                            return None;
                        }
                    }
                }
            }
        }

        let mut builder = Request::builder().method(method).uri(uri).version(version);
        if let Some(h) = builder.headers_mut() {
            *h = headers;
        }
        builder.body(body::full(body_bytes)).ok()
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

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, Method, StatusCode, Uri, Version};
    use http_body_util::BodyExt;

    fn proxied_request() -> ProxiedRequest {
        let mut headers = HeaderMap::new();
        headers.insert("x-original", "yes".parse().unwrap());
        ProxiedRequest::new(
            Method::POST,
            "http://example.test/path?x=1".parse::<Uri>().unwrap(),
            Version::HTTP_11,
            headers,
            Bytes::from_static(b"request body"),
            100,
        )
    }

    async fn body_bytes(response: Response<ProxyBody>) -> Bytes {
        response.into_body().collect().await.unwrap().to_bytes()
    }

    #[test]
    fn debug_does_not_expose_large_captured_request() {
        let (event_tx, _event_rx) = mpsc::channel(1);
        let mut handler = CapturingHandler::new(event_tx);
        handler.captured_request = Some(proxied_request());

        let debug = format!("{handler:?}");

        assert!(debug.contains("CapturingHandler"));
        assert!(debug.contains("captured_request: true"));
        assert!(debug.contains(".."));
        assert!(!debug.contains("example.test"));
        assert!(!debug.contains("/path"));
        assert!(!debug.contains("x-original"));
        assert!(!debug.contains("request body"));
    }

    #[tokio::test]
    async fn collect_and_emit_uses_pending_id_and_rebuilds_response_body() {
        let (event_tx, mut event_rx) = mpsc::channel(1);
        let mut handler = CapturingHandler::new(event_tx);
        handler.pending_id = Some(77);
        handler.captured_request = Some(proxied_request());

        let (mut parts, _) = Response::builder()
            .status(StatusCode::ACCEPTED)
            .header("x-response", "ok")
            .body(())
            .unwrap()
            .into_parts();
        parts.version = Version::HTTP_11;

        let response = collect_and_emit(&mut handler, parts, Bytes::from_static(b"accepted"));

        assert_eq!(body_bytes(response).await.as_ref(), b"accepted");
        match event_rx.recv().await.unwrap() {
            ProxyEvent::RequestComplete {
                id,
                request,
                response,
            } => {
                assert_eq!(id, 77);
                assert_eq!(request.uri().path(), "/path");
                assert_eq!(response.status(), StatusCode::ACCEPTED);
                assert_eq!(response.headers()["x-response"], "ok");
                assert_eq!(response.body().as_ref(), b"accepted");
            }
            other => panic!("expected RequestComplete, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn collect_and_emit_without_captured_request_sends_no_event() {
        let (event_tx, mut event_rx) = mpsc::channel(1);
        let mut handler = CapturingHandler::new(event_tx);
        let (parts, _) = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(())
            .unwrap()
            .into_parts();

        let response = collect_and_emit(&mut handler, parts, Bytes::new());

        assert!(body_bytes(response).await.is_empty());
        assert!(event_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn handle_replayed_request_forwards_without_intercept() {
        let (event_tx, _event_rx) = mpsc::channel(1);
        let mut handler = CapturingHandler::new(event_tx);

        let request = handler
            .handle_replayed_request(proxied_request())
            .await
            .unwrap();

        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.uri().path(), "/path");
        assert_eq!(request.headers()["x-original"], "yes");
        let body = request.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"request body");
        assert!(handler.pending_id.is_some());
        assert_eq!(handler.captured_request.unwrap().uri().path(), "/path");
    }

    #[test]
    fn take_pending_id_and_event_sender_clone_return_internal_state() {
        let (event_tx, mut event_rx) = mpsc::channel(1);
        let mut handler = CapturingHandler::new(event_tx);
        handler.pending_id = Some(123);

        assert_eq!(handler.take_pending_id(), Some(123));
        assert_eq!(handler.take_pending_id(), None);

        handler
            .event_tx_clone()
            .try_send(ProxyEvent::Error {
                message: "cloned sender".to_owned(),
            })
            .unwrap();
        assert_eq!(
            event_rx.try_recv().unwrap().to_string_for_test(),
            "cloned sender"
        );
    }

    #[tokio::test]
    async fn handle_replayed_request_applies_modified_intercept_decision() {
        let (event_tx, mut event_rx) = mpsc::channel(4);
        let intercept = InterceptConfig::new();
        intercept.set_enabled(true);
        let mut handler = CapturingHandler::new(event_tx).with_intercept(Arc::clone(&intercept));

        let task =
            tokio::spawn(async move { handler.handle_replayed_request(proxied_request()).await });

        let id = match event_rx.recv().await.unwrap() {
            ProxyEvent::RequestIntercepted { id, request } => {
                assert_eq!(request.uri().path(), "/path");
                id
            }
            other => panic!("expected RequestIntercepted, got {other:?}"),
        };

        let mut headers = HeaderMap::new();
        headers.insert("x-modified", "yes".parse().unwrap());
        assert!(intercept.resolve(
            id,
            InterceptDecision::Modified {
                method: "PUT".to_owned(),
                uri: "http://example.test/changed".to_owned(),
                headers,
                body: Bytes::from_static(b"changed body"),
            },
        ));

        let request = task.await.unwrap().unwrap();
        assert_eq!(request.method(), Method::PUT);
        assert_eq!(request.uri().path(), "/changed");
        assert_eq!(request.headers()["x-modified"], "yes");
        let body = request.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"changed body");
    }

    #[tokio::test]
    async fn handle_replayed_request_forward_intercept_decision_keeps_original_request() {
        let (event_tx, mut event_rx) = mpsc::channel(4);
        let intercept = InterceptConfig::new();
        intercept.set_enabled(true);
        let mut handler = CapturingHandler::new(event_tx).with_intercept(Arc::clone(&intercept));

        let task =
            tokio::spawn(async move { handler.handle_replayed_request(proxied_request()).await });

        let id = match event_rx.recv().await.unwrap() {
            ProxyEvent::RequestIntercepted { id, request } => {
                assert_eq!(request.method(), Method::POST);
                assert_eq!(request.uri().path(), "/path");
                id
            }
            other => panic!("expected RequestIntercepted, got {other:?}"),
        };

        assert!(intercept.resolve(id, InterceptDecision::Forward));

        let request = task.await.unwrap().unwrap();
        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.uri().path(), "/path");
        assert_eq!(request.headers()["x-original"], "yes");
        let body = request.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"request body");
    }

    #[tokio::test]
    async fn handle_replayed_request_block_decision_emits_synthetic_completion() {
        let (event_tx, mut event_rx) = mpsc::channel(4);
        let intercept = InterceptConfig::new();
        intercept.set_enabled(true);
        let mut handler = CapturingHandler::new(event_tx).with_intercept(Arc::clone(&intercept));

        let task =
            tokio::spawn(async move { handler.handle_replayed_request(proxied_request()).await });

        let id = match event_rx.recv().await.unwrap() {
            ProxyEvent::RequestIntercepted { id, .. } => id,
            other => panic!("expected RequestIntercepted, got {other:?}"),
        };

        assert!(intercept.resolve(
            id,
            InterceptDecision::Block {
                status: 418,
                body: Bytes::from_static(b"blocked"),
            },
        ));

        assert!(task.await.unwrap().is_none());
        match event_rx.recv().await.unwrap() {
            ProxyEvent::RequestComplete {
                request, response, ..
            } => {
                assert_eq!(request.uri().path(), "/path");
                assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
                assert_eq!(response.body().as_ref(), b"blocked");
            }
            other => panic!("expected RequestComplete, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn handle_replayed_request_forwards_when_intercept_event_channel_is_full() {
        let (event_tx, mut event_rx) = mpsc::channel(1);
        event_tx
            .try_send(ProxyEvent::Error {
                message: "fill channel".to_owned(),
            })
            .unwrap();
        let intercept = InterceptConfig::new();
        intercept.set_enabled(true);
        let mut handler = CapturingHandler::new(event_tx).with_intercept(intercept);

        let request = handler
            .handle_replayed_request(proxied_request())
            .await
            .unwrap();

        assert_eq!(request.method(), Method::POST);
        assert_eq!(
            event_rx.recv().await.unwrap().to_string_for_test(),
            "fill channel"
        );
    }

    #[tokio::test]
    async fn send_event_drops_full_or_closed_channels_without_panicking() {
        let (event_tx, mut event_rx) = mpsc::channel(1);
        let handler = CapturingHandler::new(event_tx);
        handler.send_event(ProxyEvent::Error {
            message: "first".to_owned(),
        });
        handler.send_event(ProxyEvent::Error {
            message: "second".to_owned(),
        });
        assert_eq!(event_rx.recv().await.unwrap().to_string_for_test(), "first");

        drop(event_rx);
        handler.send_event(ProxyEvent::Error {
            message: "closed".to_owned(),
        });
    }

    #[cfg(feature = "scripting")]
    #[tokio::test]
    async fn collect_and_emit_runs_script_response_hook() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(
            br#"
            function on_response(req, res)
                res.status = 201
                res.headers["x-script"] = "yes"
                res.body = "scripted"
                return res
            end
            "#,
        )
        .unwrap();
        file.flush().unwrap();

        let engine = Arc::new(crate::scripting::ScriptEngine::new(file.path()).unwrap());
        let (event_tx, mut event_rx) = mpsc::channel(1);
        let mut handler = CapturingHandler::new(event_tx).with_script_engine(engine);
        handler.captured_request = Some(proxied_request());

        let (parts, _) = Response::builder()
            .status(StatusCode::OK)
            .body(())
            .unwrap()
            .into_parts();

        let response = collect_and_emit(&mut handler, parts, Bytes::from_static(b"original"));

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()["x-script"], "yes");
        assert_eq!(body_bytes(response).await.as_ref(), b"scripted");
        match event_rx.recv().await.unwrap() {
            ProxyEvent::RequestComplete { response, .. } => {
                assert_eq!(response.status(), StatusCode::CREATED);
                assert_eq!(response.headers()["x-script"], "yes");
                assert_eq!(response.body().as_ref(), b"scripted");
            }
            other => panic!("expected RequestComplete, got {other:?}"),
        }
    }

    #[cfg(feature = "scripting")]
    #[tokio::test]
    async fn collect_and_emit_passes_through_on_script_response_error() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(
            br#"
            function on_response(req, res)
                error("boom")
            end
            "#,
        )
        .unwrap();
        file.flush().unwrap();

        let engine = Arc::new(crate::scripting::ScriptEngine::new(file.path()).unwrap());
        let (event_tx, _event_rx) = mpsc::channel(1);
        let mut handler = CapturingHandler::new(event_tx).with_script_engine(engine);

        let (parts, _) = Response::builder()
            .status(StatusCode::OK)
            .body(())
            .unwrap()
            .into_parts();

        let response = collect_and_emit(&mut handler, parts, Bytes::from_static(b"original"));

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_bytes(response).await.as_ref(), b"original");
    }

    #[cfg(feature = "scripting")]
    #[tokio::test]
    async fn collect_and_emit_passes_through_when_script_returns_nil_response() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(
            br#"
            function on_response(req, res)
                return nil
            end
            "#,
        )
        .unwrap();
        file.flush().unwrap();

        let engine = Arc::new(crate::scripting::ScriptEngine::new(file.path()).unwrap());
        let (event_tx, mut event_rx) = mpsc::channel(1);
        let mut handler = CapturingHandler::new(event_tx).with_script_engine(engine);
        handler.captured_request = Some(proxied_request());

        let (parts, _) = Response::builder()
            .status(StatusCode::OK)
            .header("x-original-response", "yes")
            .body(())
            .unwrap()
            .into_parts();

        let response = collect_and_emit(&mut handler, parts, Bytes::from_static(b"original"));

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-original-response"], "yes");
        assert_eq!(body_bytes(response).await.as_ref(), b"original");
        match event_rx.recv().await.unwrap() {
            ProxyEvent::RequestComplete { response, .. } => {
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(response.headers()["x-original-response"], "yes");
                assert_eq!(response.body().as_ref(), b"original");
            }
            other => panic!("expected RequestComplete, got {other:?}"),
        }
    }

    trait ProxyEventTestExt {
        fn to_string_for_test(&self) -> &str;
    }

    impl ProxyEventTestExt for ProxyEvent {
        fn to_string_for_test(&self) -> &str {
            match self {
                ProxyEvent::Error { message } => message,
                _ => "",
            }
        }
    }
}
