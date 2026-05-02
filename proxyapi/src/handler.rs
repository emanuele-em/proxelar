use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use hyper::body::Body as HttpBody;
use hyper::{Request, Response};
use proxyapi_models::{ProxiedRequest, ProxiedResponse};
use std::sync::Arc;
use tokio::sync::{mpsc, Notify};

use crate::body::{self, BodyCapture, BodySnapshot, ProxyBody};
use crate::event::{next_id, ProxyEvent};
use crate::intercept::{InterceptConfig, InterceptDecision};
use crate::{HttpContext, HttpHandler, RequestOrResponse};

/// Default body capture limit.
///
/// `None` keeps the default mitmproxy-style behavior: buffer complete HTTP
/// bodies for capture/editing unless the user configures an explicit limit.
pub const DEFAULT_BODY_CAPTURE_LIMIT: Option<usize> = None;

enum BodyCollection {
    Complete(Bytes),
    Exceeded { captured: Bytes, body: ProxyBody },
}

enum RequestBody {
    Buffered(Bytes),
    Streaming { captured: Bytes, body: ProxyBody },
}

impl RequestBody {
    fn hook_bytes(&self) -> &Bytes {
        match self {
            Self::Buffered(bytes)
            | Self::Streaming {
                captured: bytes, ..
            } => bytes,
        }
    }

    fn apply_modified_body(&mut self, original_hook_body: &Bytes, modified_body: Bytes) {
        if matches!(self, Self::Streaming { .. }) && modified_body == *original_hook_body {
            return;
        }

        *self = Self::Buffered(modified_body);
    }
}

pub(crate) fn now_millis() -> i64 {
    chrono::Local::now().timestamp_millis()
}

#[derive(Clone)]
enum CapturedRequest {
    Buffered(ProxiedRequest),
    Streaming {
        method: http::Method,
        uri: http::Uri,
        version: http::Version,
        headers: http::HeaderMap,
        body: BodyCapture,
        done: Arc<Notify>,
        time: i64,
    },
}

impl CapturedRequest {
    fn buffered(request: ProxiedRequest) -> Self {
        Self::Buffered(request)
    }

    fn streaming(
        parts: &http::request::Parts,
        body: BodyCapture,
        done: Arc<Notify>,
        time: i64,
    ) -> Self {
        Self::Streaming {
            method: parts.method.clone(),
            uri: parts.uri.clone(),
            version: parts.version,
            headers: parts.headers.clone(),
            body,
            done,
            time,
        }
    }

    fn into_proxied_request(self) -> ProxiedRequest {
        match self {
            Self::Buffered(request) => request,
            Self::Streaming {
                method,
                uri,
                version,
                headers,
                body,
                done: _,
                time,
            } => {
                let snapshot = body.snapshot();
                log_truncated_capture("request", &snapshot);
                ProxiedRequest::new(method, uri, version, headers, snapshot.bytes, time)
            }
        }
    }

    async fn into_proxied_request_after_capture(self) -> ProxiedRequest {
        match self {
            Self::Buffered(request) => request,
            Self::Streaming {
                method,
                uri,
                version,
                headers,
                body,
                done,
                time,
            } => {
                done.notified().await;
                let snapshot = body.snapshot();
                log_truncated_capture("request", &snapshot);
                ProxiedRequest::new(method, uri, version, headers, snapshot.bytes, time)
            }
        }
    }

    #[cfg(feature = "scripting")]
    fn request_line(&self) -> (String, String) {
        match self {
            Self::Buffered(request) => (
                request.method().as_str().to_owned(),
                request.uri().to_string(),
            ),
            Self::Streaming { method, uri, .. } => (method.as_str().to_owned(), uri.to_string()),
        }
    }
}

fn log_truncated_capture(kind: &str, snapshot: &BodySnapshot) {
    if snapshot.truncated {
        tracing::warn!(
            "Captured {kind} body truncated at {} bytes after seeing {} bytes; proxied traffic was streamed through unchanged",
            snapshot.bytes.len(),
            snapshot.total_seen
        );
    }
}

fn try_send_event(tx: &mpsc::Sender<ProxyEvent>, event: ProxyEvent) {
    match tx.try_send(event) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            tracing::warn!("Event channel full, dropping event");
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            tracing::debug!("Event channel closed");
        }
    }
}

fn send_request_complete(
    tx: &mpsc::Sender<ProxyEvent>,
    id: u64,
    request: ProxiedRequest,
    response: ProxiedResponse,
) {
    try_send_event(
        tx,
        ProxyEvent::RequestComplete {
            id,
            request: Box::new(request),
            response: Box::new(response),
        },
    );
}

fn synthetic_response_parts(
    status: http::StatusCode,
    headers: http::HeaderMap,
    body: Bytes,
) -> (http::response::Parts, Bytes) {
    let mut builder = Response::builder().status(status);
    if let Some(response_headers) = builder.headers_mut() {
        *response_headers = headers;
    }

    builder
        .body(body)
        .expect("synthetic response components should be valid")
        .into_parts()
}

struct HookedResponse {
    parts: http::response::Parts,
    body: HookedResponseBody,
}

enum HookedResponseBody {
    Original(Bytes),
    #[cfg(feature = "scripting")]
    Replaced(Bytes),
}

impl HookedResponseBody {
    fn is_original(&self) -> bool {
        matches!(self, Self::Original(_))
    }

    fn into_bytes(self) -> Bytes {
        match self {
            Self::Original(bytes) => bytes,
            #[cfg(feature = "scripting")]
            Self::Replaced(bytes) => bytes,
        }
    }
}

/// Collect body bytes for byte-editing features, up to the configured limit.
///
/// When the body exceeds the limit, returns a reconstructed streaming body that
/// first replays already-read bytes, then continues the original body.
async fn collect_body<B>(mut body: B, limit: Option<usize>, kind: &'static str) -> BodyCollection
where
    B: HttpBody<Data = Bytes, Error = hyper::Error> + Send + Sync + Unpin + 'static,
{
    let mut buffer = BytesMut::new();

    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(e) => {
                tracing::warn!("Failed to collect {kind} body: {e}");
                return BodyCollection::Complete(Bytes::new());
            }
        };

        let Ok(data) = frame.into_data() else {
            continue;
        };

        let Some(limit) = limit else {
            buffer.extend_from_slice(&data);
            continue;
        };

        if buffer.len().saturating_add(data.len()) > limit {
            tracing::warn!(
                "{kind} body exceeded editable limit of {limit} bytes; streaming through without body editing"
            );
            let keep = limit.saturating_sub(buffer.len()).min(data.len());
            if keep > 0 {
                buffer.extend_from_slice(&data[..keep]);
            }
            let captured = buffer.freeze();
            let overflow = data.slice(keep..);
            return BodyCollection::Exceeded {
                body: body::prefix([captured.clone(), overflow], body),
                captured,
            };
        }

        buffer.extend_from_slice(&data);
    }

    BodyCollection::Complete(buffer.freeze())
}

/// Default handler that captures request/response pairs and emits [`ProxyEvent`]s.
///
/// When the `scripting` feature is enabled and a script engine is attached,
/// Lua `on_request` / `on_response` hooks are called for every request/response.
#[derive(Clone)]
pub struct CapturingHandler {
    event_tx: mpsc::Sender<ProxyEvent>,
    captured_request: Option<CapturedRequest>,
    /// ID assigned at the start of `handle_request` so that related events
    /// share the same ID and the UI can correlate them.
    pending_id: Option<u64>,
    intercept: Option<Arc<InterceptConfig>>,
    body_capture_limit: Option<usize>,
    #[cfg(feature = "scripting")]
    script_engine: Option<Arc<crate::scripting::ScriptEngine>>,
}

impl std::fmt::Debug for CapturingHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapturingHandler")
            .field("event_tx", &self.event_tx)
            .field("captured_request", &self.captured_request.is_some())
            .field("pending_id", &self.pending_id)
            .field("body_capture_limit", &self.body_capture_limit)
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
            body_capture_limit: DEFAULT_BODY_CAPTURE_LIMIT,
            #[cfg(feature = "scripting")]
            script_engine: None,
        }
    }

    /// Set the maximum body bytes buffered for capture and byte-editing paths.
    ///
    /// `None` means unlimited capture. `Some(limit)` streams bodies above the
    /// limit through unchanged and captures only up to the configured limit.
    #[must_use]
    pub fn with_body_capture_limit(mut self, limit: Option<usize>) -> Self {
        self.body_capture_limit = limit;
        self
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
        self.take_captured_request_state()
            .map(CapturedRequest::into_proxied_request)
    }

    fn take_captured_request_state(&mut self) -> Option<CapturedRequest> {
        self.captured_request.take()
    }

    fn should_buffer_response(&self) -> bool {
        #[cfg(feature = "scripting")]
        if self.script_engine.is_some() {
            return true;
        }

        false
    }

    fn should_buffer_request(&self) -> bool {
        if self.intercept.as_ref().is_some_and(|cfg| cfg.is_enabled()) {
            return true;
        }

        #[cfg(feature = "scripting")]
        if self.script_engine.is_some() {
            return true;
        }

        false
    }

    /// Take the pending flow ID so the WS path can claim it before response
    /// completion would use it.
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

        self.captured_request = Some(CapturedRequest::buffered(ProxiedRequest::new(
            method.clone(),
            uri.clone(),
            version,
            headers.clone(),
            body_bytes.clone(),
            now_millis(),
        )));

        if let Some(ref cfg) = self.intercept {
            if cfg.is_enabled() {
                let snapshot = self
                    .captured_request
                    .clone()
                    .unwrap()
                    .into_proxied_request();
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
                            self.captured_request =
                                Some(CapturedRequest::buffered(ProxiedRequest::new(
                                    method.clone(),
                                    uri.clone(),
                                    version,
                                    headers.clone(),
                                    body_bytes.clone(),
                                    now_millis(),
                                )));
                        }
                        Ok(Ok(InterceptDecision::Block { status, body })) => {
                            let status_code = http::StatusCode::from_u16(status)
                                .unwrap_or(http::StatusCode::BAD_GATEWAY);
                            let (parts, _) = Response::<()>::builder()
                                .status(status_code)
                                .body(())
                                .unwrap()
                                .into_parts();
                            self.emit_captured_response(parts, body);
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
        try_send_event(&self.event_tx, event);
    }

    pub(crate) fn synthetic_response(
        &mut self,
        status: http::StatusCode,
        headers: http::HeaderMap,
        body: Bytes,
    ) -> Response<ProxyBody> {
        let (parts, body) = synthetic_response_parts(status, headers, body);
        self.emit_response_snapshot(&parts, body.clone());
        Response::from_parts(parts, body::full(body))
    }

    pub(crate) fn emit_synthetic_completion(
        &mut self,
        status: http::StatusCode,
        headers: http::HeaderMap,
        body: Bytes,
    ) {
        let (parts, body) = synthetic_response_parts(status, headers, body);
        self.emit_response_snapshot(&parts, body);
    }

    pub(crate) async fn handle_upstream_response<B>(
        &mut self,
        res: Response<B>,
    ) -> Response<ProxyBody>
    where
        B: HttpBody<Data = Bytes, Error = hyper::Error> + Send + Sync + Unpin + 'static,
    {
        let (parts, body) = res.into_parts();
        if !self.should_buffer_response() {
            return self.stream_response(parts, body);
        }

        match collect_body(body, self.body_capture_limit, "response").await {
            BodyCollection::Complete(body_bytes) => {
                self.finish_buffered_response(parts, body_bytes)
            }
            BodyCollection::Exceeded { captured, body } => {
                self.finish_limited_response(parts, captured, body)
            }
        }
    }

    pub(crate) async fn record_upstream_response<B>(&mut self, res: Response<B>)
    where
        B: HttpBody<Data = Bytes, Error = hyper::Error> + Send + Sync + Unpin + 'static,
    {
        let (parts, body) = res.into_parts();
        match collect_body(body, self.body_capture_limit, "response").await {
            BodyCollection::Complete(body_bytes) => self.emit_captured_response(parts, body_bytes),
            BodyCollection::Exceeded { captured, .. } => {
                self.emit_captured_response(parts, captured);
            }
        }
    }

    fn finish_buffered_response(
        &mut self,
        parts: http::response::Parts,
        body_bytes: Bytes,
    ) -> Response<ProxyBody> {
        let hooked = self.apply_response_hook_to_snapshot(parts, body_bytes);
        let HookedResponse { parts, body } = hooked;
        let body_bytes = body.into_bytes();
        self.emit_response_snapshot(&parts, body_bytes.clone());

        Response::from_parts(parts, body::full(body_bytes))
    }

    fn finish_limited_response(
        &mut self,
        parts: http::response::Parts,
        captured: Bytes,
        body: ProxyBody,
    ) -> Response<ProxyBody> {
        let hooked = self.apply_response_hook_to_snapshot(parts, captured);
        if hooked.body.is_original() {
            self.stream_response(hooked.parts, body)
        } else {
            let HookedResponse { parts, body } = hooked;
            let body_bytes = body.into_bytes();
            self.emit_response_snapshot(&parts, body_bytes.clone());
            Response::from_parts(parts, body::full(body_bytes))
        }
    }

    fn emit_captured_response(&mut self, parts: http::response::Parts, body_bytes: Bytes) {
        let hooked = self.apply_response_hook_to_snapshot(parts, body_bytes);
        let HookedResponse { parts, body } = hooked;
        self.emit_response_snapshot(&parts, body.into_bytes());
    }

    fn stream_response<B>(&mut self, parts: http::response::Parts, body: B) -> Response<ProxyBody>
    where
        B: HttpBody<Data = Bytes, Error = hyper::Error> + Send + Sync + 'static,
    {
        let status = parts.status;
        let version = parts.version;
        let headers = parts.headers.clone();
        let request = self.take_captured_request_state();
        let id = self.pending_id.take().unwrap_or_else(next_id);
        let event_tx = self.event_tx_clone();
        let response_capture = BodyCapture::new(self.body_capture_limit);
        let response_capture_for_body = response_capture.clone();

        let body = body::capture(body, response_capture, move || {
            let Some(request) = request else {
                return;
            };

            let response_snapshot = response_capture_for_body.snapshot();
            log_truncated_capture("response", &response_snapshot);
            let response = ProxiedResponse::new(
                status,
                version,
                headers,
                response_snapshot.bytes,
                now_millis(),
            );

            match request {
                CapturedRequest::Buffered(request) => {
                    send_request_complete(&event_tx, id, request, response);
                }
                request => {
                    tokio::spawn(async move {
                        let request = request.into_proxied_request_after_capture().await;
                        send_request_complete(&event_tx, id, request, response);
                    });
                }
            }
        });

        Response::from_parts(parts, body)
    }

    #[cfg(feature = "scripting")]
    fn apply_response_hook_to_snapshot(
        &self,
        mut parts: http::response::Parts,
        captured_body: Bytes,
    ) -> HookedResponse {
        if let Some(ref engine) = self.script_engine {
            let (req_method, req_url) = self
                .captured_request
                .as_ref()
                .map(CapturedRequest::request_line)
                .unwrap_or_default();

            match engine.on_response(
                &req_method,
                &req_url,
                parts.status.as_u16(),
                &parts.headers,
                &captured_body,
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
                    let body = if body == captured_body {
                        HookedResponseBody::Original(captured_body)
                    } else {
                        HookedResponseBody::Replaced(body)
                    };
                    return HookedResponse { parts, body };
                }
                Ok(crate::scripting::ScriptResponseAction::PassThrough) => {}
                Err(e) => {
                    tracing::warn!("Lua on_response error (passing through): {e}");
                }
            }
        }

        HookedResponse {
            parts,
            body: HookedResponseBody::Original(captured_body),
        }
    }

    #[cfg(not(feature = "scripting"))]
    fn apply_response_hook_to_snapshot(
        &self,
        parts: http::response::Parts,
        captured_body: Bytes,
    ) -> HookedResponse {
        HookedResponse {
            parts,
            body: HookedResponseBody::Original(captured_body),
        }
    }

    pub(crate) fn emit_response_snapshot(&mut self, parts: &http::response::Parts, body: Bytes) {
        let proxied_response = ProxiedResponse::new(
            parts.status,
            parts.version,
            parts.headers.clone(),
            body,
            now_millis(),
        );

        if let Some(request) = self.take_captured_request() {
            // Use the ID assigned at the start of handle_request (intercept flow)
            // so that RequestIntercepted and RequestComplete share the same ID.
            // Fall back to next_id() for the normal (non-intercept) path.
            let id = self.pending_id.take().unwrap_or_else(next_id);
            let event = ProxyEvent::RequestComplete {
                id,
                request: Box::new(request),
                response: Box::new(proxied_response),
            };
            self.send_event(event);
        }
    }

    fn forward_request_from_body(
        &mut self,
        parts: http::request::Parts,
        request_body: RequestBody,
    ) -> Request<ProxyBody> {
        match request_body {
            RequestBody::Buffered(body_bytes) => {
                self.captured_request = Some(CapturedRequest::buffered(ProxiedRequest::new(
                    parts.method.clone(),
                    parts.uri.clone(),
                    parts.version,
                    parts.headers.clone(),
                    body_bytes.clone(),
                    now_millis(),
                )));
                Request::from_parts(parts, body::full(body_bytes))
            }
            RequestBody::Streaming { captured, body } => {
                self.captured_request = Some(CapturedRequest::buffered(ProxiedRequest::new(
                    parts.method.clone(),
                    parts.uri.clone(),
                    parts.version,
                    parts.headers.clone(),
                    captured,
                    now_millis(),
                )));
                Request::from_parts(parts, body)
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
        if !self.should_buffer_request() {
            let capture = BodyCapture::new(self.body_capture_limit);
            let done = Arc::new(Notify::new());
            self.captured_request = Some(CapturedRequest::streaming(
                &parts,
                capture.clone(),
                Arc::clone(&done),
                now_millis(),
            ));
            let req = Request::from_parts(
                parts,
                body::capture(incoming, capture, move || done.notify_one()),
            );
            return RequestOrResponse::Request(req);
        }

        let mut request_body =
            match collect_body(incoming, self.body_capture_limit, "request").await {
                BodyCollection::Complete(bytes) => RequestBody::Buffered(bytes),
                BodyCollection::Exceeded { captured, body } => {
                    RequestBody::Streaming { captured, body }
                }
            };

        // Run Lua on_request hook (if scripting is enabled and a script is loaded).
        // This runs synchronously with the complete body or the capped snapshot.
        #[cfg(feature = "scripting")]
        if let Some(ref engine) = self.script_engine {
            let hook_body = request_body.hook_bytes().clone();
            match engine.on_request(
                parts.method.as_str(),
                &parts.uri.to_string(),
                &parts.headers,
                &hook_body,
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
                    request_body.apply_modified_body(&hook_body, body);
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
                        request_body.hook_bytes().clone(),
                        now_millis(),
                    );
                    self.captured_request = Some(CapturedRequest::buffered(proxied_request));

                    let status_code = http::StatusCode::from_u16(status)
                        .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
                    return RequestOrResponse::Response(self.synthetic_response(
                        status_code,
                        headers,
                        body,
                    ));
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
                    request_body.hook_bytes().clone(),
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
                    self.captured_request = Some(CapturedRequest::buffered(snapshot));

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
                            let hook_body = request_body.hook_bytes().clone();
                            request_body.apply_modified_body(&hook_body, body);
                        }
                        Ok(Ok(InterceptDecision::Block { status, body })) => {
                            // Short-circuit: captured_request is already set above.
                            let status_code = http::StatusCode::from_u16(status)
                                .unwrap_or(http::StatusCode::BAD_GATEWAY);
                            return RequestOrResponse::Response(self.synthetic_response(
                                status_code,
                                http::HeaderMap::new(),
                                body,
                            ));
                        }
                        _ => {
                            // Timeout or sender dropped (intercept turned off):
                            // return 504 so the client gets a clear error.
                            tracing::warn!("Intercept timed out for id={id}, returning 504");
                            return RequestOrResponse::Response(self.synthetic_response(
                                http::StatusCode::GATEWAY_TIMEOUT,
                                http::HeaderMap::new(),
                                Bytes::new(),
                            ));
                        }
                    }

                    let req = self.forward_request_from_body(parts, request_body);
                    return RequestOrResponse::Request(req);
                }
            }
        }

        let req = self.forward_request_from_body(parts, request_body);
        RequestOrResponse::Request(req)
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        res: Response<hyper::body::Incoming>,
    ) -> Response<ProxyBody> {
        self.handle_upstream_response(res).await
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
        handler.captured_request = Some(CapturedRequest::buffered(proxied_request()));

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
    async fn finish_buffered_response_uses_pending_id_and_rebuilds_response_body() {
        let (event_tx, mut event_rx) = mpsc::channel(1);
        let mut handler = CapturingHandler::new(event_tx);
        handler.pending_id = Some(77);
        handler.captured_request = Some(CapturedRequest::buffered(proxied_request()));

        let (mut parts, _) = Response::builder()
            .status(StatusCode::ACCEPTED)
            .header("x-response", "ok")
            .body(())
            .unwrap()
            .into_parts();
        parts.version = Version::HTTP_11;

        let response = handler.finish_buffered_response(parts, Bytes::from_static(b"accepted"));

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
    async fn finish_buffered_response_without_captured_request_sends_no_event() {
        let (event_tx, mut event_rx) = mpsc::channel(1);
        let mut handler = CapturingHandler::new(event_tx);
        let (parts, _) = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(())
            .unwrap()
            .into_parts();

        let response = handler.finish_buffered_response(parts, Bytes::new());

        assert!(body_bytes(response).await.is_empty());
        assert!(event_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn synthetic_response_returns_body_and_emits_completion() {
        let (event_tx, mut event_rx) = mpsc::channel(1);
        let mut handler = CapturingHandler::new(event_tx);
        handler.pending_id = Some(78);
        handler.captured_request = Some(CapturedRequest::buffered(proxied_request()));

        let mut headers = HeaderMap::new();
        headers.insert("x-synthetic", "yes".parse().unwrap());
        let response = handler.synthetic_response(
            StatusCode::BAD_GATEWAY,
            headers,
            Bytes::from_static(b"synthetic body"),
        );

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(response.headers()["x-synthetic"], "yes");
        assert_eq!(body_bytes(response).await.as_ref(), b"synthetic body");
        match event_rx.recv().await.unwrap() {
            ProxyEvent::RequestComplete {
                id,
                request,
                response,
            } => {
                assert_eq!(id, 78);
                assert_eq!(request.uri().path(), "/path");
                assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
                assert_eq!(response.headers()["x-synthetic"], "yes");
                assert_eq!(response.body().as_ref(), b"synthetic body");
            }
            other => panic!("expected RequestComplete, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stream_response_forwards_full_body_and_emits_capped_snapshots() {
        let (event_tx, mut event_rx) = mpsc::channel(1);
        let mut handler = CapturingHandler::new(event_tx);
        handler.body_capture_limit = Some(4);
        handler.pending_id = Some(88);

        let (req_parts, _) = Request::builder()
            .method(Method::POST)
            .uri("http://example.test/upload")
            .body(())
            .unwrap()
            .into_parts();
        let request_capture = BodyCapture::new(Some(4));
        request_capture.append(&Bytes::from_static(b"abcdef"));
        let request_done = Arc::new(Notify::new());
        request_done.notify_one();
        handler.captured_request = Some(CapturedRequest::streaming(
            &req_parts,
            request_capture,
            request_done,
            10,
        ));

        let (parts, _) = Response::builder()
            .status(StatusCode::OK)
            .body(())
            .unwrap()
            .into_parts();
        let response = handler.stream_response(parts, body::full(Bytes::from_static(b"uvwxyz")));

        assert_eq!(body_bytes(response).await.as_ref(), b"uvwxyz");
        match event_rx.recv().await.unwrap() {
            ProxyEvent::RequestComplete {
                id,
                request,
                response,
            } => {
                assert_eq!(id, 88);
                assert_eq!(request.body().as_ref(), b"abcd");
                assert_eq!(response.body().as_ref(), b"uvwx");
            }
            other => panic!("expected RequestComplete, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stream_response_emits_partial_capture_when_body_is_dropped() {
        let (event_tx, mut event_rx) = mpsc::channel(1);
        let mut handler = CapturingHandler::new(event_tx);
        handler.pending_id = Some(90);
        handler.captured_request = Some(CapturedRequest::buffered(proxied_request()));

        let (parts, _) = Response::builder()
            .status(StatusCode::OK)
            .body(())
            .unwrap()
            .into_parts();
        let response =
            handler.stream_response(parts, body::full(Bytes::from_static(b"not consumed")));

        drop(response);

        match event_rx.try_recv().unwrap() {
            ProxyEvent::RequestComplete {
                id,
                request,
                response,
            } => {
                assert_eq!(id, 90);
                assert_eq!(request.uri().path(), "/path");
                assert_eq!(response.status(), StatusCode::OK);
                assert!(response.body().is_empty());
            }
            other => panic!("expected RequestComplete, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stream_response_emits_for_already_empty_body() {
        let (event_tx, mut event_rx) = mpsc::channel(1);
        let mut handler = CapturingHandler::new(event_tx);
        handler.pending_id = Some(89);
        handler.captured_request = Some(CapturedRequest::buffered(proxied_request()));

        let (parts, _) = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(())
            .unwrap()
            .into_parts();

        let response = handler.stream_response(parts, body::empty());

        assert!(body_bytes(response).await.is_empty());
        match event_rx.recv().await.unwrap() {
            ProxyEvent::RequestComplete {
                id,
                request,
                response,
            } => {
                assert_eq!(id, 89);
                assert_eq!(request.uri().path(), "/path");
                assert_eq!(response.status(), StatusCode::NO_CONTENT);
                assert!(response.body().is_empty());
            }
            other => panic!("expected RequestComplete, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stream_response_waits_for_streaming_request_capture_before_empty_response_event() {
        let (event_tx, mut event_rx) = mpsc::channel(1);
        let mut handler = CapturingHandler::new(event_tx);
        handler.pending_id = Some(91);

        let (req_parts, _) = Request::builder()
            .method(Method::POST)
            .uri("http://example.test/upload")
            .body(())
            .unwrap()
            .into_parts();
        let request_capture = BodyCapture::new(Some(10));
        request_capture.append(&Bytes::from_static(b"abc"));
        let request_done = Arc::new(Notify::new());
        handler.captured_request = Some(CapturedRequest::streaming(
            &req_parts,
            request_capture.clone(),
            Arc::clone(&request_done),
            10,
        ));

        let (parts, _) = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(())
            .unwrap()
            .into_parts();
        let response = handler.stream_response(parts, body::empty());

        assert!(body_bytes(response).await.is_empty());
        tokio::task::yield_now().await;
        assert!(event_rx.try_recv().is_err());

        request_capture.append(&Bytes::from_static(b"def"));
        request_done.notify_one();

        match event_rx.recv().await.unwrap() {
            ProxyEvent::RequestComplete {
                id,
                request,
                response,
            } => {
                assert_eq!(id, 91);
                assert_eq!(request.body().as_ref(), b"abcdef");
                assert_eq!(response.status(), StatusCode::NO_CONTENT);
            }
            other => panic!("expected RequestComplete, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn collect_body_returns_streaming_body_when_limit_is_exceeded() {
        match collect_body(
            body::full(Bytes::from_static(b"abcdef")),
            Some(4),
            "response",
        )
        .await
        {
            BodyCollection::Complete(_) => panic!("expected limit fallback"),
            BodyCollection::Exceeded { captured, body } => {
                assert_eq!(captured.as_ref(), b"abcd");
                assert_eq!(body.collect().await.unwrap().to_bytes().as_ref(), b"abcdef");
            }
        }
    }

    #[tokio::test]
    async fn collect_body_buffers_full_body_when_unlimited() {
        match collect_body(body::full(Bytes::from_static(b"abcdef")), None, "response").await {
            BodyCollection::Complete(body) => assert_eq!(body.as_ref(), b"abcdef"),
            BodyCollection::Exceeded { .. } => panic!("expected complete body"),
        }
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
        assert_eq!(
            handler.take_captured_request().unwrap().uri().path(),
            "/path"
        );
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
    async fn finish_buffered_response_runs_script_response_hook() {
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
        handler.captured_request = Some(CapturedRequest::buffered(proxied_request()));

        let (parts, _) = Response::builder()
            .status(StatusCode::OK)
            .body(())
            .unwrap()
            .into_parts();

        let response = handler.finish_buffered_response(parts, Bytes::from_static(b"original"));

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
    async fn finish_buffered_response_passes_through_on_script_response_error() {
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

        let response = handler.finish_buffered_response(parts, Bytes::from_static(b"original"));

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_bytes(response).await.as_ref(), b"original");
    }

    #[cfg(feature = "scripting")]
    #[tokio::test]
    async fn finish_buffered_response_passes_through_when_script_returns_nil_response() {
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
        handler.captured_request = Some(CapturedRequest::buffered(proxied_request()));

        let (parts, _) = Response::builder()
            .status(StatusCode::OK)
            .header("x-original-response", "yes")
            .body(())
            .unwrap()
            .into_parts();

        let response = handler.finish_buffered_response(parts, Bytes::from_static(b"original"));

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
