use proxyapi::{FlowFilter, InterceptConfig, InterceptDecision, ProxyEvent, SessionRecorder};
use proxyapi_models::{CapturedFlow, ProxiedRequest, TrafficSession};
use rama::bytes::Bytes;
use rama::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, COOKIE, HOST, ORIGIN, SET_COOKIE,
};
use rama::http::layer::error_handling::ErrorHandlerLayer;
use rama::http::server::HttpServer;
use rama::http::service::web::extract::{Json, Path, Query, State};
use rama::http::service::web::response::{Html, IntoResponse};
use rama::http::service::web::Router;
use rama::http::ws::handshake::server::{ServerWebSocket, WebSocketAcceptor};
use rama::http::ws::Message;
use rama::http::{HeaderMap, Request, Response, StatusCode};
use rama::net::uri::Uri;
use rama::rt::Executor;
use rama::service::service_fn;
use rama::tcp::server::TcpListener;
use rama::telemetry::tracing;
use rama::{Layer, Service};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio_util::sync::CancellationToken;

use crate::wireguard_setup::WireGuardSetup;

const INDEX_HTML: &str = include_str!("assets/index.html");
const STYLE_CSS: &str = include_str!("assets/style.css");
const APP_JS: &str = include_str!("assets/app.js");
const BROWSER_COOKIE: &str = "proxelar_session";

struct WebState {
    broadcast_tx: broadcast::Sender<String>,
    api_token: String,
    browser_token: String,
    intercept: Arc<InterceptConfig>,
    replay_tx: mpsc::Sender<ProxiedRequest>,
    recorder: Arc<RwLock<SessionRecorder>>,
    wireguard_setup: Option<Arc<WireGuardSetup>>,
}

fn generate_token() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A message sent from the browser to the proxy.
#[derive(Deserialize)]
#[serde(tag = "type")]
enum ClientMessage {
    /// Enable or disable intercept mode.
    SetIntercept { enabled: bool },
    /// Drop a pending request (returns 504 to the client).
    Drop { id: u64 },
    /// Forward a pending request (with any edits the user made).
    Modified {
        id: u64,
        method: String,
        uri: String,
        headers: ClientHeaders,
        body: ClientBody,
    },
    /// Replay a previously captured request.
    Replay {
        method: String,
        uri: String,
        headers: ClientHeaders,
        body: ClientBody,
    },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ClientBody {
    Text(String),
    Bytes { bytes: Vec<u8> },
    Structured { format: String, text: String },
}

impl Default for ClientBody {
    fn default() -> Self {
        Self::Text(String::new())
    }
}

impl ClientBody {
    fn try_into_bytes(self) -> Result<Bytes, String> {
        match self {
            Self::Text(body) => Ok(Bytes::from(body)),
            Self::Bytes { bytes } => Ok(Bytes::from(bytes)),
            Self::Structured { format, text } => {
                proxyapi::content::encode_edit(&format, &text).map_err(|error| error.to_string())
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ClientHeaders {
    Map(HashMap<String, HeaderValues>),
    List(Vec<ClientHeader>),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum HeaderValues {
    One(ClientHeaderValue),
    Many(Vec<ClientHeaderValue>),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ClientHeaderValue {
    Text(String),
    Bytes(Vec<u8>),
}

#[derive(Deserialize)]
struct ClientHeader {
    name: String,
    value: ClientHeaderValue,
}

impl ClientHeaderValue {
    fn try_into_header_value(self) -> Result<rama::http::HeaderValue, String> {
        match self {
            Self::Text(value) => rama::http::HeaderValue::from_str(&value),
            Self::Bytes(value) => rama::http::HeaderValue::from_bytes(&value),
        }
        .map_err(|error| format!("invalid header value: {error}"))
    }
}

impl ClientHeaders {
    fn try_into_header_map(self) -> Result<HeaderMap, String> {
        let values: Vec<(String, ClientHeaderValue)> = match self {
            Self::Map(headers) => headers
                .into_iter()
                .flat_map(|(name, values)| match values {
                    HeaderValues::One(value) => vec![(name, value)],
                    HeaderValues::Many(values) => values
                        .into_iter()
                        .map(|value| (name.clone(), value))
                        .collect(),
                })
                .collect(),
            Self::List(headers) => headers
                .into_iter()
                .map(|header| (header.name, header.value))
                .collect(),
        };
        let mut headers = HeaderMap::new();
        for (name, value) in values {
            let name = rama::http::header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|error| format!("invalid header name: {error}"))?;
            let value = value.try_into_header_value()?;
            headers.append(name, value);
        }
        Ok(headers)
    }
}

/// Status broadcast to all connected browser clients when intercept state changes.
#[derive(Serialize)]
struct InterceptStatus {
    enabled: bool,
    pending_count: usize,
}

pub(crate) struct ServerConfig {
    pub(crate) addr: std::net::IpAddr,
    pub(crate) port: u16,
    pub(crate) token: Option<String>,
    pub(crate) open_browser: bool,
    pub(crate) wireguard_setup: Option<Arc<WireGuardSetup>>,
    pub(crate) browser_proxy: Option<(std::net::SocketAddr, std::path::PathBuf)>,
}

pub async fn run(
    mut event_rx: mpsc::Receiver<ProxyEvent>,
    intercept: Arc<InterceptConfig>,
    replay_tx: mpsc::Sender<ProxiedRequest>,
    recorder: Arc<RwLock<SessionRecorder>>,
    config: ServerConfig,
    cancel: CancellationToken,
) {
    let api_token = config
        .token
        .filter(|token| !token.is_empty())
        .unwrap_or_else(generate_token);
    let browser_token = generate_token();
    let (broadcast_tx, _) = broadcast::channel::<String>(256);
    let state = Arc::new(WebState {
        broadcast_tx: broadcast_tx.clone(),
        api_token: api_token.clone(),
        browser_token: browser_token.clone(),
        intercept,
        replay_tx,
        recorder,
        wireguard_setup: config.wireguard_setup,
    });

    // Background task: forward proxy events to broadcast channel
    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            match serialize_browser_event(&event) {
                Ok(json) => {
                    if let Err(e) = broadcast_tx.send(json) {
                        tracing::debug!("No active WebSocket subscribers: {e}");
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to serialize proxy event: {e}");
                }
            }
        }
    });

    // GET /ws — gated on same-origin + browser cookie, then handed to the
    // WebSocket acceptor. Auth must run before the acceptor consumes the request.
    let ws_route = {
        let socket_state = Arc::clone(&state);
        let acceptor =
            WebSocketAcceptor::new().into_service(service_fn(move |ws: ServerWebSocket| {
                let state = Arc::clone(&socket_state);
                async move {
                    handle_socket(ws, state).await;
                    Ok::<(), std::convert::Infallible>(())
                }
            }));
        let auth_state = Arc::clone(&state);
        service_fn(move |req: Request| {
            let state = Arc::clone(&auth_state);
            let acceptor = acceptor.clone();
            async move {
                // Same-origin (compared against Host) plus browser cookie: allows
                // LAN addresses/hostnames without permitting cross-site WebSocket use.
                if !origin_matches_host(req.headers())
                    || !browser_cookie_matches(req.headers(), &state.browser_token)
                {
                    return Ok::<Response, std::convert::Infallible>(
                        (StatusCode::FORBIDDEN, "Forbidden").into_response(),
                    );
                }
                acceptor.serve(req).await
            }
        })
    };

    let router = Router::new_with_state(Arc::clone(&state))
        .with_get("/", index_handler)
        .with_get("/style.css", css_handler)
        .with_get("/app.js", js_handler)
        .with_post("/api/v1/auth", api_authenticate_browser)
        .with_get("/api/v1/wireguard.svg", api_wireguard_svg)
        .with_get("/ws", ws_route)
        .with_get("/api/v1/status", api_status)
        .with_get("/api/v1/session", api_session)
        .with_get("/api/v1/flows", api_flows)
        .with_delete("/api/v1/flows", api_clear_flows)
        .with_get("/api/v1/filter", api_filter_matches)
        .with_get("/api/v1/flows/{id}", api_flow)
        .with_get("/api/v1/flows/{id}/content/{side}", api_content)
        .with_post("/api/v1/flows/{id}/replay", api_replay)
        .with_put("/api/v1/intercept", api_set_intercept)
        .with_post("/api/v1/intercept/{id}", api_resolve_intercept);

    let bind_addr = SocketAddr::new(config.addr, config.port);
    let exec = Executor::default();
    let listener = match TcpListener::bind_address(bind_addr, exec.clone()).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind web GUI on {bind_addr}: {e}");
            return;
        }
    };

    // Open browser *after* successful bind
    let url = format!("http://{bind_addr}");
    let browser_url = format!("{url}/#token={browser_token}");
    tracing::info!("Web/API server available at {url}");
    tracing::info!("Browser GUI login URL: {browser_url}");
    tracing::info!("REST API bearer token: {api_token}");
    if let Some((proxy, profile)) = config.browser_proxy {
        if let Err(error) = crate::browser::launch(&browser_url, proxy, &profile) {
            tracing::warn!("Failed to launch proxy-configured browser: {error}");
        }
    } else if config.open_browser {
        if let Err(e) = open::that(&browser_url) {
            tracing::warn!("Failed to open browser: {e}");
        }
    }

    // `Arc<S>` is always `Clone`, which the per-connection serve loop requires.
    let app = Arc::new(ErrorHandlerLayer::new().into_layer(router));
    let server = HttpServer::auto(exec).service(app);
    tokio::select! {
        () = listener.serve(server) => {}
        () = cancel.cancelled() => {
            tracing::info!("Web GUI shutting down");
        }
    }
}

async fn api_wireguard_svg(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> rama::http::Response {
    if !api_authorized(&headers, &state) {
        return forbidden();
    }
    let Some(setup) = &state.wireguard_setup else {
        return rama::http::StatusCode::NOT_FOUND.into_response();
    };
    let mut response = setup.svg().to_owned().into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        "image/svg+xml; charset=utf-8"
            .parse()
            .expect("static content type is valid"),
    );
    response.headers_mut().insert(
        CACHE_CONTROL,
        "no-store".parse().expect("static cache control is valid"),
    );
    response
}

fn serialize_browser_event(event: &ProxyEvent) -> Result<String, serde_json::Error> {
    let mut value = serde_json::to_value(event)?;
    if let ProxyEvent::RequestIntercepted { request, .. } = event {
        let editor = proxyapi::content::editable_content(request.headers(), request.body())
            .ok()
            .flatten();
        let intercepted = value
            .get_mut("RequestIntercepted")
            .and_then(serde_json::Value::as_object_mut);
        if let (Some(editor), Some(intercepted)) = (editor, intercepted) {
            intercepted.insert(
                "editor".to_owned(),
                serde_json::json!({
                    "format": editor.format.as_str(),
                    "text": editor.text,
                }),
            );
        }
    }
    serde_json::to_string(&value)
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, token)| scheme.eq_ignore_ascii_case("bearer") && !token.is_empty())
        .map(|(_, token)| token)
}

fn browser_cookie_matches(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|cookie| cookie.trim().split_once('='))
        .any(|(name, value)| name == BROWSER_COOKIE && value == expected)
}

fn api_authorized(headers: &HeaderMap, state: &WebState) -> bool {
    bearer_token(headers).is_some_and(|token| token == state.api_token)
        || browser_cookie_matches(headers, &state.browser_token)
}

fn forbidden() -> rama::http::Response {
    (rama::http::StatusCode::FORBIDDEN, "Forbidden").into_response()
}

async fn api_authenticate_browser(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> rama::http::Response {
    if !bearer_token(&headers).is_some_and(|token| token == state.browser_token) {
        return forbidden();
    }

    let cookie = format!(
        "{BROWSER_COOKIE}={}; HttpOnly; SameSite=Strict; Path=/",
        state.browser_token
    );
    let mut response = rama::http::StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        SET_COOKIE,
        cookie
            .parse()
            .expect("generated browser tokens are valid cookie values"),
    );
    response
}

#[derive(Serialize)]
struct ApiStatus {
    version: &'static str,
    intercept_enabled: bool,
    pending_count: usize,
    flow_count: usize,
    websocket_count: usize,
    tcp_stream_count: usize,
    dns_exchange_count: usize,
    udp_exchange_count: usize,
}

async fn api_status(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> rama::http::Response {
    if !api_authorized(&headers, &state) {
        return forbidden();
    }
    let session = state.recorder.read().await;
    Json(ApiStatus {
        version: env!("CARGO_PKG_VERSION"),
        intercept_enabled: state.intercept.is_enabled(),
        pending_count: state.intercept.pending_count(),
        flow_count: session.session().flows.len(),
        websocket_count: session.session().websockets.len(),
        tcp_stream_count: session.session().tcp_streams.len(),
        dns_exchange_count: session.session().dns_exchanges.len(),
        udp_exchange_count: session.session().udp_exchanges.len(),
    })
    .into_response()
}

async fn api_session(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> rama::http::Response {
    if !api_authorized(&headers, &state) {
        return forbidden();
    }
    Json::<TrafficSession>(state.recorder.read().await.snapshot()).into_response()
}

async fn api_flows(
    Query(params): Query<HashMap<String, String>>,
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> rama::http::Response {
    if !api_authorized(&headers, &state) {
        return forbidden();
    }
    let filter = match params.get("filter") {
        Some(expression) => match FlowFilter::parse(expression) {
            Ok(filter) => Some(filter),
            Err(error) => {
                return (rama::http::StatusCode::BAD_REQUEST, error.to_string()).into_response()
            }
        },
        None => None,
    };
    let flows = state
        .recorder
        .read()
        .await
        .session()
        .flows
        .iter()
        .filter(|flow| {
            filter
                .as_ref()
                .is_none_or(|filter| filter.matches(&flow.request, Some(&flow.response), false))
        })
        .cloned()
        .collect::<Vec<_>>();
    Json::<Vec<CapturedFlow>>(flows).into_response()
}

#[derive(Serialize)]
struct ApiFilterMatches {
    flow_ids: Vec<u64>,
    websocket_ids: Vec<u64>,
    tcp_stream_ids: Vec<u64>,
    dns_exchange_ids: Vec<u64>,
    udp_exchange_ids: Vec<u64>,
}

async fn api_filter_matches(
    Query(params): Query<HashMap<String, String>>,
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> rama::http::Response {
    if !api_authorized(&headers, &state) {
        return forbidden();
    }
    let expression = params.get("filter").map_or("", String::as_str);
    let filter = match FlowFilter::parse(expression) {
        Ok(filter) => filter,
        Err(error) => {
            return (rama::http::StatusCode::BAD_REQUEST, error.to_string()).into_response()
        }
    };
    let recorder = state.recorder.read().await;
    let session = recorder.session();
    Json(ApiFilterMatches {
        flow_ids: session
            .flows
            .iter()
            .filter(|flow| filter.matches(&flow.request, Some(&flow.response), false))
            .map(|flow| flow.id)
            .collect(),
        websocket_ids: session
            .websockets
            .iter()
            .filter(|flow| {
                filter.matches_websocket(&flow.request, &flow.response, &flow.frames, flow.closed)
            })
            .map(|flow| flow.id)
            .collect(),
        tcp_stream_ids: session
            .tcp_streams
            .iter()
            .filter(|stream| filter.matches_tcp(stream))
            .map(|stream| stream.id)
            .collect(),
        dns_exchange_ids: session
            .dns_exchanges
            .iter()
            .filter(|exchange| filter.matches_dns(exchange))
            .map(|exchange| exchange.id)
            .collect(),
        udp_exchange_ids: session
            .udp_exchanges
            .iter()
            .filter(|exchange| filter.matches_udp(exchange))
            .map(|exchange| exchange.id)
            .collect(),
    })
    .into_response()
}

async fn api_flow(
    Path(id): Path<u64>,
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> rama::http::Response {
    if !api_authorized(&headers, &state) {
        return forbidden();
    }
    let session = state.recorder.read().await;
    match session.session().flows.iter().find(|flow| flow.id == id) {
        Some(flow) => Json(flow.clone()).into_response(),
        None => (rama::http::StatusCode::NOT_FOUND, "Flow not found").into_response(),
    }
}

#[derive(Serialize)]
struct ApiContentView {
    kind: &'static str,
    text: String,
    decoded_len: usize,
    content_encoding: Option<String>,
    image_media_type: Option<String>,
    image_base64: Option<String>,
    truncated: bool,
    total_seen: usize,
}

async fn api_content(
    Path((id, side)): Path<(u64, String)>,
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> rama::http::Response {
    if !api_authorized(&headers, &state) {
        return forbidden();
    }
    let session = state.recorder.read().await;
    let Some(flow) = session.session().flows.iter().find(|flow| flow.id == id) else {
        return (rama::http::StatusCode::NOT_FOUND, "Flow not found").into_response();
    };
    let (headers, body, metadata) = match side.as_str() {
        "request" => (
            flow.request.headers(),
            flow.request.body(),
            flow.request.body_metadata(),
        ),
        "response" => (
            flow.response.headers(),
            flow.response.body(),
            flow.response.body_metadata(),
        ),
        _ => {
            return (
                rama::http::StatusCode::BAD_REQUEST,
                "side must be request or response",
            )
                .into_response()
        }
    };
    match proxyapi::content::content_view(headers, body) {
        Ok(view) => {
            let image_media_type = view
                .inline_image
                .as_ref()
                .map(|image| image.media_type.clone());
            let image_base64 = view.inline_image.map(|image| image.base64);
            Json(ApiContentView {
                kind: view.kind.label(),
                text: view.text,
                decoded_len: view.decoded_len,
                content_encoding: view.content_encoding,
                image_media_type,
                image_base64,
                truncated: metadata.truncated,
                total_seen: metadata.total_seen,
            })
            .into_response()
        }
        Err(error) => (
            rama::http::StatusCode::UNPROCESSABLE_ENTITY,
            error.to_string(),
        )
            .into_response(),
    }
}

async fn api_clear_flows(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> rama::http::Response {
    if !api_authorized(&headers, &state) {
        return forbidden();
    }
    state.recorder.write().await.clear();
    rama::http::StatusCode::NO_CONTENT.into_response()
}

async fn api_replay(
    Path(id): Path<u64>,
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> rama::http::Response {
    if !api_authorized(&headers, &state) {
        return forbidden();
    }
    let request = state
        .recorder
        .read()
        .await
        .session()
        .flows
        .iter()
        .find(|flow| flow.id == id)
        .map(|flow| flow.request.clone());
    let Some(request) = request else {
        return (rama::http::StatusCode::NOT_FOUND, "Flow not found").into_response();
    };
    match state.replay_tx.try_send(request) {
        Ok(()) => rama::http::StatusCode::ACCEPTED.into_response(),
        Err(_) => (
            rama::http::StatusCode::SERVICE_UNAVAILABLE,
            "Replay queue full",
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct SetInterceptBody {
    enabled: bool,
}

async fn api_set_intercept(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Json(body): Json<SetInterceptBody>,
) -> rama::http::Response {
    if !api_authorized(&headers, &state) {
        return forbidden();
    }
    state.intercept.set_enabled(body.enabled);
    rama::http::StatusCode::NO_CONTENT.into_response()
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum ApiInterceptDecision {
    Forward,
    Drop {
        #[serde(default = "default_drop_status")]
        status: u16,
        #[serde(default)]
        body: String,
    },
    Modify {
        method: String,
        uri: String,
        headers: ClientHeaders,
        #[serde(default)]
        body: ClientBody,
    },
}

const fn default_drop_status() -> u16 {
    504
}

async fn api_resolve_intercept(
    Path(id): Path<u64>,
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Json(body): Json<ApiInterceptDecision>,
) -> rama::http::Response {
    if !api_authorized(&headers, &state) {
        return forbidden();
    }
    let decision = match body {
        ApiInterceptDecision::Forward => InterceptDecision::Forward,
        ApiInterceptDecision::Drop { status, body } => {
            if rama::http::StatusCode::from_u16(status).is_err() {
                return (
                    rama::http::StatusCode::UNPROCESSABLE_ENTITY,
                    "Invalid HTTP status",
                )
                    .into_response();
            }
            InterceptDecision::Block {
                status,
                body: Bytes::from(body),
            }
        }
        ApiInterceptDecision::Modify {
            method,
            uri,
            headers,
            body,
        } => {
            if method.parse::<rama::http::Method>().is_err() || uri.parse::<Uri>().is_err() {
                return (
                    rama::http::StatusCode::UNPROCESSABLE_ENTITY,
                    "Invalid method or URI",
                )
                    .into_response();
            }
            let Ok(headers) = headers.try_into_header_map() else {
                return (
                    rama::http::StatusCode::UNPROCESSABLE_ENTITY,
                    "Invalid headers",
                )
                    .into_response();
            };
            let body = match body.try_into_bytes() {
                Ok(body) => body,
                Err(error) => {
                    return (rama::http::StatusCode::UNPROCESSABLE_ENTITY, error).into_response()
                }
            };
            InterceptDecision::Modified {
                method,
                uri,
                headers,
                body,
            }
        }
    };
    if state.intercept.resolve(id, decision) {
        rama::http::StatusCode::NO_CONTENT.into_response()
    } else {
        (rama::http::StatusCode::NOT_FOUND, "Pending flow not found").into_response()
    }
}

async fn index_handler() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn css_handler() -> impl IntoResponse {
    ([(rama::http::header::CONTENT_TYPE, "text/css")], STYLE_CSS)
}

async fn js_handler() -> impl IntoResponse {
    (
        [(rama::http::header::CONTENT_TYPE, "application/javascript")],
        APP_JS,
    )
}

fn origin_matches_host(headers: &HeaderMap) -> bool {
    let Some(host) = headers.get(HOST).and_then(|value| value.to_str().ok()) else {
        return false;
    };
    let Some(origin) = headers.get(ORIGIN).and_then(|value| value.to_str().ok()) else {
        return false;
    };
    let Ok(origin) = origin.parse::<Uri>() else {
        return false;
    };

    origin.scheme_str() == Some("http")
        && origin
            .authority()
            .is_some_and(|authority| authority.to_string().eq_ignore_ascii_case(host))
        && origin.path_or_root().as_ref() == "/"
        && origin.query().is_none()
}

async fn handle_socket(mut ws: ServerWebSocket, state: Arc<WebState>) {
    let mut rx = state.broadcast_tx.subscribe();

    loop {
        tokio::select! {
            // Proxy events → browser
            result = rx.recv() => {
                match result {
                    Ok(msg) => {
                        if ws.send_message(Message::text(msg)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("WebSocket broadcast lagged by {n} messages");
                    }
                }
            }
            // Browser → proxy commands
            result = ws.recv_message() => {
                match result {
                    Ok(Message::Text(text)) => {
                        handle_client_message(text.as_str(), &state).await;
                    }
                    // A receive error signals a closed/reset connection in rama-ws.
                    Ok(Message::Close(_)) | Err(_) => break,
                    _ => {} // Ping/Pong/Binary ignored
                }
            }
        }
    }
}

async fn handle_client_message(text: &str, state: &WebState) {
    let msg: ClientMessage = match serde_json::from_str(text) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("Invalid client message: {e}");
            return;
        }
    };

    match msg {
        ClientMessage::SetIntercept { enabled } => {
            state.intercept.set_enabled(enabled);
            // Broadcast updated intercept status to all connected clients
            let status = InterceptStatus {
                enabled,
                pending_count: state.intercept.pending_count(),
            };
            if let Ok(json) = serde_json::to_string(&serde_json::json!({"InterceptStatus": status}))
            {
                let _ = state.broadcast_tx.send(json);
            }
        }
        ClientMessage::Drop { id } => {
            state.intercept.resolve(
                id,
                InterceptDecision::Block {
                    status: 504,
                    body: Bytes::from_static(b"Blocked by Proxelar intercept"),
                },
            );
        }
        ClientMessage::Modified {
            id,
            method,
            uri,
            headers,
            body,
        } => {
            let Ok(method) = method.parse::<rama::http::Method>() else {
                tracing::warn!("Invalid method in browser intercept edit");
                return;
            };
            let Ok(uri) = uri.parse::<Uri>() else {
                tracing::warn!("Invalid URI in browser intercept edit");
                return;
            };
            let Ok(header_map) = headers.try_into_header_map() else {
                tracing::warn!("Invalid header in browser intercept edit");
                return;
            };
            let body = match body.try_into_bytes() {
                Ok(body) => body,
                Err(error) => {
                    let message = serde_json::json!({
                        "EditorError": { "id": id, "message": error }
                    });
                    if let Ok(message) = serde_json::to_string(&message) {
                        let _ = state.broadcast_tx.send(message);
                    }
                    return;
                }
            };
            state.intercept.resolve(
                id,
                InterceptDecision::Modified {
                    method: method.to_string(),
                    uri: uri.to_string(),
                    headers: header_map,
                    body,
                },
            );
        }
        ClientMessage::Replay {
            method,
            uri,
            headers,
            body,
        } => {
            let Ok(header_map) = headers.try_into_header_map() else {
                tracing::warn!("Invalid header in browser replay");
                return;
            };
            let Ok(method) = method.parse() else {
                tracing::warn!("Invalid method in browser replay");
                return;
            };
            let Ok(uri) = uri.parse() else {
                tracing::warn!("Invalid URI in browser replay");
                return;
            };
            let now = chrono::Local::now().timestamp_millis();
            let Ok(body) = body.try_into_bytes() else {
                tracing::warn!("Invalid structured body in browser replay");
                return;
            };
            let req = ProxiedRequest::new(
                method,
                uri,
                rama::http::Version::HTTP_11,
                header_map,
                body,
                now,
            );
            if state.replay_tx.try_send(req).is_err() {
                tracing::warn!("Replay channel full");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxyapi_models::{ProxiedResponse, WsDirection, WsFrame, WsOpcode};
    use rama::http::body::util::BodyExt as _;
    use rama::http::service::web::response::IntoResponse;
    use rama::http::{HeaderValue, Method, Version};

    fn test_state() -> (
        WebState,
        broadcast::Receiver<String>,
        mpsc::Receiver<ProxiedRequest>,
    ) {
        let (broadcast_tx, broadcast_rx) = broadcast::channel(16);
        let (replay_tx, replay_rx) = mpsc::channel(4);
        (
            WebState {
                broadcast_tx,
                api_token: "api-token".to_owned(),
                browser_token: "browser-token".to_owned(),
                intercept: InterceptConfig::new(),
                replay_tx,
                recorder: Arc::new(RwLock::new(SessionRecorder::default())),
                wireguard_setup: None,
            },
            broadcast_rx,
            replay_rx,
        )
    }

    async fn response_text(response: rama::http::Response) -> String {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn websocket_headers(host: Option<&str>, origin: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(host) = host {
            headers.insert(HOST, HeaderValue::from_str(host).unwrap());
        }
        if let Some(origin) = origin {
            headers.insert(ORIGIN, HeaderValue::from_str(origin).unwrap());
        }
        headers
    }

    #[test]
    fn generate_token_returns_64_hex_chars() {
        let token = generate_token();

        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn static_asset_handlers_return_expected_content() {
        let index = index_handler().await.into_response();
        assert_eq!(index.status(), rama::http::StatusCode::OK);
        assert!(response_text(index).await.contains("<html"));

        let css = css_handler().await.into_response();
        assert_eq!(css.headers()[rama::http::header::CONTENT_TYPE], "text/css");
        assert!(response_text(css).await.contains(":root"));

        let js = js_handler().await.into_response();
        assert_eq!(
            js.headers()[rama::http::header::CONTENT_TYPE],
            "application/javascript"
        );
        let js_text = response_text(js).await;
        assert!(!js_text.contains("api-token"));
        assert!(!js_text.contains("browser-token"));
    }

    #[test]
    fn websocket_origin_accepts_matching_local_and_lan_hosts() {
        for (host, origin) in [
            ("127.0.0.1:8081", "http://127.0.0.1:8081"),
            ("localhost:8081", "http://localhost:8081"),
            ("192.168.1.20:8081", "http://192.168.1.20:8081"),
            ("PROXELAR.local:8081", "http://proxelar.local:8081"),
            ("[::1]:8081", "http://[::1]:8081"),
        ] {
            let headers = websocket_headers(Some(host), Some(origin));

            assert!(origin_matches_host(&headers));
        }
    }

    #[test]
    fn websocket_origin_rejects_missing_malformed_and_cross_site_values() {
        for (host, origin) in [
            (None, Some("http://192.168.1.20:8081")),
            (Some("192.168.1.20:8081"), None),
            (Some("192.168.1.20:8081"), Some("null")),
            (Some("192.168.1.20:8081"), Some("not-an-origin")),
            (Some("192.168.1.20:8081"), Some("https://192.168.1.20:8081")),
            (
                Some("192.168.1.20:8081"),
                Some("http://192.168.1.20:8081/path"),
            ),
            (
                Some("192.168.1.20:8081"),
                Some("http://attacker.example:8081"),
            ),
        ] {
            let headers = websocket_headers(host, origin);

            assert!(!origin_matches_host(&headers));
        }
    }

    #[test]
    fn browser_cookie_must_match() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            "other=value; proxelar_session=browser-token"
                .parse()
                .unwrap(),
        );
        assert!(browser_cookie_matches(&headers, "browser-token"));
        assert!(!browser_cookie_matches(&headers, "wrong-token"));
        assert!(!browser_cookie_matches(&HeaderMap::new(), "browser-token"));
    }

    #[test]
    fn api_accepts_api_bearer_or_browser_cookie() {
        let (state, _broadcast_rx, _replay_rx) = test_state();
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "bearer api-token".parse().unwrap());
        assert!(api_authorized(&headers, &state));

        headers.insert(AUTHORIZATION, "Basic api-token".parse().unwrap());
        assert!(!api_authorized(&headers, &state));

        headers.remove(AUTHORIZATION);
        headers.insert(COOKIE, "proxelar_session=browser-token".parse().unwrap());
        assert!(api_authorized(&headers, &state));
    }

    #[tokio::test]
    async fn browser_authentication_sets_http_only_cookie() {
        let (state, _broadcast_rx, _replay_rx) = test_state();
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer browser-token".parse().unwrap());

        let response = api_authenticate_browser(State(Arc::new(state)), headers).await;

        assert_eq!(response.status(), rama::http::StatusCode::NO_CONTENT);
        assert_eq!(
            response.headers()[SET_COOKIE],
            "proxelar_session=browser-token; HttpOnly; SameSite=Strict; Path=/"
        );
    }

    #[tokio::test]
    async fn browser_authentication_rejects_api_and_invalid_tokens() {
        for token in ["api-token", "wrong-token"] {
            let (state, _broadcast_rx, _replay_rx) = test_state();
            let mut headers = HeaderMap::new();
            headers.insert(AUTHORIZATION, format!("Bearer {token}").parse().unwrap());

            let response = api_authenticate_browser(State(Arc::new(state)), headers).await;

            assert_eq!(response.status(), rama::http::StatusCode::FORBIDDEN);
            assert!(!response.headers().contains_key(SET_COOKIE));
        }
    }

    #[tokio::test]
    async fn wireguard_qr_requires_authentication_and_disables_caching() {
        let (mut state, _broadcast_rx, _replay_rx) = test_state();
        state.wireguard_setup = Some(Arc::new(
            WireGuardSetup::from_bytes(
                "proxelar-wg".to_owned(),
                std::path::PathBuf::from("/tmp/proxelar-wg.conf"),
                b"[Interface]\nPrivateKey = test\n\n[Peer]\nPublicKey = peer\n",
            )
            .unwrap(),
        ));
        let state = Arc::new(state);

        let forbidden_response =
            api_wireguard_svg(State(Arc::clone(&state)), HeaderMap::new()).await;
        assert_eq!(
            forbidden_response.status(),
            rama::http::StatusCode::FORBIDDEN
        );

        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, "proxelar_session=browser-token".parse().unwrap());
        let response = api_wireguard_svg(State(state), headers).await;

        assert_eq!(response.status(), rama::http::StatusCode::OK);
        assert_eq!(
            response.headers()[CONTENT_TYPE],
            "image/svg+xml; charset=utf-8"
        );
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        assert!(response_text(response).await.starts_with("<svg"));
    }

    #[tokio::test]
    async fn set_intercept_message_updates_state_and_broadcasts_status() {
        let (state, mut broadcast_rx, _replay_rx) = test_state();

        handle_client_message(r#"{"type":"SetIntercept","enabled":true}"#, &state).await;

        assert!(state.intercept.is_enabled());
        let json = broadcast_rx.recv().await.unwrap();
        assert!(json.contains("InterceptStatus"));
        assert!(json.contains("\"enabled\":true"));
    }

    #[tokio::test]
    async fn drop_message_resolves_pending_request_as_blocked() {
        let (state, _broadcast_rx, _replay_rx) = test_state();
        let mut rx = state.intercept.register(12);

        handle_client_message(r#"{"type":"Drop","id":12}"#, &state).await;

        match rx.try_recv().unwrap() {
            InterceptDecision::Block { status, body } => {
                assert_eq!(status, 504);
                assert_eq!(body.as_ref(), b"Blocked by Proxelar intercept");
            }
            _ => panic!("expected block decision"),
        }
    }

    #[tokio::test]
    async fn modified_message_builds_header_map_and_resolves_pending_request() {
        let (state, _broadcast_rx, _replay_rx) = test_state();
        let mut rx = state.intercept.register(33);

        handle_client_message(
            r#"{
                "type":"Modified",
                "id":33,
                "method":"PATCH",
                "uri":"http://api.test/items",
                "headers":[
                    {"name":"x-good","value":"yes"},
                    {"name":"x-repeat","value":"one"},
                    {"name":"x-repeat","value":"two"}
                ],
                "body":{"bytes":[255,0,1]}
            }"#,
            &state,
        )
        .await;

        match rx.try_recv().unwrap() {
            InterceptDecision::Modified {
                method,
                uri,
                headers,
                body,
            } => {
                assert_eq!(method, "PATCH");
                assert_eq!(uri, "http://api.test/items");
                assert_eq!(headers["x-good"], "yes");
                assert_eq!(headers.get_all("x-repeat").iter().count(), 2);
                assert_eq!(body.as_ref(), b"\xff\x00\x01");
            }
            _ => panic!("expected modified decision"),
        }
    }

    #[test]
    fn intercepted_protobuf_event_includes_structured_editor() {
        let mut headers = HeaderMap::new();
        headers.insert(
            rama::http::header::CONTENT_TYPE,
            "application/x-protobuf".parse().unwrap(),
        );
        let request = ProxiedRequest::new(
            Method::POST,
            "http://api.test/message".parse().unwrap(),
            Version::HTTP_11,
            headers,
            Bytes::from_static(&[0x08, 0x96, 0x01]),
            0,
        );
        let event = ProxyEvent::RequestIntercepted {
            id: 9,
            request: Box::new(request),
        };
        let value: serde_json::Value =
            serde_json::from_str(&serialize_browser_event(&event).unwrap()).unwrap();
        assert_eq!(value["RequestIntercepted"]["editor"]["format"], "protobuf");
        assert!(value["RequestIntercepted"]["editor"]["text"]
            .as_str()
            .unwrap()
            .contains("\"field\": 1"));
    }

    #[tokio::test]
    async fn structured_protobuf_message_is_validated_and_encoded() {
        let (state, _broadcast_rx, _replay_rx) = test_state();
        let mut decision_rx = state.intercept.register(34);
        handle_client_message(
            r#"{
                "type":"Modified",
                "id":34,
                "method":"POST",
                "uri":"http://api.test/message",
                "headers":{"content-type":"application/x-protobuf"},
                "body":{
                    "format":"protobuf",
                    "text":"[{\"field\":1,\"wire\":\"varint\",\"value\":\"151\"}]"
                }
            }"#,
            &state,
        )
        .await;
        let InterceptDecision::Modified { body, .. } = decision_rx.try_recv().unwrap() else {
            panic!("expected modified decision");
        };
        assert_eq!(body.as_ref(), &[0x08, 0x97, 0x01]);
    }

    #[tokio::test]
    async fn replay_message_sends_proxied_request() {
        let (state, _broadcast_rx, mut replay_rx) = test_state();

        handle_client_message(
            r#"{
                "type":"Replay",
                "method":"POST",
                "uri":"http://api.test/replay",
                "headers":{"content-type":"text/plain"},
                "body":"again"
            }"#,
            &state,
        )
        .await;

        let req = replay_rx.recv().await.unwrap();
        assert_eq!(req.method(), Method::POST);
        assert_eq!(req.uri().path().unwrap(), "/replay");
        assert_eq!(req.version(), Version::HTTP_11);
        assert_eq!(
            req.headers()[rama::http::header::CONTENT_TYPE],
            "text/plain"
        );
        assert_eq!(req.body().as_ref(), b"again");
    }

    #[tokio::test]
    async fn replay_accepts_ordered_header_pairs_without_losing_duplicates() {
        let (state, _broadcast_rx, mut replay_rx) = test_state();

        handle_client_message(
            r#"{
                "type":"Replay",
                "method":"GET",
                "uri":"http://api.test/ordered",
                "headers":[
                    ["x-repeat","one"],
                    ["x-opaque",[128,255]],
                    ["x-repeat","two"]
                ],
                "body":""
            }"#,
            &state,
        )
        .await;

        let request = replay_rx.recv().await.unwrap();
        let repeated = request
            .headers()
            .get_all("x-repeat")
            .iter()
            .map(|value| value.as_bytes())
            .collect::<Vec<_>>();
        assert_eq!(repeated, [b"one".as_slice(), b"two".as_slice()]);
        assert_eq!(request.headers()["x-opaque"].as_bytes(), &[128, 255]);
    }

    #[tokio::test]
    async fn malformed_json_and_invalid_replay_are_ignored() {
        let (state, _broadcast_rx, mut replay_rx) = test_state();

        handle_client_message("not json", &state).await;
        handle_client_message(
            r#"{"type":"Replay","method":"bad method","uri":"%%%","headers":{},"body":""}"#,
            &state,
        )
        .await;

        assert!(replay_rx.try_recv().is_err());
    }

    #[test]
    fn proxy_events_serialize_for_browser_broadcasts() {
        let event = ProxyEvent::WebSocketFrame {
            conn_id: 42,
            frame: Box::new(WsFrame::new(
                WsDirection::ServerToClient,
                WsOpcode::Text,
                100,
                Bytes::from_static(b"hello"),
                false,
            )),
        };
        let json = serde_json::to_value(&event).unwrap();
        let frame_event = json.get("WebSocketFrame").unwrap();

        assert_eq!(frame_event["conn_id"], 42);
        assert_eq!(frame_event["frame"]["direction"], "ServerToClient");
        assert_eq!(frame_event["frame"]["opcode"], "Text");
        assert_eq!(frame_event["frame"]["time"], 100);
        assert_eq!(
            frame_event["frame"]["payload"],
            serde_json::json!([104, 101, 108, 108, 111])
        );
        assert_eq!(frame_event["frame"]["truncated"], false);

        let complete = ProxyEvent::RequestComplete {
            id: 1,
            request: Box::new(ProxiedRequest::new(
                Method::GET,
                "http://api.test/".parse().unwrap(),
                Version::HTTP_11,
                HeaderMap::new(),
                Bytes::new(),
                1,
            )),
            response: Box::new(ProxiedResponse::new(
                rama::http::StatusCode::OK,
                Version::HTTP_11,
                HeaderMap::new(),
                Bytes::new(),
                2,
            )),
        };
        let json = serde_json::to_value(&complete).unwrap();
        let complete_event = json.get("RequestComplete").unwrap();

        assert_eq!(complete_event["id"], 1);
        assert_eq!(complete_event["request"]["method"], "GET");
        assert_eq!(complete_event["request"]["uri"], "http://api.test/");
        assert_eq!(complete_event["request"]["time"], 1);
        assert_eq!(complete_event["response"]["status"], 200);
        assert_eq!(complete_event["response"]["time"], 2);

        let udp = ProxyEvent::UdpExchange {
            exchange: Box::new(proxyapi_models::CapturedUdpExchange {
                id: 7,
                target: "127.0.0.1:9000".to_owned(),
                client: "127.0.0.1:50000".to_owned(),
                time: 3,
                request: Bytes::from_static(b"ping"),
                response: Bytes::new(),
                response_received: true,
                request_truncated: false,
                response_truncated: false,
            }),
        };
        let json = serde_json::to_value(&udp).unwrap();
        assert_eq!(
            json["UdpExchange"]["exchange"]["request"],
            serde_json::json!([112, 105, 110, 103])
        );
        assert_eq!(json["UdpExchange"]["exchange"]["response_received"], true);
    }
}
