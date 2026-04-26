use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use bytes::Bytes;
use http::HeaderMap;
use proxyapi::{InterceptConfig, InterceptDecision, ProxyEvent};
use proxyapi_models::ProxiedRequest;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;

const INDEX_HTML: &str = include_str!("assets/index.html");
const STYLE_CSS: &str = include_str!("assets/style.css");
const APP_JS: &str = include_str!("assets/app.js");

struct WebState {
    broadcast_tx: broadcast::Sender<String>,
    token: String,
    gui_port: u16,
    intercept: Arc<InterceptConfig>,
    replay_tx: mpsc::Sender<ProxiedRequest>,
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
        headers: HashMap<String, String>,
        body: String,
    },
    /// Replay a previously captured request.
    Replay {
        method: String,
        uri: String,
        headers: HashMap<String, String>,
        body: String,
    },
}

/// Status broadcast to all connected browser clients when intercept state changes.
#[derive(Serialize)]
struct InterceptStatus {
    enabled: bool,
    pending_count: usize,
}

pub async fn run(
    mut event_rx: mpsc::Receiver<ProxyEvent>,
    intercept: Arc<InterceptConfig>,
    replay_tx: mpsc::Sender<ProxiedRequest>,
    gui_addr: std::net::IpAddr,
    gui_port: u16,
    cancel: CancellationToken,
) {
    let token = generate_token();
    let (broadcast_tx, _) = broadcast::channel::<String>(256);
    let state = Arc::new(WebState {
        broadcast_tx: broadcast_tx.clone(),
        token,
        gui_port,
        intercept,
        replay_tx,
    });

    // Background task: forward proxy events to broadcast channel
    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            match serde_json::to_string(&event) {
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

    let app = Router::new()
        .route("/", get(index_handler))
        .route("/style.css", get(css_handler))
        .route("/app.js", get(js_handler))
        .route("/ws", get(ws_handler))
        .with_state(state);

    let addr = format!("{gui_addr}:{gui_port}");

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind web GUI on {addr}: {e}");
            return;
        }
    };

    // Open browser *after* successful bind
    let url = format!("http://{addr}");
    tracing::info!("Web GUI available at {url}");
    if let Err(e) = open::that(&url) {
        tracing::warn!("Failed to open browser: {e}");
    }

    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(cancel.cancelled_owned())
        .await
    {
        tracing::error!("Web GUI server error: {e}");
    }
}

async fn index_handler() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn css_handler() -> impl IntoResponse {
    ([(axum::http::header::CONTENT_TYPE, "text/css")], STYLE_CSS)
}

async fn js_handler(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let js = APP_JS.replace("__WS_TOKEN__", &state.token);
    (
        [(axum::http::header::CONTENT_TYPE, "application/javascript")],
        js,
    )
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    headers: axum::http::HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<Arc<WebState>>,
) -> axum::response::Response {
    // Validate Origin header
    let allowed_origins = [
        format!("http://127.0.0.1:{}", state.gui_port),
        format!("http://localhost:{}", state.gui_port),
    ];
    match headers.get("origin").and_then(|v| v.to_str().ok()) {
        Some(origin) if allowed_origins.iter().any(|a| a == origin) => {}
        _ => return (axum::http::StatusCode::FORBIDDEN, "Forbidden").into_response(),
    }

    // Validate token
    match params.get("token") {
        Some(t) if t == &state.token => {}
        _ => return (axum::http::StatusCode::FORBIDDEN, "Forbidden").into_response(),
    }

    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: Arc<WebState>) {
    let mut rx = state.broadcast_tx.subscribe();

    loop {
        tokio::select! {
            // Proxy events → browser
            result = rx.recv() => {
                match result {
                    Ok(msg) => {
                        if socket.send(Message::Text(msg.into())).await.is_err() {
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
            result = socket.recv() => {
                match result {
                    Some(Ok(Message::Text(text))) => {
                        handle_client_message(&text, &state).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(e)) => {
                        tracing::debug!("WebSocket receive error: {e}");
                        break;
                    }
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
            let mut header_map = HeaderMap::new();
            for (k, v) in &headers {
                if let (Ok(name), Ok(value)) = (
                    http::header::HeaderName::from_bytes(k.as_bytes()),
                    http::header::HeaderValue::from_str(v),
                ) {
                    header_map.append(name, value);
                }
            }
            state.intercept.resolve(
                id,
                InterceptDecision::Modified {
                    method,
                    uri,
                    headers: header_map,
                    body: Bytes::from(body.into_bytes()),
                },
            );
        }
        ClientMessage::Replay {
            method,
            uri,
            headers,
            body,
        } => {
            let mut header_map = HeaderMap::new();
            for (k, v) in &headers {
                if let (Ok(name), Ok(value)) = (
                    http::header::HeaderName::from_bytes(k.as_bytes()),
                    http::header::HeaderValue::from_str(v),
                ) {
                    header_map.append(name, value);
                }
            }
            let method = method.parse().unwrap_or(http::Method::GET);
            let uri = uri.parse().unwrap_or_else(|_| "/".parse().unwrap());
            let now = chrono::Local::now().timestamp_millis();
            let req = ProxiedRequest::new(
                method,
                uri,
                http::Version::HTTP_11,
                header_map,
                Bytes::from(body.into_bytes()),
                now,
            );
            if state.replay_tx.try_send(req).is_err() {
                tracing::warn!("Replay channel full");
            }
        }
    }
}
