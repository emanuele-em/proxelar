use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use proxyapi::ProxyEvent;
use rand::Rng;
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
}

fn generate_token() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub async fn run(
    mut event_rx: mpsc::Receiver<ProxyEvent>,
    gui_port: u16,
    cancel: CancellationToken,
) {
    let token = generate_token();
    let (broadcast_tx, _) = broadcast::channel::<String>(256);
    let state = Arc::new(WebState {
        broadcast_tx: broadcast_tx.clone(),
        token,
        gui_port,
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

    let addr = format!("127.0.0.1:{gui_port}");

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

    while let Ok(msg) = rx.recv().await {
        if socket.send(Message::Text(msg.into())).await.is_err() {
            break;
        }
    }
}
