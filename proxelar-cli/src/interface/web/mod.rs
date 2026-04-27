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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::response::IntoResponse;
    use http::{Method, Version};
    use proxyapi_models::{ProxiedResponse, WsDirection, WsFrame, WsOpcode};

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
                token: "test-token".to_owned(),
                gui_port: 8081,
                intercept: InterceptConfig::new(),
                replay_tx,
            },
            broadcast_rx,
            replay_rx,
        )
    }

    async fn response_text(response: axum::response::Response) -> String {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[test]
    fn generate_token_returns_64_hex_chars() {
        let token = generate_token();

        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn static_asset_handlers_return_expected_content() {
        let (state, _broadcast_rx, _replay_rx) = test_state();
        let state = Arc::new(state);

        let index = index_handler().await.into_response();
        assert_eq!(index.status(), http::StatusCode::OK);
        assert!(response_text(index).await.contains("<html"));

        let css = css_handler().await.into_response();
        assert_eq!(css.headers()[http::header::CONTENT_TYPE], "text/css");
        assert!(response_text(css).await.contains(":root"));

        let js = js_handler(State(state)).await.into_response();
        assert_eq!(
            js.headers()[http::header::CONTENT_TYPE],
            "application/javascript"
        );
        let js_text = response_text(js).await;
        assert!(js_text.contains("test-token"));
        assert!(!js_text.contains("__WS_TOKEN__"));
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
                "headers":{"x-good":"yes","bad header":"ignored"},
                "body":"changed"
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
                assert!(!headers.contains_key("bad header"));
                assert_eq!(body.as_ref(), b"changed");
            }
            _ => panic!("expected modified decision"),
        }
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
        assert_eq!(req.uri().path(), "/replay");
        assert_eq!(req.version(), Version::HTTP_11);
        assert_eq!(req.headers()[http::header::CONTENT_TYPE], "text/plain");
        assert_eq!(req.body().as_ref(), b"again");
    }

    #[tokio::test]
    async fn malformed_json_is_ignored_and_replay_falls_back_for_bad_uri() {
        let (state, _broadcast_rx, mut replay_rx) = test_state();

        handle_client_message("not json", &state).await;
        handle_client_message(
            r#"{"type":"Replay","method":"bad","uri":"%%%","headers":{},"body":""}"#,
            &state,
        )
        .await;

        let req = replay_rx.recv().await.unwrap();
        assert_eq!(req.method().as_str(), "bad");
        assert_eq!(req.uri().path(), "/");
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
                http::StatusCode::OK,
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
    }
}
