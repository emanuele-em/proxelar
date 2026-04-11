use proxyapi_models::{ProxiedRequest, ProxiedResponse, WsFrame};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// An event emitted by the proxy for each completed request/response pair.
///
/// Variants are boxed to keep the enum size small.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProxyEvent {
    /// A full request/response round-trip was captured.
    RequestComplete {
        /// Monotonically increasing event identifier.
        id: u64,
        /// The captured request.
        request: Box<ProxiedRequest>,
        /// The captured response.
        response: Box<ProxiedResponse>,
    },
    /// A request is held pending a UI decision (intercept mode).
    ///
    /// The proxy handler is paused until the UI calls
    /// [`InterceptConfig::resolve`](crate::intercept::InterceptConfig::resolve).
    /// The `id` matches the eventual [`RequestComplete`](Self::RequestComplete)
    /// event for the same flow.
    RequestIntercepted {
        /// Same ID that will appear in the `RequestComplete` event for this flow.
        id: u64,
        /// Snapshot of the captured request.
        request: Box<ProxiedRequest>,
    },
    /// A non-fatal error occurred during proxying.
    Error {
        /// Human-readable error description.
        message: String,
    },
    /// A WebSocket upgrade completed (101 Switching Protocols received).
    ///
    /// The `id` is shared with all subsequent [`WebSocketFrame`](Self::WebSocketFrame)
    /// and [`WebSocketClosed`](Self::WebSocketClosed) events for this connection.
    WebSocketConnected {
        id: u64,
        request: Box<ProxiedRequest>,
        /// The 101 response — contains `Sec-WebSocket-Accept`, negotiated subprotocol, etc.
        response: Box<ProxiedResponse>,
    },
    /// A single WebSocket frame was captured (either direction).
    WebSocketFrame {
        /// Matches the `id` of the [`WebSocketConnected`](Self::WebSocketConnected) event.
        conn_id: u64,
        frame: Box<WsFrame>,
    },
    /// The WebSocket connection closed (either side closed, or an error occurred).
    WebSocketClosed {
        conn_id: u64,
    },
}

pub(crate) fn next_id() -> u64 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next_id_increments() {
        let id1 = next_id();
        let id2 = next_id();
        assert!(id2 > id1);
    }
}
