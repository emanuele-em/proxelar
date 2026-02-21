use proxyapi_models::{ProxiedRequest, ProxiedResponse};
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
    /// A non-fatal error occurred during proxying.
    Error {
        /// Human-readable error description.
        message: String,
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
