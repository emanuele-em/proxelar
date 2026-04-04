use bytes::Bytes;
use http::HeaderMap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;

/// Map of pending intercepted requests awaiting a UI decision.
///
/// `std::sync::Mutex` is intentional: the critical sections are
/// `insert`/`remove` only — no `.await` inside — so a sync mutex is
/// the correct idiomatic choice and avoids unnecessary async overhead.
type PendingMap = Mutex<HashMap<u64, oneshot::Sender<InterceptDecision>>>;

/// The UI's decision for a paused request.
pub enum InterceptDecision {
    /// Forward the request as captured (or as modified by the UI).
    Forward,
    /// Forward the request with modifications applied by the UI.
    Modified {
        method: String,
        uri: String,
        headers: HeaderMap,
        body: Bytes,
    },
    /// Drop the request and return a synthetic response to the client.
    Block { status: u16, body: Bytes },
}

/// Shared state for the intercept feature.
///
/// Clone-cheap via `Arc` — both the proxy handlers and the UI interface
/// hold a reference to the same instance.
pub struct InterceptConfig {
    enabled: Arc<AtomicBool>,
    pending: PendingMap,
}

impl InterceptConfig {
    /// Create a new `InterceptConfig` (intercept disabled by default).
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            enabled: Arc::new(AtomicBool::new(false)),
            pending: Mutex::new(HashMap::new()),
        })
    }

    /// Returns `true` if intercept mode is currently enabled.
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Enable or disable intercept mode.
    ///
    /// When disabling, all currently pending requests are forwarded immediately
    /// so clients do not hang.
    pub fn set_enabled(&self, v: bool) {
        let prev = self.enabled.swap(v, Ordering::SeqCst);
        if prev && !v {
            self.drain_forward();
        }
    }

    /// Toggle intercept on/off. Returns the new state.
    ///
    /// When toggling **off**, all pending requests are forwarded immediately.
    pub fn toggle(&self) -> bool {
        // fetch_xor flips the bit atomically; SeqCst ensures the pending-map
        // drain happens after all handlers have observed the new value.
        let prev = self.enabled.fetch_xor(true, Ordering::SeqCst);
        let new_state = !prev;
        if !new_state {
            self.drain_forward();
        }
        new_state
    }

    /// Register a pending intercepted request.
    ///
    /// Returns the `Receiver` that `handle_request` should await.
    /// The corresponding `Sender` is stored in the pending map and will
    /// be consumed by [`resolve`](Self::resolve).
    ///
    /// # Race note
    /// A narrow window exists between `is_enabled()` returning `true` in the
    /// handler and `register()` inserting the sender: if the user toggles
    /// intercept off in that gap, `drain_forward()` runs before the sender
    /// is in the map and the request will block until the 300 s timeout fires
    /// a 504. This is acceptable — the timeout is the safety net.
    pub fn register(&self, id: u64) -> oneshot::Receiver<InterceptDecision> {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);
        rx
    }

    /// Resolve a pending request with the given decision.
    ///
    /// Returns `false` if `id` is not in the pending map (already resolved,
    /// timed out, or unknown).
    pub fn resolve(&self, id: u64, decision: InterceptDecision) -> bool {
        if let Some(tx) = self.pending.lock().unwrap().remove(&id) {
            tx.send(decision).is_ok()
        } else {
            false
        }
    }

    /// Returns the number of requests currently awaiting a UI decision.
    pub fn pending_count(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    /// Forward all pending requests immediately.
    ///
    /// Called automatically when intercept is toggled off.
    fn drain_forward(&self) {
        let mut map = self.pending.lock().unwrap();
        for (_, tx) in map.drain() {
            let _ = tx.send(InterceptDecision::Forward);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_disabled() {
        let cfg = InterceptConfig::new();
        assert!(!cfg.is_enabled());
        assert_eq!(cfg.pending_count(), 0);
    }

    #[test]
    fn test_toggle() {
        let cfg = InterceptConfig::new();
        assert!(cfg.toggle()); // off → on
        assert!(cfg.is_enabled());
        assert!(!cfg.toggle()); // on → off
        assert!(!cfg.is_enabled());
    }

    #[test]
    fn test_register_resolve_forward() {
        let cfg = InterceptConfig::new();
        let mut rx = cfg.register(1);
        assert_eq!(cfg.pending_count(), 1);
        assert!(cfg.resolve(1, InterceptDecision::Forward));
        assert_eq!(cfg.pending_count(), 0);
        // Receiver should have the value
        assert!(matches!(rx.try_recv(), Ok(InterceptDecision::Forward)));
    }

    #[test]
    fn test_resolve_unknown_id() {
        let cfg = InterceptConfig::new();
        assert!(!cfg.resolve(99, InterceptDecision::Forward));
    }

    #[test]
    fn test_drain_forward_on_toggle_off() {
        let cfg = InterceptConfig::new();
        cfg.toggle(); // enable
        let mut rx1 = cfg.register(1);
        let mut rx2 = cfg.register(2);
        assert_eq!(cfg.pending_count(), 2);
        cfg.toggle(); // disable → drains
        assert_eq!(cfg.pending_count(), 0);
        assert!(matches!(rx1.try_recv(), Ok(InterceptDecision::Forward)));
        assert!(matches!(rx2.try_recv(), Ok(InterceptDecision::Forward)));
    }

    #[test]
    fn test_set_enabled_drains_on_disable() {
        let cfg = InterceptConfig::new();
        cfg.set_enabled(true);
        let mut rx = cfg.register(42);
        cfg.set_enabled(false);
        assert_eq!(cfg.pending_count(), 0);
        assert!(matches!(rx.try_recv(), Ok(InterceptDecision::Forward)));
    }
}
