use rama::bytes::{Bytes, BytesMut};
use rama::error::BoxError;
use rama::http::body::{Frame, SizeHint};
use rama::http::{Body, StreamingBody};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

/// Boxed HTTP body type used throughout the proxy.
///
/// rama exposes a single unified [`Body`] for both requests and responses, so
/// this alias keeps the existing call sites readable while pointing at it.
pub type ProxyBody = Body;

#[derive(Clone, Debug)]
pub(crate) struct BodyCapture {
    inner: Arc<Mutex<BodyCaptureState>>,
    limit: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BodySnapshot {
    pub bytes: Bytes,
    pub truncated: bool,
    pub total_seen: usize,
}

#[derive(Debug)]
struct BodyCaptureState {
    bytes: BytesMut,
    truncated: bool,
    total_seen: usize,
}

impl BodyCapture {
    pub(crate) fn new(limit: Option<usize>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BodyCaptureState {
                bytes: BytesMut::new(),
                truncated: false,
                total_seen: 0,
            })),
            limit,
        }
    }

    pub(crate) fn append(&self, chunk: &Bytes) {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        state.total_seen = state.total_seen.saturating_add(chunk.len());

        if let Some(limit) = self.limit {
            let remaining = limit.saturating_sub(state.bytes.len());
            if remaining > 0 {
                let keep = remaining.min(chunk.len());
                state.bytes.extend_from_slice(&chunk[..keep]);
            }
            if chunk.len() > remaining {
                state.truncated = true;
            }
        } else {
            state.bytes.extend_from_slice(chunk);
        }
    }

    pub(crate) fn snapshot(&self) -> BodySnapshot {
        let state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        BodySnapshot {
            bytes: Bytes::copy_from_slice(&state.bytes),
            truncated: state.truncated,
            total_seen: state.total_seen,
        }
    }
}

/// A streaming body that taps every data frame into a [`BodyCapture`] and runs
/// a completion callback exactly once — on normal EOF, on error, or on drop.
///
/// rama ships the two disjoint halves of this behaviour (`BodyExt::inspect_frame`
/// for the per-frame tap and `Body::on_drop` which fires only on early drop and
/// is disarmed at EOF), but no single combinator that fires on *any* terminal
/// event, which is exactly what the `RequestComplete` event emission requires.
/// So we keep a small bespoke [`StreamingBody`] built on rama's public body API.
struct CaptureBody<B, F: FnOnce()> {
    inner: Pin<Box<B>>,
    capture: BodyCapture,
    on_complete: Option<F>,
}

impl<B, F> CaptureBody<B, F>
where
    F: FnOnce(),
{
    fn new(body: B, capture: BodyCapture, on_complete: F) -> Self {
        Self {
            inner: Box::pin(body),
            capture,
            on_complete: Some(on_complete),
        }
    }

    fn complete(&mut self) {
        if let Some(on_complete) = self.on_complete.take() {
            on_complete();
        }
    }
}

impl<B, F> Unpin for CaptureBody<B, F> where F: FnOnce() {}

impl<B, F> StreamingBody for CaptureBody<B, F>
where
    B: StreamingBody<Data = Bytes>,
    B::Error: Into<BoxError>,
    F: FnOnce(),
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match this.inner.as_mut().poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.capture.append(data);
                }
                if this.inner.is_end_stream() {
                    this.complete();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                this.complete();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(e))) => {
                this.complete();
                Poll::Ready(Some(Err(e.into())))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl<B, F> Drop for CaptureBody<B, F>
where
    F: FnOnce(),
{
    fn drop(&mut self) {
        self.complete();
    }
}

pub(crate) fn capture<B, F>(body: B, capture: BodyCapture, on_complete: F) -> ProxyBody
where
    B: StreamingBody<Data = Bytes> + Send + Sync + 'static,
    B::Error: Into<BoxError>,
    F: FnOnce() + Send + Sync + 'static,
{
    Body::new(CaptureBody::new(body, capture, on_complete))
}

/// Create a body from the given bytes.
pub fn full(bytes: Bytes) -> ProxyBody {
    Body::from(bytes)
}

/// Create an empty body.
pub fn empty() -> ProxyBody {
    Body::empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::http::body::util::BodyExt;

    #[tokio::test]
    async fn test_full_body() {
        let body = full(Bytes::from("hello"));
        let collected = body.collect().await.unwrap().to_bytes();
        assert_eq!(collected, Bytes::from("hello"));
    }

    #[tokio::test]
    async fn test_empty_body() {
        let body = empty();
        let collected = body.collect().await.unwrap().to_bytes();
        assert!(collected.is_empty());
    }

    #[tokio::test]
    async fn capture_body_forwards_all_bytes_and_caps_snapshot() {
        let capture_state = BodyCapture::new(Some(4));
        let body = capture(
            full(Bytes::from_static(b"abcdef")),
            capture_state.clone(),
            || {},
        );

        let collected = body.collect().await.unwrap().to_bytes();
        let snapshot = capture_state.snapshot();

        assert_eq!(collected.as_ref(), b"abcdef");
        assert_eq!(snapshot.bytes.as_ref(), b"abcd");
        assert!(snapshot.truncated);
        assert_eq!(snapshot.total_seen, 6);
    }

    #[tokio::test]
    async fn capture_body_keeps_full_snapshot_when_unlimited() {
        let capture_state = BodyCapture::new(None);
        let body = capture(
            full(Bytes::from_static(b"abcdef")),
            capture_state.clone(),
            || {},
        );

        let collected = body.collect().await.unwrap().to_bytes();
        let snapshot = capture_state.snapshot();

        assert_eq!(collected.as_ref(), b"abcdef");
        assert_eq!(snapshot.bytes.as_ref(), b"abcdef");
        assert!(!snapshot.truncated);
        assert_eq!(snapshot.total_seen, 6);
    }

    #[tokio::test]
    async fn capture_body_runs_completion_once_at_end_of_stream() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let completed = Arc::new(AtomicUsize::new(0));
        let completed_for_body = Arc::clone(&completed);
        let body = capture(full(Bytes::new()), BodyCapture::new(Some(16)), move || {
            completed_for_body.fetch_add(1, Ordering::SeqCst);
        });

        let collected = body.collect().await.unwrap().to_bytes();

        assert!(collected.is_empty());
        assert_eq!(completed.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn capture_body_runs_completion_when_dropped_before_eof() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let completed = Arc::new(AtomicUsize::new(0));
        let completed_for_body = Arc::clone(&completed);
        let body = capture(
            full(Bytes::from_static(b"body")),
            BodyCapture::new(Some(16)),
            move || {
                completed_for_body.fetch_add(1, Ordering::SeqCst);
            },
        );

        drop(body);

        assert_eq!(completed.load(Ordering::SeqCst), 1);
    }
}
