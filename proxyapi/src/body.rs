use bytes::{Bytes, BytesMut};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

/// Boxed HTTP body type used throughout the proxy.
///
/// Erases the concrete body type so that both `Full` (captured) and `Empty`
/// bodies can be returned in the same position.
pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

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
}

impl<B, F> CaptureBody<B, F>
where
    F: FnOnce(),
{
    fn complete(&mut self) {
        if let Some(on_complete) = self.on_complete.take() {
            on_complete();
        }
    }
}

impl<B, F> Unpin for CaptureBody<B, F> where F: FnOnce() {}

impl<B, F> HttpBody for CaptureBody<B, F>
where
    B: HttpBody<Data = Bytes, Error = hyper::Error>,
    F: FnOnce(),
{
    type Data = Bytes;
    type Error = hyper::Error;

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
                Poll::Ready(Some(Err(e)))
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
    B: HttpBody<Data = Bytes, Error = hyper::Error> + Send + Sync + 'static,
    F: FnOnce() + Send + Sync + 'static,
{
    CaptureBody::new(body, capture, on_complete).boxed()
}

struct PrefixBody<B> {
    prefixes: VecDeque<Bytes>,
    inner: Pin<Box<B>>,
}

impl<B> PrefixBody<B> {
    fn new<I>(prefixes: I, body: B) -> Self
    where
        I: IntoIterator<Item = Bytes>,
    {
        Self {
            prefixes: prefixes
                .into_iter()
                .filter(|bytes| !bytes.is_empty())
                .collect(),
            inner: Box::pin(body),
        }
    }
}

impl<B> Unpin for PrefixBody<B> {}

impl<B> HttpBody for PrefixBody<B>
where
    B: HttpBody<Data = Bytes, Error = hyper::Error>,
{
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(prefix) = this.prefixes.pop_front() {
            return Poll::Ready(Some(Ok(Frame::data(prefix))));
        }

        this.inner.as_mut().poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.prefixes.is_empty() && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        let mut hint = self.inner.size_hint();
        let prefix_len = self
            .prefixes
            .iter()
            .fold(0_u64, |acc, bytes| acc.saturating_add(bytes.len() as u64));

        let lower = hint.lower().saturating_add(prefix_len);
        if let Some(upper) = hint.upper() {
            hint.set_upper(upper.saturating_add(prefix_len));
        }
        hint.set_lower(lower);

        hint
    }
}

pub(crate) fn prefix<B, I>(prefixes: I, body: B) -> ProxyBody
where
    B: HttpBody<Data = Bytes, Error = hyper::Error> + Send + Sync + 'static,
    I: IntoIterator<Item = Bytes>,
{
    PrefixBody::new(prefixes, body).boxed()
}

/// Create a body from the given bytes.
pub fn full(bytes: Bytes) -> ProxyBody {
    Full::new(bytes).map_err(|never| match never {}).boxed()
}

/// Create an empty body.
#[must_use]
pub fn empty() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

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

    #[tokio::test]
    async fn prefix_body_replays_prefixes_before_inner_body() {
        let body = prefix(
            [
                Bytes::from_static(b"hello "),
                Bytes::new(),
                Bytes::from_static(b"from "),
            ],
            full(Bytes::from_static(b"inner")),
        );

        let collected = body.collect().await.unwrap().to_bytes();

        assert_eq!(collected.as_ref(), b"hello from inner");
    }
}
