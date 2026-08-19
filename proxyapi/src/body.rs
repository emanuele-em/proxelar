use bytes::{Bytes, BytesMut};
use futures_util::Stream;
use proxelar_proto::{BodyFrame, BodyResult};
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

pub use proxelar_proto::ProxyBody;

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
        let mut state = self.inner.lock().unwrap_or_else(|error| error.into_inner());
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
        let state = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        BodySnapshot {
            bytes: Bytes::copy_from_slice(&state.bytes),
            truncated: state.truncated,
            total_seen: state.total_seen,
        }
    }
}

struct CaptureBody<F: FnOnce()> {
    inner: ProxyBody,
    capture: BodyCapture,
    on_complete: Option<F>,
}

impl<F: FnOnce()> CaptureBody<F> {
    fn complete(&mut self) {
        if let Some(on_complete) = self.on_complete.take() {
            on_complete();
        }
    }
}

impl<F> Stream for CaptureBody<F>
where
    F: FnOnce() + Unpin,
{
    type Item = BodyResult;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let BodyFrame::Data(data) = &frame {
                    this.capture.append(data);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.complete();
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                this.complete();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<F: FnOnce()> Drop for CaptureBody<F> {
    fn drop(&mut self) {
        self.complete();
    }
}

pub(crate) fn capture<F>(body: ProxyBody, capture: BodyCapture, on_complete: F) -> ProxyBody
where
    F: FnOnce() + Send + Unpin + 'static,
{
    let exact_length = body.exact_length();
    let may_have_trailers = body.may_have_trailers();
    let body = ProxyBody::new(CaptureBody {
        inner: body,
        capture,
        on_complete: Some(on_complete),
    })
    .with_trailer_hint(may_have_trailers);
    match exact_length {
        Some(length) => body.with_exact_length(length),
        None => body,
    }
}

struct PrefixBody {
    prefixes: VecDeque<BodyResult>,
    inner: ProxyBody,
}

impl Stream for PrefixBody {
    type Item = BodyResult;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(prefix) = self.prefixes.pop_front() {
            return Poll::Ready(Some(prefix));
        }
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

pub(crate) fn prefix<I>(prefixes: I, body: ProxyBody) -> ProxyBody
where
    I: IntoIterator<Item = BodyFrame>,
{
    ProxyBody::new(PrefixBody {
        prefixes: prefixes.into_iter().map(Ok).collect(),
        inner: body,
    })
}

/// Create a body from the given bytes.
pub fn full(bytes: Bytes) -> ProxyBody {
    ProxyBody::full(bytes)
}

/// Create an empty body.
#[must_use]
pub fn empty() -> ProxyBody {
    ProxyBody::empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxyapi_models::HeaderBlock;

    #[tokio::test]
    async fn full_body_collects_without_transport_types() {
        let collected = full(Bytes::from_static(b"hello")).collect().await.unwrap();
        assert_eq!(collected.data, Bytes::from_static(b"hello"));
        assert_eq!(collected.trailers, None);
    }

    #[tokio::test]
    async fn capture_preserves_trailers() {
        let trailers = HeaderBlock::new();
        let body = ProxyBody::from_frames([
            Ok(BodyFrame::Data(Bytes::from_static(b"data"))),
            Ok(BodyFrame::Trailers(trailers.clone())),
        ]);
        let capture_state = BodyCapture::new(None);
        let output = capture(body, capture_state.clone(), || {})
            .collect()
            .await
            .unwrap();
        assert_eq!(output.data, Bytes::from_static(b"data"));
        assert_eq!(output.trailers, Some(trailers));
        assert_eq!(capture_state.snapshot().bytes, Bytes::from_static(b"data"));
    }
}
