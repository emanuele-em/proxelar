use std::collections::VecDeque;
use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use futures_core::Stream;
use futures_util::StreamExt as _;
use proxyapi_models::HeaderBlock;

use crate::{ErrorKind, ProtocolError};

/// A transport-neutral HTTP body frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BodyFrame {
    Data(Bytes),
    Trailers(HeaderBlock),
}

pub type BodyResult = Result<BodyFrame, ProtocolError>;

/// A fully collected body used only where buffering is explicitly required.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CollectedBody {
    pub data: Bytes,
    pub trailers: Option<HeaderBlock>,
}

impl CollectedBody {
    /// Return the collected data bytes, matching the common body-collector API.
    pub fn to_bytes(self) -> Bytes {
        self.data
    }
}

/// A backpressure-aware stream of data and trailer frames.
///
/// Pulling the next item is the only way to advance the producer, so protocol
/// drivers can couple stream polling directly to H1 reads or H2/H3 flow-control
/// credit. No body buffering is implicit in this type.
pub struct ProxyBody {
    inner: Pin<Box<dyn Stream<Item = BodyResult> + Send + 'static>>,
    exact_length: Option<u64>,
}

impl ProxyBody {
    pub fn new<S>(stream: S) -> Self
    where
        S: Stream<Item = BodyResult> + Send + 'static,
    {
        Self {
            inner: Box::pin(stream),
            exact_length: None,
        }
    }

    pub fn empty() -> Self {
        Self::from_frames([])
    }

    pub fn full(data: impl Into<Bytes>) -> Self {
        let data = data.into();
        let length = data.len() as u64;
        Self::from_frames([Ok(BodyFrame::Data(data))]).with_exact_length(length)
    }

    pub fn from_frames(frames: impl IntoIterator<Item = BodyResult>) -> Self {
        let frames = frames.into_iter().collect::<VecDeque<_>>();
        let exact_length = frames.iter().try_fold(0_u64, |length, frame| match frame {
            Ok(BodyFrame::Data(data)) => length.checked_add(data.len() as u64),
            Ok(BodyFrame::Trailers(_)) => Some(length),
            Err(_) => None,
        });
        Self {
            inner: Box::pin(ReadyFrames { frames }),
            exact_length,
        }
    }

    /// Declare the exact number of data bytes produced by this body.
    ///
    /// Protocol adapters use this to select framing without polling the stream.
    pub fn with_exact_length(mut self, length: u64) -> Self {
        self.exact_length = Some(length);
        self
    }

    /// Return the exact data length when the producer can determine it upfront.
    pub const fn exact_length(&self) -> Option<u64> {
        self.exact_length
    }

    /// Collect a body while retaining ordered trailers.
    ///
    /// Protocols permit at most one trailer block. A second block is rejected
    /// instead of being silently merged or reordered.
    pub async fn collect(mut self) -> Result<CollectedBody, ProtocolError> {
        let mut data = BytesMut::new();
        let mut trailers = None;
        while let Some(frame) = self.next().await {
            match frame? {
                BodyFrame::Data(bytes) => data.extend_from_slice(&bytes),
                BodyFrame::Trailers(headers) if trailers.is_none() => trailers = Some(headers),
                BodyFrame::Trailers(_) => {
                    return Err(ProtocolError::new(
                        ErrorKind::ProtocolViolation,
                        "body contains more than one trailer block",
                    ));
                }
            }
        }
        Ok(CollectedBody {
            data: data.freeze(),
            trailers,
        })
    }
}

impl Stream for ProxyBody {
    type Item = BodyResult;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(context)
    }
}

impl fmt::Debug for ProxyBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProxyBody { .. }")
    }
}

struct ReadyFrames {
    frames: VecDeque<BodyResult>,
}

impl Stream for ReadyFrames {
    type Item = BodyResult;

    fn poll_next(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.frames.pop_front())
    }
}
