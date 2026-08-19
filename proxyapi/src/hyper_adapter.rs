//! Temporary streaming adapter between Hyper's body trait and protocol-core messages.
//!
//! Hyper remains a connection engine while the native drivers are introduced,
//! but no Hyper type crosses the public handler boundary.

use std::fmt::Display;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::Stream;
use hyper::body::{Body, Frame, SizeHint};
use proxelar_proto::{
    BodyFrame, ErrorKind, ProtocolError, ProxyBody, ProxyRequest, ProxyResponse, RequestHead,
    ResponseHead,
};

pub(crate) struct HyperBody {
    inner: ProxyBody,
}

impl HyperBody {
    pub(crate) const fn new(inner: ProxyBody) -> Self {
        Self { inner }
    }

    pub(crate) fn full(data: impl Into<Bytes>) -> Self {
        Self::new(ProxyBody::full(data))
    }

    pub(crate) fn empty() -> Self {
        Self::new(ProxyBody::empty())
    }
}

impl Body for HyperBody {
    type Data = Bytes;
    type Error = ProtocolError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(BodyFrame::Data(data)))) => {
                Poll::Ready(Some(Ok(Frame::data(data))))
            }
            Poll::Ready(Some(Ok(BodyFrame::Trailers(trailers)))) => {
                let trailers = crate::header::to_http(&trailers).map_err(|error| {
                    ProtocolError::new(ErrorKind::MalformedMessage, error.to_string())
                });
                Poll::Ready(Some(trailers.map(Frame::trailers)))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> SizeHint {
        let mut hint = SizeHint::default();
        if let Some(length) = self.inner.exact_length() {
            hint.set_exact(length);
        }
        hint
    }
}

struct HyperBodyStream<B> {
    inner: Pin<Box<B>>,
}

impl<B> Stream for HyperBodyStream<B>
where
    B: Body<Data = Bytes>,
    B::Error: Display,
{
    type Item = Result<BodyFrame, ProtocolError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.inner.as_mut().poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => Poll::Ready(Some(Ok(BodyFrame::Data(data)))),
                Err(frame) => match frame.into_trailers() {
                    Ok(trailers) => Poll::Ready(Some(Ok(BodyFrame::Trailers(
                        crate::header::from_http(&trailers),
                    )))),
                    Err(_) => Poll::Ready(Some(Err(ProtocolError::new(
                        ErrorKind::Unsupported,
                        "Hyper produced an unsupported body frame",
                    )))),
                },
            },
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(ProtocolError::new(
                ErrorKind::Io,
                error.to_string(),
            )))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub(crate) fn from_hyper_body<B>(body: B) -> ProxyBody
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Display,
{
    let exact_length = body
        .size_hint()
        .upper()
        .filter(|upper| *upper == body.size_hint().lower());
    let body = ProxyBody::new(HyperBodyStream {
        inner: Box::pin(body),
    });
    match exact_length {
        Some(length) => body.with_exact_length(length),
        None => body,
    }
}

pub(crate) fn from_hyper_request<B>(request: http::Request<B>) -> ProxyRequest
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Display,
{
    let (parts, body) = request.into_parts();
    ProxyRequest::new(
        RequestHead::new(
            parts.method,
            parts.uri,
            parts.version,
            crate::header::from_http(&parts.headers),
        ),
        from_hyper_body(body),
    )
}

pub(crate) fn from_hyper_response<B>(response: http::Response<B>) -> ProxyResponse
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Display,
{
    let (parts, body) = response.into_parts();
    ProxyResponse::new(
        ResponseHead::new(
            parts.status,
            parts.version,
            crate::header::from_http(&parts.headers),
        ),
        from_hyper_body(body),
    )
}

pub(crate) fn to_hyper_request(
    request: ProxyRequest,
) -> Result<http::Request<HyperBody>, ProtocolError> {
    let (head, body) = request.into_parts();
    let mut request = http::Request::new(HyperBody::new(body));
    *request.method_mut() = head.method;
    *request.uri_mut() = head.uri;
    *request.version_mut() = head.version;
    *request.headers_mut() = crate::header::to_http(&head.headers)
        .map_err(|error| ProtocolError::new(ErrorKind::MalformedMessage, error.to_string()))?;
    Ok(request)
}

pub(crate) fn to_hyper_response(
    response: ProxyResponse,
) -> Result<http::Response<HyperBody>, ProtocolError> {
    let (head, body) = response.into_parts();
    let mut response = http::Response::new(HyperBody::new(body));
    *response.status_mut() = head.status;
    *response.version_mut() = head.version;
    *response.headers_mut() = crate::header::to_http(&head.headers)
        .map_err(|error| ProtocolError::new(ErrorKind::MalformedMessage, error.to_string()))?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxyapi_models::{HeaderBlock, HeaderField};

    #[tokio::test]
    async fn adapter_streams_data_and_trailers_in_both_directions() {
        let trailers = HeaderBlock::from_fields([
            HeaderField::new("x-checksum", "one").unwrap(),
            HeaderField::new("x-checksum", "two").unwrap(),
        ]);
        let protocol = ProxyBody::from_frames([
            Ok(BodyFrame::Data(Bytes::from_static(b"payload"))),
            Ok(BodyFrame::Trailers(trailers.clone())),
        ]);

        let collected = from_hyper_body(HyperBody::new(protocol))
            .collect()
            .await
            .unwrap();
        assert_eq!(collected.data, Bytes::from_static(b"payload"));
        assert_eq!(collected.trailers, Some(trailers));
    }
}
