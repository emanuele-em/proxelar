use bytes::Bytes;
use futures_util::StreamExt as _;
use http::{Method, StatusCode, Version};
use proxelar_proto::{
    BodyFrame, ErrorKind, ProtocolError, ProxyBody, ProxyRequest, ProxyResponse, RequestHead,
    ResponseHead,
};
use proxyapi_models::{HeaderBlock, HeaderField};

#[tokio::test]
async fn body_stream_preserves_data_and_trailer_frames() {
    let trailers = HeaderBlock::from_fields([
        HeaderField::new("X-Checksum", "one").unwrap(),
        HeaderField::new("X-Checksum", "two").unwrap(),
    ]);
    let mut body = ProxyBody::from_frames([
        Ok(BodyFrame::Data(Bytes::from_static(b"hello "))),
        Ok(BodyFrame::Data(Bytes::from_static(b"world"))),
        Ok(BodyFrame::Trailers(trailers.clone())),
    ]);

    assert_eq!(
        body.next().await.unwrap().unwrap(),
        BodyFrame::Data(Bytes::from_static(b"hello "))
    );
    assert_eq!(
        body.next().await.unwrap().unwrap(),
        BodyFrame::Data(Bytes::from_static(b"world"))
    );
    assert_eq!(
        body.next().await.unwrap().unwrap(),
        BodyFrame::Trailers(trailers)
    );
    assert!(body.next().await.is_none());
}

#[tokio::test]
async fn explicit_collection_rejects_multiple_trailer_blocks() {
    let body = ProxyBody::from_frames([
        Ok(BodyFrame::Trailers(HeaderBlock::new())),
        Ok(BodyFrame::Trailers(HeaderBlock::new())),
    ]);

    let error = body.collect().await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ProtocolViolation);
}

#[tokio::test]
async fn protocol_errors_flow_through_bodies_without_engine_types() {
    let expected = ProtocolError::new(ErrorKind::Reset, "peer reset stream 7");
    let mut body = ProxyBody::from_frames([Err(expected.clone())]);
    assert_eq!(body.next().await.unwrap().unwrap_err(), expected);
}

#[tokio::test]
async fn request_and_response_heads_are_transport_neutral() {
    let request = ProxyRequest::new(
        RequestHead::new(
            Method::POST,
            "https://example.test/upload".parse().unwrap(),
            Version::HTTP_3,
            HeaderBlock::new(),
        ),
        ProxyBody::full(Bytes::from_static(b"request")),
    );
    let response = ProxyResponse::new(
        ResponseHead::new(StatusCode::CREATED, Version::HTTP_2, HeaderBlock::new()),
        ProxyBody::full(Bytes::from_static(b"response")),
    );

    let (request_head, request_body) = request.into_parts();
    let (response_head, response_body) = response.into_parts();
    assert_eq!(request_head.version, Version::HTTP_3);
    assert_eq!(response_head.status, StatusCode::CREATED);
    assert_eq!(request_body.collect().await.unwrap().data, b"request"[..]);
    assert_eq!(response_body.collect().await.unwrap().data, b"response"[..]);
}
