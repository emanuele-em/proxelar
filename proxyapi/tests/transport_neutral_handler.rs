use bytes::Bytes;
use proxyapi::{
    BodyFrame, HttpContext, HttpHandler, ProxyBody, ProxyRequest, ProxyResponse, RequestHead,
    RequestOrResponse, ResponseHead,
};
use proxyapi_models::{HeaderBlock, HeaderField};

#[derive(Clone)]
struct NeutralHandler;

#[async_trait::async_trait]
impl HttpHandler for NeutralHandler {
    async fn handle_request(
        &mut self,
        _context: &HttpContext,
        request: ProxyRequest,
    ) -> RequestOrResponse {
        RequestOrResponse::Request(request)
    }

    async fn handle_response(
        &mut self,
        _context: &HttpContext,
        mut response: ProxyResponse,
    ) -> ProxyResponse {
        response.head.headers.add("x-handler", "neutral").unwrap();
        response
    }
}

#[tokio::test]
async fn public_handler_boundary_preserves_transport_neutral_frames() {
    let context = HttpContext {
        remote_addr: "127.0.0.1:12345".parse().unwrap(),
    };
    let mut handler = NeutralHandler;
    let request = ProxyRequest::new(
        RequestHead::new(
            http::Method::POST,
            "https://example.test/upload".parse().unwrap(),
            http::Version::HTTP_2,
            HeaderBlock::from_fields([
                HeaderField::new("x-duplicate", "one").unwrap(),
                HeaderField::new("x-duplicate", "two").unwrap(),
            ]),
        ),
        ProxyBody::full(Bytes::from_static(b"request")),
    );

    let RequestOrResponse::Request(request) = handler.handle_request(&context, request).await
    else {
        panic!("request was unexpectedly short-circuited");
    };
    assert_eq!(
        request.headers().get_all("x-duplicate").collect::<Vec<_>>(),
        vec![b"one".as_slice(), b"two".as_slice()]
    );

    let trailers = HeaderBlock::from_fields([
        HeaderField::new("x-checksum", "first").unwrap(),
        HeaderField::new("x-checksum", "second").unwrap(),
    ]);
    let response = ProxyResponse::new(
        ResponseHead::new(
            http::StatusCode::OK,
            http::Version::HTTP_2,
            HeaderBlock::new(),
        ),
        ProxyBody::from_frames([
            Ok(BodyFrame::Data(Bytes::from_static(b"response"))),
            Ok(BodyFrame::Trailers(trailers.clone())),
        ]),
    );
    let response = handler.handle_response(&context, response).await;

    assert_eq!(
        response.headers().get("x-handler"),
        Some(b"neutral".as_slice())
    );
    let collected = response.into_body().collect().await.unwrap();
    assert_eq!(collected.data, Bytes::from_static(b"response"));
    assert_eq!(collected.trailers, Some(trailers));
}
