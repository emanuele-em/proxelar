use std::time::Duration;

use proxelar_proto::{BoxFuture, HttpService, ProtocolError};
use proxyapi::{
    CapturingHandler, HttpContext, HttpHandler, InterceptConfig, InterceptDecision, ProxyBody,
    ProxyEvent, ProxyRequest, ProxyResponse, RequestOrResponse, ResponseHead,
};
use proxyapi_models::HeaderBlock;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

struct InterceptService(CapturingHandler);

impl HttpService for InterceptService {
    fn call(
        &mut self,
        request: ProxyRequest,
    ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
        Box::pin(async move {
            let context = HttpContext {
                remote_addr: "127.0.0.1:12345".parse().unwrap(),
            };
            match self.0.handle_request(&context, request).await {
                RequestOrResponse::Response(response) => Ok(response),
                RequestOrResponse::Request(_) => Ok(ProxyResponse::new(
                    ResponseHead::new(
                        http::StatusCode::OK,
                        http::Version::HTTP_11,
                        HeaderBlock::new(),
                    ),
                    ProxyBody::empty(),
                )),
            }
        })
    }
}

#[tokio::test(start_paused = true)]
async fn interception_uses_its_own_deadline_and_delivers_the_response() {
    for elapsed in [61, 299, 301] {
        let intercept = InterceptConfig::new();
        intercept.set_enabled(true);
        let (events, mut receiver) = tokio::sync::mpsc::channel(10);
        let handler = CapturingHandler::new(events).with_intercept(intercept.clone());
        let (mut peer, io) = tokio::io::duplex(4096);
        let server = tokio::spawn(proxelar_proto::http1::serve_connection(
            io,
            InterceptService(handler),
            proxelar_proto::http1::ConnectionConfig::default(),
        ));
        peer.write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let id = loop {
            if let ProxyEvent::RequestIntercepted { id, .. } = receiver.recv().await.unwrap() {
                break id;
            }
        };
        tokio::time::advance(Duration::from_secs(elapsed)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            intercept.resolve(id, InterceptDecision::Forward),
            elapsed < 300
        );
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        let expected = if elapsed < 300 {
            "HTTP/1.1 200"
        } else {
            "HTTP/1.1 504"
        };
        assert!(
            response.starts_with(expected.as_bytes()),
            "{}",
            String::from_utf8_lossy(&response)
        );
        server.await.unwrap().unwrap();
    }
}
