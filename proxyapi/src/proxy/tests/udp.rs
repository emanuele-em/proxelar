use super::*;

#[tokio::test]
async fn datagram_handler_returns_the_response_to_the_original_client() {
    let listener = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = upstream.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let mut bytes = [0; 32];
        let (length, peer) = upstream.recv_from(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..length], b"request");
        upstream.send_to(b"response", peer).await.unwrap();
    });
    let (tx, mut events) = mpsc::channel(1);
    handle_datagram(
        listener.clone(),
        client.local_addr().unwrap(),
        target,
        b"request".to_vec(),
        tx,
    )
    .await
    .unwrap();
    let mut bytes = [0; 32];
    let (length, sender) =
        tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(&bytes[..length], b"response");
    assert_eq!(sender, listener.local_addr().unwrap());
    let ProxyEvent::UdpExchange { exchange } = events.recv().await.unwrap() else {
        panic!("expected UDP capture");
    };
    assert!(exchange.response_received);
    assert_eq!(exchange.response, b"response".as_slice());
    echo.await.unwrap();
}

#[tokio::test]
async fn silent_udp_upstream_records_an_unanswered_exchange() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (tx, mut events) = mpsc::channel(1);
    let error = exchange(
        "127.0.0.1:12345".parse().unwrap(),
        upstream.local_addr().unwrap(),
        b"request".to_vec(),
        tx,
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    let ProxyEvent::UdpExchange { exchange } = events.recv().await.unwrap() else {
        panic!("expected UDP capture");
    };
    assert!(!exchange.response_received);
    assert_eq!(exchange.request, b"request".as_slice());
    assert!(exchange.response.is_empty());
}
