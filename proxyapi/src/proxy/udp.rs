use rama::telemetry::tracing;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use proxyapi_models::CapturedUdpExchange;
use rama::bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::event::{next_id, ProxyEvent};
use crate::handler::now_millis;

const MAX_DATAGRAM_SIZE: usize = 65_535;
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn serve(
    address: SocketAddr,
    target: SocketAddr,
    event_tx: mpsc::Sender<ProxyEvent>,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    let socket = Arc::new(UdpSocket::bind(address).await?);
    tracing::info!("Raw UDP proxy listening on {address}, target {target}");
    tokio::pin!(shutdown);
    let mut buffer = vec![0_u8; MAX_DATAGRAM_SIZE];
    loop {
        tokio::select! {
            received = socket.recv_from(&mut buffer) => {
                let (length, client) = received?;
                let payload = buffer[..length].to_vec();
                let socket = Arc::clone(&socket);
                let event_tx = event_tx.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_datagram(socket, client, target, payload, event_tx).await {
                        tracing::debug!("Raw UDP exchange failed: {error}");
                    }
                });
            }
            () = &mut shutdown => return Ok(()),
        }
    }
}

async fn handle_datagram(
    listener: Arc<UdpSocket>,
    client: SocketAddr,
    target: SocketAddr,
    request: Vec<u8>,
    event_tx: mpsc::Sender<ProxyEvent>,
) -> std::io::Result<()> {
    let response = exchange(client, target, request, event_tx).await?;
    listener.send_to(&response, client).await?;
    Ok(())
}

pub(crate) async fn exchange(
    client: SocketAddr,
    target: SocketAddr,
    request: Vec<u8>,
    event_tx: mpsc::Sender<ProxyEvent>,
) -> std::io::Result<Vec<u8>> {
    let id = next_id();
    let time = now_millis();
    let bind_address = if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let upstream = UdpSocket::bind(bind_address).await?;
    upstream.connect(target).await?;
    upstream.send(&request).await?;

    let mut response = vec![0_u8; MAX_DATAGRAM_SIZE];
    let response_result =
        tokio::time::timeout(RESPONSE_TIMEOUT, upstream.recv(&mut response)).await;
    let (response, response_received, result) = match response_result {
        Ok(Ok(length)) => {
            response.truncate(length);
            (response, true, Ok(()))
        }
        Ok(Err(error)) => (Vec::new(), false, Err(error)),
        Err(_) => (
            Vec::new(),
            false,
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "raw UDP upstream timeout",
            )),
        ),
    };
    let _ = event_tx.try_send(ProxyEvent::UdpExchange {
        exchange: Box::new(CapturedUdpExchange {
            id,
            target: target.to_string(),
            client: client.to_string(),
            time,
            request: Bytes::from(request),
            response: Bytes::copy_from_slice(&response),
            response_received,
            request_truncated: false,
            response_truncated: false,
        }),
    });
    result.map(|()| response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn forwards_and_captures_udp_datagrams() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0_u8; 32];
            let (length, peer) = upstream.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], b"request");
            upstream.send_to(b"response", peer).await.unwrap();
        });

        let listener = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (event_tx, mut event_rx) = mpsc::channel(4);
        handle_datagram(
            Arc::clone(&listener),
            client.local_addr().unwrap(),
            upstream_address,
            b"request".to_vec(),
            event_tx,
        )
        .await
        .unwrap();

        let mut response = [0_u8; 32];
        let (length, _) = client.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..length], b"response");
        let ProxyEvent::UdpExchange { exchange } = event_rx.recv().await.unwrap() else {
            panic!("expected UDP exchange event");
        };
        assert_eq!(exchange.request.as_ref(), b"request");
        assert_eq!(exchange.response.as_ref(), b"response");
    }
}
