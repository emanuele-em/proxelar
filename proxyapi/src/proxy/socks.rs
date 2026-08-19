use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use http::uri::{Authority, Scheme};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tower_service::Service;

use crate::ca::{CertificateAuthority, Ssl};
use crate::handler::CapturingHandler;
use crate::rewind::Rewind;

use super::forward::{serve_pinned_stream, sniff_stream_protocol, StreamProtocol};
use super::outbound::OutboundConnector;
use super::BoxError;

const SOCKS_VERSION: u8 = 5;
const AUTH_NONE: u8 = 0;
const AUTH_UNACCEPTABLE: u8 = 0xff;
const COMMAND_CONNECT: u8 = 1;
const ADDRESS_IPV4: u8 = 1;
const ADDRESS_DOMAIN: u8 = 3;
const ADDRESS_IPV6: u8 = 4;

pub async fn handle_connection(
    mut stream: TcpStream,
    remote_addr: SocketAddr,
    handler: CapturingHandler,
    ca: Arc<Ssl>,
    mut outbound: OutboundConnector,
    upstream_tls: Arc<rustls::ClientConfig>,
    listen_addr: SocketAddr,
) {
    let authority = match accept_connect(&mut stream).await {
        Ok(authority) => authority,
        Err(error) => {
            tracing::debug!("SOCKS5 handshake failed: {error}");
            return;
        }
    };
    let upstream = match connect_target(&authority, &mut outbound).await {
        Ok(upstream) => upstream,
        Err(error) => {
            let status = reply_status(error.as_ref());
            let _ = send_reply(&mut stream, status, None).await;
            tracing::debug!("SOCKS5 upstream connection failed: {error}");
            return;
        }
    };
    let bound = upstream.local_addr().ok();
    if let Err(error) = send_reply(&mut stream, 0, bound).await {
        tracing::debug!("SOCKS5 success reply failed: {error}");
        return;
    }

    let (protocol, buffered) = match sniff_stream_protocol(&mut stream).await {
        Ok(result) => result,
        Err(error) => {
            tracing::debug!("SOCKS5 protocol detection failed: {error}");
            return;
        }
    };
    let stream = Rewind::new_buffered(stream, buffered);
    match protocol {
        StreamProtocol::Http => {
            if let Err(error) = serve_pinned_stream(
                stream,
                upstream,
                authority.clone(),
                Scheme::HTTP,
                handler,
                ca,
                remote_addr,
                listen_addr,
            )
            .await
            {
                tracing::debug!("SOCKS5 HTTP inspection failed: {error}");
            }
        }
        StreamProtocol::Tls => {
            let server_name = match ServerName::try_from(authority.host().to_owned()) {
                Ok(server_name) => server_name,
                Err(error) => {
                    tracing::warn!("SOCKS5 upstream TLS server name is invalid: {error}");
                    return;
                }
            };
            let upstream = match TlsConnector::from(upstream_tls)
                .connect(server_name, upstream)
                .await
            {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::debug!("SOCKS5 upstream TLS handshake failed: {error}");
                    return;
                }
            };
            let server_config = match ca.gen_server_config(&authority).await {
                Ok(config) => config,
                Err(error) => {
                    tracing::warn!("SOCKS5 certificate generation failed: {error}");
                    return;
                }
            };
            let stream = match TlsAcceptor::from(server_config).accept(stream).await {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::debug!("SOCKS5 TLS interception failed: {error}");
                    return;
                }
            };
            if let Err(error) = serve_pinned_stream(
                stream,
                upstream,
                authority.clone(),
                Scheme::HTTPS,
                handler,
                ca,
                remote_addr,
                listen_addr,
            )
            .await
            {
                tracing::debug!("SOCKS5 HTTPS inspection failed: {error}");
            }
        }
        StreamProtocol::Unknown => {
            let mut client_stream = stream;
            let mut upstream = upstream;
            if let Err(error) = super::raw::tunnel(
                &mut client_stream,
                &mut upstream,
                authority.to_string(),
                handler.event_tx_clone(),
            )
            .await
            {
                tracing::debug!("SOCKS5 TCP tunnel failed: {error}");
            }
        }
    }
}

async fn accept_connect(stream: &mut TcpStream) -> Result<Authority, std::io::Error> {
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != SOCKS_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported SOCKS version",
        ));
    }
    let mut methods = vec![0_u8; usize::from(greeting[1])];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&AUTH_NONE) {
        stream
            .write_all(&[SOCKS_VERSION, AUTH_UNACCEPTABLE])
            .await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "SOCKS client does not support no-auth",
        ));
    }
    stream.write_all(&[SOCKS_VERSION, AUTH_NONE]).await?;

    let mut request = [0_u8; 4];
    stream.read_exact(&mut request).await?;
    if request[0] != SOCKS_VERSION || request[1] != COMMAND_CONNECT || request[2] != 0 {
        send_reply(stream, 7, None).await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "only SOCKS5 CONNECT is supported",
        ));
    }
    let host = match request[3] {
        ADDRESS_IPV4 => {
            let mut octets = [0_u8; 4];
            stream.read_exact(&mut octets).await?;
            IpAddr::V4(Ipv4Addr::from(octets)).to_string()
        }
        ADDRESS_IPV6 => {
            let mut octets = [0_u8; 16];
            stream.read_exact(&mut octets).await?;
            format!("[{}]", Ipv6Addr::from(octets))
        }
        ADDRESS_DOMAIN => {
            let length = stream.read_u8().await?;
            let mut domain = vec![0_u8; usize::from(length)];
            stream.read_exact(&mut domain).await?;
            String::from_utf8(domain)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?
        }
        _ => {
            send_reply(stream, 8, None).await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported SOCKS address type",
            ));
        }
    };
    let port = stream.read_u16().await?;
    let authority = format!("{host}:{port}")
        .parse::<Authority>()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    Ok(authority)
}

async fn connect_target(
    authority: &Authority,
    outbound: &mut OutboundConnector,
) -> Result<TcpStream, BoxError> {
    let destination = format!("http://{authority}/").parse()?;
    poll_fn(|context| outbound.poll_ready(context)).await?;
    Ok(outbound.call(destination).await?.into_inner())
}

fn reply_status(error: &(dyn std::error::Error + 'static)) -> u8 {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(error) = error.downcast_ref::<std::io::Error>() {
            return match error.kind() {
                std::io::ErrorKind::PermissionDenied => 2,
                std::io::ErrorKind::NetworkUnreachable => 3,
                std::io::ErrorKind::HostUnreachable | std::io::ErrorKind::TimedOut => 4,
                std::io::ErrorKind::ConnectionRefused => 5,
                _ => 1,
            };
        }
        current = error.source();
    }
    1
}

async fn send_reply(
    stream: &mut TcpStream,
    status: u8,
    bound: Option<SocketAddr>,
) -> Result<(), std::io::Error> {
    let bound = bound.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    let mut reply = vec![SOCKS_VERSION, status, 0];
    match bound.ip() {
        IpAddr::V4(ip) => {
            reply.push(ADDRESS_IPV4);
            reply.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            reply.push(ADDRESS_IPV6);
            reply.extend_from_slice(&ip.octets());
        }
    }
    reply.extend_from_slice(&bound.port().to_be_bytes());
    stream.write_all(&reply).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn accepts_domain_connect_and_rejects_missing_no_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            accept_connect(&mut stream).await.unwrap()
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut auth = [0_u8; 2];
        client.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, [5, 0]);
        client
            .write_all(&[
                5, 1, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
                0, 80,
            ])
            .await
            .unwrap();
        assert_eq!(server.await.unwrap().as_str(), "example.com:80");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            accept_connect(&mut stream).await.unwrap_err()
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&[5, 1, 2]).await.unwrap();
        client.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, [5, 0xff]);
        assert_eq!(
            server.await.unwrap().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn maps_connection_errors_to_socks_reply_statuses() {
        for (kind, expected) in [
            (std::io::ErrorKind::PermissionDenied, 2),
            (std::io::ErrorKind::NetworkUnreachable, 3),
            (std::io::ErrorKind::HostUnreachable, 4),
            (std::io::ErrorKind::TimedOut, 4),
            (std::io::ErrorKind::ConnectionRefused, 5),
            (std::io::ErrorKind::Other, 1),
        ] {
            let error = std::io::Error::from(kind);
            assert_eq!(reply_status(&error), expected);
        }
    }

    #[tokio::test]
    async fn accepts_ipv4_and_ipv6_and_rejects_invalid_requests() {
        async fn run_request(request: Vec<u8>) -> (Result<Authority, std::io::Error>, Vec<u8>) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                accept_connect(&mut stream).await
            });
            let mut client = TcpStream::connect(address).await.unwrap();
            client.write_all(&request).await.unwrap();
            client.shutdown().await.unwrap();
            let mut reply = Vec::new();
            let _ = client.read_to_end(&mut reply).await;
            (server.await.unwrap(), reply)
        }

        let (authority, _) = run_request(vec![5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0, 80]).await;
        assert_eq!(authority.unwrap().as_str(), "127.0.0.1:80");

        let mut ipv6 = vec![5, 1, 0, 5, 1, 0, ADDRESS_IPV6];
        ipv6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        ipv6.extend_from_slice(&443_u16.to_be_bytes());
        let (authority, _) = run_request(ipv6).await;
        assert_eq!(authority.unwrap().as_str(), "[::1]:443");

        let (error, _) = run_request(vec![4, 0]).await;
        assert_eq!(error.unwrap_err().kind(), std::io::ErrorKind::InvalidData);

        let (error, _) =
            run_request(vec![5, 1, 0, 5, 2, 0, ADDRESS_IPV4, 127, 0, 0, 1, 0, 80]).await;
        assert_eq!(error.unwrap_err().kind(), std::io::ErrorKind::Unsupported);

        let (error, _) = run_request(vec![5, 1, 0, 5, 1, 0, 9]).await;
        assert_eq!(error.unwrap_err().kind(), std::io::ErrorKind::InvalidData);

        let (error, _) = run_request(vec![5, 1, 0, 5, 1, 0, ADDRESS_DOMAIN, 1, 0xff, 0, 80]).await;
        assert_eq!(error.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn sends_ipv4_and_ipv6_replies_and_connects_directly() {
        async fn reply(bound: Option<SocketAddr>) -> Vec<u8> {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                send_reply(&mut stream, 0, bound).await.unwrap();
            });
            let mut client = TcpStream::connect(address).await.unwrap();
            let mut bytes = Vec::new();
            client.read_to_end(&mut bytes).await.unwrap();
            server.await.unwrap();
            bytes
        }

        assert_eq!(reply(None).await, [5, 0, 0, ADDRESS_IPV4, 0, 0, 0, 0, 0, 0]);
        let ipv4 = reply(Some("127.0.0.1:8080".parse().unwrap())).await;
        assert_eq!(ipv4[3], ADDRESS_IPV4);
        assert_eq!(&ipv4[4..8], &[127, 0, 0, 1]);
        let ipv6 = reply(Some("[::1]:8080".parse().unwrap())).await;
        assert_eq!(ipv6[3], ADDRESS_IPV6);
        assert_eq!(ipv6.len(), 22);

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = upstream.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });
        let mut outbound = OutboundConnector::new(None).unwrap();
        let mut connected = connect_target(
            &target.to_string().parse::<Authority>().unwrap(),
            &mut outbound,
        )
        .await
        .unwrap();
        connected.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        connected.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn proxy_mode_tunnels_unknown_tcp_streams() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(&request).await.unwrap();
        });

        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = probe.local_addr().unwrap();
        drop(probe);
        let directory = tempfile::tempdir().unwrap();
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(16);
        let proxy = crate::Proxy::new(crate::ProxyConfig {
            addr: address,
            mode: crate::ProxyMode::Socks5,
            event_tx,
            ca_dir: directory.path().to_owned(),
            upstream_tls: crate::UpstreamTlsConfig::Default,
            intercept: None,
            body_capture_limit: Some(1_024),
            #[cfg(feature = "scripting")]
            script_path: None,
            replay_rx: None,
        });
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let proxy_task = tokio::spawn(proxy.start(async {
            let _ = shutdown_rx.await;
        }));
        let mut client = None;
        for _ in 0..100 {
            match TcpStream::connect(address).await {
                Ok(stream) => {
                    client = Some(stream);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                Err(error) => panic!("failed to connect to SOCKS listener: {error}"),
            }
        }
        let mut client = client.expect("SOCKS listener did not start");
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut auth = [0_u8; 2];
        client.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, [5, 0]);
        let mut request = vec![5, 1, 0, ADDRESS_IPV4];
        let IpAddr::V4(target_ip) = target.ip() else {
            panic!("expected IPv4 target");
        };
        request.extend_from_slice(&target_ip.octets());
        request.extend_from_slice(&target.port().to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0);

        client.write_all(&[0, 1, 2, 3]).await.unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, [0, 1, 2, 3]);
        drop(client);
        upstream_task.await.unwrap();

        let mut saw_connection = false;
        let mut saw_client_data = false;
        for _ in 0..4 {
            let Some(event) =
                tokio::time::timeout(std::time::Duration::from_secs(1), event_rx.recv())
                    .await
                    .unwrap()
            else {
                break;
            };
            match event {
                crate::ProxyEvent::TcpConnected {
                    target: captured, ..
                } => {
                    saw_connection = captured == target.to_string();
                }
                crate::ProxyEvent::TcpData { chunk, .. }
                    if chunk.direction == proxyapi_models::StreamDirection::ClientToServer =>
                {
                    saw_client_data = chunk.payload.as_ref() == [0, 1, 2, 3];
                }
                crate::ProxyEvent::TcpClosed { .. } if saw_connection && saw_client_data => break,
                _ => {}
            }
        }
        assert!(saw_connection);
        assert!(saw_client_data);

        shutdown_tx.send(()).unwrap();
        proxy_task.await.unwrap().unwrap();
    }
}
