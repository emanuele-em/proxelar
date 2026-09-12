use std::future::poll_fn;
use std::sync::Arc;

use base64::Engine as _;
use http::uri::{Authority, PathAndQuery};
use http::{Method, Uri, Version};
use proxelar_proto::http1::{
    BoxIo, ConnectionConfig, Http1Client, Http1ClientResponse, Http1Connector, Http1Pool, PoolKey,
};
use proxelar_proto::http2::{ConnectionConfig as H2ConnectionConfig, H2Client};
use proxelar_proto::{BoxFuture, ErrorKind, ProtocolError, ProxyBody, ProxyRequest, ProxyResponse};
use rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;
use tower_service::Service as _;

use super::outbound::OutboundConnector;

#[derive(Clone)]
pub(super) struct NativeConnector {
    outbound: OutboundConnector,
    tls: Arc<rustls::ClientConfig>,
}

impl NativeConnector {
    pub(super) fn new(outbound: OutboundConnector, tls: Arc<rustls::ClientConfig>) -> Self {
        let mut tls = (*tls).clone();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self {
            outbound,
            tls: Arc::new(tls),
        }
    }
}

impl Http1Connector for NativeConnector {
    fn connect(&self, key: PoolKey) -> BoxFuture<'static, Result<BoxIo, ProtocolError>> {
        let mut outbound = self.outbound.clone();
        let tls = Arc::clone(&self.tls);
        Box::pin(async move {
            let scheme = if key.tls { "https" } else { "http" };
            let destination: Uri = format!("{scheme}://{}/", key.destination)
                .parse()
                .map_err(|error: http::uri::InvalidUri| malformed(error.to_string()))?;
            poll_fn(|context| outbound.poll_ready(context))
                .await
                .map_err(|error| io(error.to_string()))?;
            let stream = outbound
                .call(destination.clone())
                .await
                .map_err(|error| io(error.to_string()))?;
            if !key.tls {
                return Ok(Box::new(stream) as BoxIo);
            }

            let host = destination
                .host()
                .ok_or_else(|| malformed("TLS destination has no host"))?;
            let server_name = ServerName::try_from(host.to_owned())
                .map_err(|error| malformed(error.to_string()))?;
            let stream = TlsConnector::from(tls)
                .connect(server_name, stream)
                .await
                .map_err(|error| io(error.to_string()))?;
            Ok(Box::new(stream) as BoxIo)
        })
    }
}

pub(super) type NativePool = Http1Pool<NativeConnector>;

pub(super) fn new_pool(outbound: OutboundConnector, tls: Arc<rustls::ClientConfig>) -> NativePool {
    Http1Pool::new(
        NativeConnector::new(outbound, tls),
        ConnectionConfig::default(),
    )
}

#[derive(Clone)]
pub(super) enum NativeUpstream {
    Shared {
        pool: Arc<NativePool>,
        route: Option<String>,
    },
    Pinned {
        client: Http1Client,
        authority: Authority,
    },
    Negotiated(Arc<NegotiatedUpstream>),
}

pub(super) struct NegotiatedUpstream {
    outbound: OutboundConnector,
    tls: Arc<rustls::ClientConfig>,
    client: tokio::sync::Mutex<Option<Arc<NegotiatedClient>>>,
}

enum NegotiatedClient {
    Http1 {
        client: Http1Client,
        authority: Authority,
    },
    Http2(H2Client),
}

fn should_evict(client: &NegotiatedClient, error: &ProtocolError) -> bool {
    !matches!(client, NegotiatedClient::Http2(_)) || h2_error_closes_connection(error.kind())
}

fn h2_error_closes_connection(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::Io | ErrorKind::Timeout | ErrorKind::ProtocolViolation
    )
}

pub(super) enum NativeWebSocketResponse {
    Http1(Http1ClientResponse),
    Http2(ProxyResponse),
}

impl NativeUpstream {
    pub(super) fn shared(pool: Arc<NativePool>, route: Option<String>) -> Self {
        Self::Shared { pool, route }
    }

    pub(super) fn pinned<I>(io: I, authority: Authority) -> Self
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        Self::Pinned {
            client: Http1Client::new(io, ConnectionConfig::default()),
            authority,
        }
    }

    pub(super) fn negotiated(
        outbound: OutboundConnector,
        mut tls: rustls::ClientConfig,
        client_alpn_offers: Vec<Vec<u8>>,
    ) -> Self {
        tls.alpn_protocols = client_alpn_offers;
        Self::Negotiated(Arc::new(NegotiatedUpstream {
            outbound,
            tls: Arc::new(tls),
            client: tokio::sync::Mutex::new(None),
        }))
    }

    pub(super) async fn send(
        &self,
        mut request: ProxyRequest,
        preserve_upgrade: bool,
    ) -> Result<Http1ClientResponse, ProtocolError> {
        let scheme = request.head.uri.scheme_str().unwrap_or("http").to_owned();
        let authority = match self {
            Self::Shared { .. } => request
                .head
                .uri
                .authority()
                .cloned()
                .ok_or_else(|| malformed("upstream request has no authority"))?,
            Self::Pinned { authority, .. } => authority.clone(),
            Self::Negotiated(_) => request
                .head
                .uri
                .authority()
                .cloned()
                .ok_or_else(|| malformed("upstream request has no authority"))?,
        };

        if let Self::Negotiated(upstream) = self {
            return upstream.send(request, preserve_upgrade, authority).await;
        }

        prepare_http1_request(&mut request, &authority, preserve_upgrade)?;

        match self {
            Self::Shared { pool, route } => {
                let key = PoolKey {
                    destination: authority.to_string(),
                    tls: scheme.eq_ignore_ascii_case("https"),
                    outbound_route: route.clone(),
                };
                pool.send_with_upgrade(key, request).await
            }
            Self::Pinned { client, .. } => client.send_request_with_upgrade(request).await,
            Self::Negotiated(_) => unreachable!("negotiated upstream returned before H1 dispatch"),
        }
    }

    pub(super) async fn send_websocket(
        &self,
        mut request: ProxyRequest,
    ) -> Result<NativeWebSocketResponse, ProtocolError> {
        let authority = request
            .head
            .uri
            .authority()
            .cloned()
            .ok_or_else(|| malformed("upstream request has no authority"))?;
        if let Self::Negotiated(upstream) = self {
            return upstream.send_websocket(request, authority).await;
        }

        prepare_http1_websocket_upgrade(&mut request)?;
        self.send(request, true)
            .await
            .map(NativeWebSocketResponse::Http1)
    }
}

impl NegotiatedUpstream {
    async fn send(
        &self,
        request: ProxyRequest,
        preserve_upgrade: bool,
        authority: Authority,
    ) -> Result<Http1ClientResponse, ProtocolError> {
        let client = {
            let mut state = self.client.lock().await;
            if let Some(client) = state.as_ref() {
                client.clone()
            } else {
                let client = Arc::new(self.connect(authority.clone()).await?);
                *state = Some(client.clone());
                client
            }
        };

        let result = match client.as_ref() {
            NegotiatedClient::Http1 { client, authority } => {
                let mut request = request;
                prepare_http1_request(&mut request, authority, preserve_upgrade)?;
                client.send_request_with_upgrade(request).await
            }
            NegotiatedClient::Http2(client) => {
                if preserve_upgrade {
                    return Err(ProtocolError::new(
                        ErrorKind::Unsupported,
                        "HTTP/1 Upgrade cannot be forwarded over a negotiated HTTP/2 upstream",
                    ));
                }
                let mut request = request;
                super::prepare_upstream_protocol_request(&mut request, false)?;
                client
                    .send_request(request)
                    .await
                    .map(|response| Http1ClientResponse {
                        response,
                        upgrade: None,
                    })
            }
        };
        if result
            .as_ref()
            .is_err_and(|error| should_evict(&client, error))
        {
            self.remove_if_current(&client).await;
        }
        result
    }

    async fn remove_if_current(&self, failed: &Arc<NegotiatedClient>) {
        let mut state = self.client.lock().await;
        clear_if_current(&mut state, failed);
    }

    async fn connect(&self, authority: Authority) -> Result<NegotiatedClient, ProtocolError> {
        let destination: Uri = format!("https://{authority}/")
            .parse()
            .map_err(|error: http::uri::InvalidUri| malformed(error.to_string()))?;
        let mut outbound = self.outbound.clone();
        poll_fn(|context| outbound.poll_ready(context))
            .await
            .map_err(|error| io(error.to_string()))?;
        let stream = outbound
            .call(destination)
            .await
            .map_err(|error| io(error.to_string()))?;
        let server_name = ServerName::try_from(authority.host().to_owned())
            .map_err(|error| malformed(error.to_string()))?;
        let stream = TlsConnector::from(Arc::clone(&self.tls))
            .connect(server_name, stream)
            .await
            .map_err(|error| io(error.to_string()))?;
        match stream.get_ref().1.alpn_protocol() {
            Some(b"h2") => Ok(NegotiatedClient::Http2(
                H2Client::handshake(stream, H2ConnectionConfig::default()).await?,
            )),
            Some(b"http/1.1") | None => Ok(NegotiatedClient::Http1 {
                client: Http1Client::new(stream, ConnectionConfig::default()),
                authority,
            }),
            Some(protocol) => Err(ProtocolError::new(
                ErrorKind::Unsupported,
                format!(
                    "upstream selected unsupported ALPN {}",
                    String::from_utf8_lossy(protocol)
                ),
            )),
        }
    }

    async fn send_websocket(
        &self,
        mut request: ProxyRequest,
        authority: Authority,
    ) -> Result<NativeWebSocketResponse, ProtocolError> {
        let client = {
            let mut state = self.client.lock().await;
            if let Some(client) = state.as_ref() {
                client.clone()
            } else {
                let client = Arc::new(self.connect(authority.clone()).await?);
                *state = Some(client.clone());
                client
            }
        };

        let result = match client.as_ref() {
            NegotiatedClient::Http1 { client, authority } => {
                prepare_http1_websocket_upgrade(&mut request)?;
                prepare_http1_request(&mut request, authority, true)?;
                client
                    .send_request_with_upgrade(request)
                    .await
                    .map(NativeWebSocketResponse::Http1)
            }
            NegotiatedClient::Http2(client) => {
                super::prepare_upstream_protocol_request(&mut request, true)?;
                match client.ensure_extended_connect().await {
                    Ok(()) => client
                        .send_request(request)
                        .await
                        .map(NativeWebSocketResponse::Http2),
                    Err(error) => Err(error),
                }
            }
        };
        if result
            .as_ref()
            .is_err_and(|error| should_evict(&client, error))
        {
            self.remove_if_current(&client).await;
        }
        result
    }
}

fn prepare_http1_websocket_upgrade(request: &mut ProxyRequest) -> Result<(), ProtocolError> {
    request.body = ProxyBody::empty();
    request.head.method = Method::GET;
    request.head.version = Version::HTTP_11;
    for name in [
        b":protocol".as_slice(),
        b"connection".as_slice(),
        b"upgrade".as_slice(),
        b"sec-websocket-key".as_slice(),
        b"sec-websocket-accept".as_slice(),
        b"sec-websocket-extensions".as_slice(),
    ] {
        request.head.headers.remove(name);
    }
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce)
        .map_err(|error| ProtocolError::new(ErrorKind::Io, error.to_string()))?;
    request
        .head
        .headers
        .set("connection", "Upgrade")
        .map_err(|error| malformed(error.to_string()))?;
    request
        .head
        .headers
        .set("upgrade", "websocket")
        .map_err(|error| malformed(error.to_string()))?;
    request
        .head
        .headers
        .set(
            "sec-websocket-key",
            base64::engine::general_purpose::STANDARD.encode(nonce),
        )
        .map_err(|error| malformed(error.to_string()))?;
    Ok(())
}

fn prepare_http1_request(
    request: &mut ProxyRequest,
    authority: &Authority,
    preserve_upgrade: bool,
) -> Result<(), ProtocolError> {
    super::prepare_upstream_protocol_request(request, preserve_upgrade)?;
    request
        .head
        .headers
        .set("host", authority.as_str())
        .map_err(|error| malformed(error.to_string()))?;
    let path = request
        .head
        .uri
        .path_and_query()
        .map_or("/", PathAndQuery::as_str)
        .parse::<PathAndQuery>()
        .map_err(|error| malformed(error.to_string()))?;
    request.head.uri = Uri::builder()
        .path_and_query(path)
        .build()
        .map_err(|error| malformed(error.to_string()))?;
    request.head.version = Version::HTTP_11;
    Ok(())
}

fn malformed(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ErrorKind::MalformedMessage, message)
}

fn io(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ErrorKind::Io, message)
}

fn clear_if_current<T>(cached: &mut Option<Arc<T>>, failed: &Arc<T>) {
    if cached
        .as_ref()
        .is_some_and(|current| Arc::ptr_eq(current, failed))
    {
        *cached = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h2_stream_errors_do_not_evict_the_connection() {
        assert!(!h2_error_closes_connection(ErrorKind::Reset));
        assert!(!h2_error_closes_connection(ErrorKind::MalformedMessage));
        assert!(!h2_error_closes_connection(ErrorKind::Unsupported));
        assert!(h2_error_closes_connection(ErrorKind::Io));
        assert!(h2_error_closes_connection(ErrorKind::Timeout));
        assert!(h2_error_closes_connection(ErrorKind::ProtocolViolation));
    }

    #[test]
    fn stale_failure_does_not_remove_a_newer_negotiated_connection() {
        let current = Arc::new(());
        let stale = Arc::new(());
        let mut cached = Some(Arc::clone(&current));

        clear_if_current(&mut cached, &stale);
        assert!(cached
            .as_ref()
            .is_some_and(|cached| Arc::ptr_eq(cached, &current)));

        clear_if_current(&mut cached, &current);
        assert!(cached.is_none());
    }
}

#[cfg(test)]
#[path = "tests/http1.rs"]
mod protocol_tests;
