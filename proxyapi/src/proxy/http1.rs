use std::future::poll_fn;
use std::sync::Arc;

use http::uri::{Authority, PathAndQuery};
use http::{Uri, Version};
use proxelar_proto::http1::{
    BoxIo, ConnectionConfig, Http1Client, Http1ClientResponse, Http1Connector, Http1Pool, PoolKey,
};
use proxelar_proto::http2::{ConnectionConfig as H2ConnectionConfig, H2Client};
use proxelar_proto::{BoxFuture, ErrorKind, ProtocolError, ProxyRequest};
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
    client: tokio::sync::Mutex<Option<NegotiatedClient>>,
}

#[derive(Clone)]
enum NegotiatedClient {
    Http1 {
        client: Http1Client,
        authority: Authority,
    },
    Http2(H2Client),
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
                let client = self.connect(authority.clone()).await?;
                *state = Some(client.clone());
                client
            }
        };

        let result = match client {
            NegotiatedClient::Http1 { client, authority } => {
                let mut request = request;
                prepare_http1_request(&mut request, &authority, preserve_upgrade)?;
                client.send_request_with_upgrade(request).await
            }
            NegotiatedClient::Http2(client) => {
                if preserve_upgrade {
                    return Err(ProtocolError::new(
                        ErrorKind::Unsupported,
                        "HTTP/1 Upgrade cannot be forwarded over a negotiated HTTP/2 upstream",
                    ));
                }
                let response = client.send_request(request).await?;
                Ok(Http1ClientResponse {
                    response,
                    upgrade: None,
                })
            }
        };
        if result.is_err() {
            *self.client.lock().await = None;
        }
        result
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
