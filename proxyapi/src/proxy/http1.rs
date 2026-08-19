use std::future::poll_fn;
use std::sync::Arc;

use http::uri::{Authority, PathAndQuery};
use http::{Uri, Version};
use proxelar_proto::http1::{
    BoxIo, ConnectionConfig, Http1Client, Http1ClientResponse, Http1Connector, Http1Pool, PoolKey,
};
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
                .map_err(|error| io(error.to_string()))?
                .into_inner();
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
        };

        super::prepare_upstream_protocol_request(&mut request, preserve_upgrade)?;
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
        }
    }
}

fn malformed(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ErrorKind::MalformedMessage, message)
}

fn io(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ErrorKind::Io, message)
}
