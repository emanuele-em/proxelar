//! Shared rama transport connector for HTTP and raw upstream traffic.

use std::{sync::Arc, time::Duration};

use rama::dns::client::DnsConnector;
use rama::error::{BoxError, BoxErrorExt as _};
use rama::http::client::proxy::layer::HttpProxyConnectorLayer;
use rama::http::client::{MaybeProxiedConnection, ProxyConnector};
use rama::layer::TimeoutLayer;
use rama::net::address::ProxyAddress;
use rama::net::client::{
    ConnectRequest, ConnectionError, ConnectionErrorKind, ConnectorService,
    EstablishedClientConnection, ProxyRoute,
};
use rama::net::Protocol;
use rama::proxy::socks5::Socks5ProxyConnectorLayer;
use rama::service::BoxService;
use rama::tcp::client::service::TcpConnector;
use rama::tcp::TcpStream;
use rama::{Layer, Service};
use tokio::sync::Mutex;

pub(crate) type RawConnection = MaybeProxiedConnection<TcpStream>;
pub(crate) type RawConnector = BoxService<
    ConnectRequest,
    EstablishedClientConnection<RawConnection, ConnectRequest>,
    ConnectionError,
>;
pub(crate) type TimedRawConnector = BoxService<
    ConnectRequest,
    EstablishedClientConnection<RawConnection, ConnectRequest>,
    BoxError,
>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Build the DNS + direct/HTTP-CONNECT/SOCKS5 transport used by all egress
/// paths. Keeping the selected route inside this connector prevents raw
/// tunnels from accidentally bypassing a mandatory upstream proxy.
pub(crate) fn routed(proxy: Option<ProxyAddress>) -> RawConnector {
    let transport = DnsConnector::new(TcpConnector::default());
    let connector = ProxyConnector::optional(
        transport,
        Socks5ProxyConnectorLayer::required(),
        HttpProxyConnectorLayer::required().with_tls_proxy_support(false),
    );
    RoutedConnector { connector, proxy }.boxed()
}

/// Apply the same bounded connect policy rama's default eager SOCKS connector
/// uses. This wrapper is shared by SOCKS and HTTP CONNECT so both report
/// unreachable targets before acknowledging the tunnel.
pub(crate) fn with_timeout(connector: RawConnector) -> TimedRawConnector {
    TimeoutLayer::new(CONNECT_TIMEOUT)
        .into_layer(connector)
        .boxed()
}

/// Make an already-established egress usable as the transport for exactly one
/// HTTP connection attempt. Clones share the same slot, which lets the HTTP
/// path and raw fallback race only by protocol selection, never by dialing.
pub(crate) fn pinned(connection: RawConnection) -> RawConnector {
    PinnedConnector {
        connection: Arc::new(Mutex::new(Some(connection))),
    }
    .boxed()
}

#[derive(Clone)]
struct RoutedConnector {
    connector: ProxyConnector<DnsConnector<TcpConnector>>,
    proxy: Option<ProxyAddress>,
}

impl Service<ConnectRequest> for RoutedConnector {
    type Output = EstablishedClientConnection<RawConnection, ConnectRequest>;
    type Error = ConnectionError;

    async fn serve(&self, mut input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        let application_protocol = input.application_protocol.clone();
        if let Some(proxy) = &self.proxy {
            // UpstreamProxyConfig promises an HTTP CONNECT proxy, while rama's
            // HTTP connector defaults plain HTTP to forward-proxy mode. Force
            // CONNECT for every HTTP-proxy transport, including raw TCP, then
            // restore the actual application protocol for the outer TLS/HTTP
            // connector layers.
            if proxy
                .protocol
                .as_ref()
                .map(Protocol::is_http)
                .unwrap_or(true)
            {
                input.application_protocol = Some(Protocol::HTTPS);
            }
            input.extensions.insert(ProxyRoute::Proxy(proxy.clone()));
        }
        let EstablishedClientConnection { mut input, conn } = self.connector.connect(input).await?;
        input.application_protocol = application_protocol;
        Ok(EstablishedClientConnection { input, conn })
    }
}

#[derive(Clone)]
struct PinnedConnector {
    connection: Arc<Mutex<Option<RawConnection>>>,
}

impl Service<ConnectRequest> for PinnedConnector {
    type Output = EstablishedClientConnection<RawConnection, ConnectRequest>;
    type Error = ConnectionError;

    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        let connection = self.connection.lock().await.take().ok_or_else(|| {
            ConnectionError::local(
                BoxError::from_static_str("pinned upstream connection is no longer available"),
                ConnectionErrorKind::Unavailable,
            )
        })?;
        Ok(EstablishedClientConnection {
            input,
            conn: connection,
        })
    }
}
