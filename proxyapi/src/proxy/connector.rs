//! Shared rama transport connector for HTTP and raw upstream traffic.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};

use rama::dns::client::DnsConnector;
use rama::error::{BoxError, BoxErrorExt as _};
use rama::extensions::{Extensions, ExtensionsRef};
use rama::http::client::proxy::layer::HttpProxyConnectorLayer;
use rama::http::client::{MaybeProxiedConnection, ProxyConnector};
use rama::net::address::{ProxyAddress, SocketAddress};
use rama::net::client::{
    ConnectRequest, ConnectionError, ConnectionErrorKind, ConnectorService, ConnectorTarget,
    EstablishedClientConnection, ProxyRoute,
};
use rama::net::stream::{Socket, SocketInfo};
use rama::net::Protocol;
use rama::proxy::socks5::Socks5ProxyConnectorLayer;
use rama::service::BoxService;
use rama::tcp::client::service::TcpConnector;
use rama::tcp::TcpStream;
use rama::Service;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;

pub(crate) type RawConnection = MaybeProxiedConnection<TcpStream>;
pub(crate) type RawConnector = BoxService<
    ConnectRequest,
    EstablishedClientConnection<RawConnection, ConnectRequest>,
    ConnectionError,
>;
pub(crate) type SocketConnector = BoxService<
    ConnectRequest,
    EstablishedClientConnection<SocketIo<RawConnection>, ConnectRequest>,
    ConnectionError,
>;

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

/// Make an already-established egress usable as the transport for exactly one
/// HTTP connection attempt. Clones share the same slot, which lets the HTTP
/// path and raw fallback race only by protocol selection, never by dialing.
pub(crate) fn pinned(connection: RawConnection) -> RawConnector {
    PinnedConnector {
        connection: Arc::new(Mutex::new(Some(connection))),
    }
    .boxed()
}

pub(crate) fn socket_capable(connector: RawConnector) -> SocketConnector {
    SocketConnectorAdapter { connector }.boxed()
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
        conn.extensions()
            .insert(ConnectorTarget(input.authority.clone()));
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

#[derive(Clone)]
struct SocketConnectorAdapter {
    connector: RawConnector,
}

impl Service<ConnectRequest> for SocketConnectorAdapter {
    type Output = EstablishedClientConnection<SocketIo<RawConnection>, ConnectRequest>;
    type Error = ConnectionError;

    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, conn } = self.connector.connect(input).await?;
        Ok(EstablishedClientConnection {
            input,
            conn: SocketIo::new(conn),
        })
    }
}

/// `MaybeProxiedConnection` already delegates I/O and extensions, but rama's
/// combined proxy connection does not yet delegate `Socket`. The eager SOCKS
/// server needs that trait only to populate its success reply, so recover the
/// addresses from the `SocketInfo` installed by rama's TCP connector.
pub(crate) struct SocketIo<T> {
    inner: StdMutex<T>,
    extensions: Extensions,
}

impl<T: ExtensionsRef> SocketIo<T> {
    fn new(inner: T) -> Self {
        Self {
            extensions: inner.extensions().clone(),
            inner: StdMutex::new(inner),
        }
    }

    pub(crate) fn into_inner(self) -> Result<T, BoxError> {
        self.inner
            .into_inner()
            .map_err(|_| BoxError::from_static_str("SOCKS egress socket mutex poisoned"))
    }
}

impl<T> ExtensionsRef for SocketIo<T> {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<T: Send + 'static> Socket for SocketIo<T> {
    fn local_addr(&self) -> io::Result<SocketAddress> {
        self.extensions()
            .get_ref::<SocketInfo>()
            .and_then(SocketInfo::local_addr)
            .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "local address missing"))
    }

    fn peer_addr(&self) -> io::Result<SocketAddress> {
        self.extensions()
            .get_ref::<SocketInfo>()
            .map(SocketInfo::peer_addr)
            .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "peer address missing"))
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for SocketIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut inner = match self.get_mut().inner.lock() {
            Ok(inner) => inner,
            Err(_) => return Poll::Ready(Err(io::Error::other("SOCKS egress mutex poisoned"))),
        };
        Pin::new(&mut *inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for SocketIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut inner = match self.get_mut().inner.lock() {
            Ok(inner) => inner,
            Err(_) => return Poll::Ready(Err(io::Error::other("SOCKS egress mutex poisoned"))),
        };
        Pin::new(&mut *inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = match self.get_mut().inner.lock() {
            Ok(inner) => inner,
            Err(_) => return Poll::Ready(Err(io::Error::other("SOCKS egress mutex poisoned"))),
        };
        Pin::new(&mut *inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = match self.get_mut().inner.lock() {
            Ok(inner) => inner,
            Err(_) => return Poll::Ready(Err(io::Error::other("SOCKS egress mutex poisoned"))),
        };
        Pin::new(&mut *inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner
            .lock()
            .is_ok_and(|inner| inner.is_write_vectored())
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let mut inner = match self.get_mut().inner.lock() {
            Ok(inner) => inner,
            Err(_) => return Poll::Ready(Err(io::Error::other("SOCKS egress mutex poisoned"))),
        };
        Pin::new(&mut *inner).poll_write_vectored(cx, bufs)
    }
}
