use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};

use bytes::Bytes;
use http::Uri;
use proxelar_proto::http1::{
    serve_connection_with_upgrades, ConnectionConfig, ServerConnection, UpgradeReceiver,
};
use proxelar_proto::{BoxFuture, HttpService, ProtocolError, ProxyRequest, ProxyResponse};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;
use tokio_rustls::TlsAcceptor;

use crate::ca::{CertificateAuthority, Ssl};
use crate::handler::CapturingHandler;
use crate::rewind::Rewind;
use crate::{HttpContext, HttpHandler, RequestOrResponse};

use super::{
    forward::{
        is_h2_preface, is_protocol_websocket_upgrade, pump_native_websocket, sniff_stream_protocol,
    },
    http1::{NativePool, NativeUpstream},
    is_benign_shutdown_error,
};

pub(super) struct ReverseConnectionConfig {
    target: Uri,
    ca: Arc<Ssl>,
    native_pool: Arc<NativePool>,
    route: Option<String>,
    outbound: super::outbound::OutboundConnector,
    upstream_tls: Arc<rustls::ClientConfig>,
}

impl ReverseConnectionConfig {
    pub(super) fn new(
        target: Uri,
        ca: Arc<Ssl>,
        native_pool: Arc<NativePool>,
        route: Option<String>,
        outbound: super::outbound::OutboundConnector,
        upstream_tls: Arc<rustls::ClientConfig>,
    ) -> Self {
        Self {
            target,
            ca,
            native_pool,
            route,
            outbound,
            upstream_tls,
        }
    }
}

pub(super) async fn handle_connection(
    mut stream: TcpStream,
    remote_addr: SocketAddr,
    handler: CapturingHandler,
    config: ReverseConnectionConfig,
) {
    let ReverseConnectionConfig {
        target,
        ca,
        native_pool,
        route,
        outbound,
        upstream_tls,
    } = config;
    if target.scheme_str() == Some("https") {
        let Some(authority) = target.authority() else {
            tracing::debug!("Reverse HTTPS target has no authority");
            return;
        };
        let server_config = match ca.gen_server_config(authority).await {
            Ok(config) => config,
            Err(error) => {
                tracing::debug!("Reverse HTTPS certificate error: {error}");
                return;
            }
        };
        let offered_alpn = Arc::new(StdMutex::new(Vec::new()));
        let mut server_config = (*server_config).clone();
        server_config.cert_resolver = Arc::new(AlpnCaptureResolver {
            inner: Arc::clone(&server_config.cert_resolver),
            offered: Arc::clone(&offered_alpn),
        });
        let stream = match TlsAcceptor::from(Arc::new(server_config))
            .accept(stream)
            .await
        {
            Ok(stream) => stream,
            Err(error) => {
                tracing::debug!("Reverse HTTPS handshake error: {error}");
                return;
            }
        };
        let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
        let client_alpn_offers = offered_alpn
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        let upstream =
            NativeUpstream::negotiated(outbound, (*upstream_tls).clone(), client_alpn_offers);
        serve_tcp_stream(stream, h2, remote_addr, handler, target, upstream).await;
        return;
    }

    let (_, buffered) = match sniff_stream_protocol(&mut stream).await {
        Ok(detected) => detected,
        Err(error) => {
            tracing::debug!("Reverse proxy protocol detection failed: {error}");
            return;
        }
    };
    let h2 = is_h2_preface(&buffered);
    let stream = Rewind::new_buffered(stream, buffered);
    let upstream = NativeUpstream::shared(native_pool, route);
    serve_tcp_stream(stream, h2, remote_addr, handler, target, upstream).await;
}

#[derive(Debug)]
struct AlpnCaptureResolver {
    inner: Arc<dyn rustls::server::ResolvesServerCert>,
    offered: Arc<StdMutex<Vec<Vec<u8>>>>,
}

impl rustls::server::ResolvesServerCert for AlpnCaptureResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let protocols = client_hello
            .alpn()
            .into_iter()
            .flatten()
            .map(<[u8]>::to_vec)
            .collect();
        *self
            .offered
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = protocols;
        self.inner.resolve(client_hello)
    }
}

async fn serve_tcp_stream<I>(
    stream: I,
    h2: bool,
    remote_addr: SocketAddr,
    handler: CapturingHandler,
    target: Uri,
    upstream: NativeUpstream,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if !h2 {
        let upgrade = Arc::new(AsyncMutex::new(None));
        let service = ReverseHttp1Service {
            remote_addr,
            handler,
            target,
            upstream: upstream.clone(),
            upgrade: Arc::clone(&upgrade),
        };
        match serve_connection_with_upgrades(stream, service, ConnectionConfig::default()).await {
            Ok(ServerConnection::Upgraded(client)) => {
                if let Some(ReverseUpgrade {
                    upstream,
                    handler,
                    conn_id,
                }) = upgrade.lock().await.take()
                {
                    match upstream.wait().await {
                        Ok(server) => pump_native_websocket(conn_id, client, server, handler).await,
                        Err(error) => {
                            tracing::debug!("Reverse WebSocket upgrade failed: {error}");
                        }
                    }
                }
            }
            Ok(ServerConnection::Closed) => {}
            Err(error) => tracing::debug!("Reverse HTTP/1 connection error: {error}"),
        }
        return;
    }

    if let Err(error) =
        super::http2::serve_reverse(stream, remote_addr, handler, target, upstream).await
    {
        if !is_benign_shutdown_error(error.as_ref()) {
            tracing::debug!("Reverse HTTP/2 connection error: {error}");
        }
    }
}

#[cfg(feature = "http3")]
pub(super) struct ReverseH3Server {
    connections: tokio_quiche::QuicConnectionStream<tokio_quiche::metrics::DefaultMetrics>,
    target: Uri,
    handler: CapturingHandler,
    upstream: super::http3::ReverseH3Upstream,
    #[cfg(test)]
    local_addr: SocketAddr,
    _tls_files: tempfile::TempDir,
}

#[cfg(feature = "http3")]
impl ReverseH3Server {
    pub(super) async fn bind(
        address: SocketAddr,
        target: Uri,
        handler: CapturingHandler,
        ca: Arc<Ssl>,
        upstream_tls: &super::UpstreamTlsConfig,
    ) -> Result<Self, crate::Error> {
        use tokio::net::UdpSocket;
        use tokio_quiche::metrics::DefaultMetrics;
        use tokio_quiche::settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths};
        use tokio_quiche::{listen, ConnectionParams};

        let authority = target.authority().ok_or_else(|| {
            crate::Error::Other("reverse HTTP/3 target has no authority".to_owned())
        })?;
        let certificate = ca.gen_h3_certificate(authority).await?;
        let tls_files = tempfile::tempdir()?;
        let cert_path = tls_files.path().join("reverse-h3-cert.pem");
        let key_path = tls_files.path().join("reverse-h3-key.pem");
        std::fs::write(&cert_path, &certificate.certificate_pem)?;
        std::fs::write(&key_path, &certificate.private_key_pem)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        }

        let cert_path_str = cert_path.to_str().ok_or_else(|| {
            crate::Error::Other("HTTP/3 certificate path is not UTF-8".to_owned())
        })?;
        let key_path_str = key_path
            .to_str()
            .ok_or_else(|| crate::Error::Other("HTTP/3 key path is not UTF-8".to_owned()))?;
        let socket = UdpSocket::bind(address).await?;
        let local_addr = socket.local_addr()?;
        let mut quic_settings = QuicSettings::default();
        quic_settings.alpn = vec![b"h3".to_vec()];
        quic_settings.enable_dgram = false;
        quic_settings.enable_early_data = false;
        let params = ConnectionParams::new_server(
            quic_settings,
            TlsCertificatePaths {
                cert: cert_path_str,
                private_key: key_path_str,
                kind: CertificateKind::X509,
            },
            Hooks::default(),
        );
        let connections = listen([socket], params, DefaultMetrics)?
            .pop()
            .ok_or_else(|| crate::Error::Other("HTTP/3 listener was not created".to_owned()))?;
        let verifier = super::tls::h3_server_verifier(upstream_tls)?;
        let wire_target = h3_wire_target(&target)?;
        let upstream = super::http3::ReverseH3Upstream::new(
            wire_target,
            verifier,
            cert_path.clone(),
            key_path.clone(),
        );
        tracing::info!("Reverse HTTP/3 proxy listening on {local_addr}");

        Ok(Self {
            connections,
            target,
            handler,
            upstream,
            #[cfg(test)]
            local_addr,
            _tls_files: tls_files,
        })
    }

    #[cfg(test)]
    pub(super) const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub(super) async fn serve(mut self) -> Result<(), crate::Error> {
        use futures_util::StreamExt as _;
        use tokio_quiche::ServerH3Driver;

        while let Some(result) = self.connections.next().await {
            let initial = match result {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::debug!("Rejected HTTP/3 initial packet: {error}");
                    continue;
                }
            };
            let remote_addr = initial.peer_addr();
            let (driver, controller) = ServerH3Driver::new(super::http3::default_http3_settings());
            let connection = initial.start(driver);
            let service = ReverseH3Service {
                remote_addr,
                handler: self.handler.clone(),
                target: self.target.clone(),
                upstream: self.upstream.clone(),
            };
            tokio::spawn(async move {
                if let Err(error) =
                    super::http3::serve_connection(connection, controller, service).await
                {
                    tracing::debug!("Reverse HTTP/3 connection error: {error}");
                }
            });
        }
        Ok(())
    }
}

#[cfg(feature = "http3")]
#[derive(Clone)]
struct ReverseH3Service {
    remote_addr: SocketAddr,
    handler: CapturingHandler,
    target: Uri,
    upstream: super::http3::ReverseH3Upstream,
}

#[cfg(feature = "http3")]
impl HttpService for ReverseH3Service {
    fn call(
        &mut self,
        request: ProxyRequest,
    ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
        let mut handler = self.handler.clone();
        let target = self.target.clone();
        let upstream = self.upstream.clone();
        let remote_addr = self.remote_addr;
        Box::pin(async move {
            let context = HttpContext { remote_addr };
            if super::http3::is_extended_websocket(&request) {
                let wire_target = h3_wire_target(&target).map_err(|error| {
                    ProtocolError::new(
                        proxelar_proto::ErrorKind::MalformedMessage,
                        error.to_string(),
                    )
                })?;
                return super::http3::handle_extended_websocket(
                    request,
                    handler,
                    remote_addr,
                    Some(wire_target),
                    move |mut request| async move {
                        super::prepare_upstream_protocol_request(&mut request, false)?;
                        upstream.send(request).await
                    },
                )
                .await;
            }
            let request = match handler.handle_request(&context, request).await {
                RequestOrResponse::Request(request) => request,
                RequestOrResponse::Response(response) => return Ok(response),
            };
            let wire_target = h3_wire_target(&target).map_err(|error| {
                ProtocolError::new(
                    proxelar_proto::ErrorKind::MalformedMessage,
                    error.to_string(),
                )
            })?;
            let mut request = rewrite_uri(request, &wire_target).map_err(|error| {
                ProtocolError::new(
                    proxelar_proto::ErrorKind::MalformedMessage,
                    error.to_string(),
                )
            })?;
            super::prepare_upstream_protocol_request(&mut request, false)?;
            match upstream.send(request).await {
                Ok(response) => Ok(handler.handle_response(&context, response).await),
                Err(error) => {
                    tracing::error!("Reverse HTTP/3 upstream error: {error}");
                    Ok(handler.synthetic_protocol_response(
                        http::StatusCode::BAD_GATEWAY,
                        http::HeaderMap::new(),
                        Bytes::from_static(b"Bad Gateway"),
                    ))
                }
            }
        })
    }
}

#[cfg(feature = "http3")]
fn h3_wire_target(target: &Uri) -> Result<Uri, crate::Error> {
    let mut parts = target.clone().into_parts();
    parts.scheme = Some(http::uri::Scheme::HTTPS);
    Uri::from_parts(parts).map_err(|error| crate::Error::Other(error.to_string()))
}

struct ReverseHttp1Service {
    remote_addr: SocketAddr,
    handler: CapturingHandler,
    target: Uri,
    upstream: NativeUpstream,
    upgrade: Arc<AsyncMutex<Option<ReverseUpgrade>>>,
}

struct ReverseUpgrade {
    upstream: UpgradeReceiver,
    handler: CapturingHandler,
    conn_id: u64,
}

impl HttpService for ReverseHttp1Service {
    fn call(
        &mut self,
        request: ProxyRequest,
    ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
        let mut handler = self.handler.clone();
        let target = self.target.clone();
        let upstream = self.upstream.clone();
        let upgrade = Arc::clone(&self.upgrade);
        let remote_addr = self.remote_addr;
        Box::pin(async move {
            let ctx = HttpContext { remote_addr };
            let request = match handler.handle_request(&ctx, request).await {
                RequestOrResponse::Request(request) => request,
                RequestOrResponse::Response(response) => return Ok(response),
            };
            let websocket = is_protocol_websocket_upgrade(&request);
            let request = match rewrite_uri(request, &target) {
                Ok(request) => request,
                Err(error) => {
                    tracing::error!("Failed to rewrite native H1 URI: {error}");
                    return Ok(handler.synthetic_protocol_response(
                        http::StatusCode::BAD_GATEWAY,
                        http::HeaderMap::new(),
                        Bytes::from_static(b"Bad Gateway: URI rewrite failed"),
                    ));
                }
            };
            match upstream.send(request, websocket).await {
                Ok(mut response)
                    if websocket
                        && response.response.head.status
                            == http::StatusCode::SWITCHING_PROTOCOLS =>
                {
                    let Some(upstream) = response.upgrade.take() else {
                        return Ok(handler.synthetic_protocol_response(
                            http::StatusCode::BAD_GATEWAY,
                            http::HeaderMap::new(),
                            Bytes::from_static(b"Bad Gateway: missing WebSocket upgrade"),
                        ));
                    };
                    let ws_response = proxyapi_models::ProxiedResponse::new(
                        response.response.head.status,
                        response.response.head.version,
                        response.response.head.headers.clone(),
                        Bytes::new(),
                        crate::handler::now_millis(),
                    );
                    let conn_id = handler
                        .take_pending_id()
                        .unwrap_or_else(crate::event::next_id);
                    if let Some(captured_req) = handler.take_captured_request() {
                        handler.send_event(crate::event::ProxyEvent::WebSocketConnected {
                            id: conn_id,
                            request: Box::new(captured_req),
                            response: Box::new(ws_response),
                        });
                    }
                    *upgrade.lock().await = Some(ReverseUpgrade {
                        upstream,
                        handler,
                        conn_id,
                    });
                    Ok(response.response)
                }
                Ok(response) => Ok(handler.handle_response(&ctx, response.response).await),
                Err(error) => {
                    tracing::error!("Native reverse HTTP/1 error: {error}");
                    Ok(handler.synthetic_protocol_response(
                        http::StatusCode::BAD_GATEWAY,
                        http::HeaderMap::new(),
                        Bytes::from_static(b"Bad Gateway"),
                    ))
                }
            }
        })
    }
}

/// Rewrite the request URI to point at the reverse proxy target, preserving
/// the original path and query. Also updates the `Host` header to match.
pub(super) fn rewrite_uri(
    mut req: crate::ProxyRequest,
    target: &Uri,
) -> Result<crate::ProxyRequest, http::Error> {
    let mut uri_parts = req.head.uri.clone().into_parts();
    uri_parts.scheme = target.scheme().cloned();
    uri_parts.authority = target.authority().cloned();
    req.head.uri = Uri::from_parts(uri_parts)?;

    // Update Host header to match the target so virtual hosting works correctly
    if let Some(authority) = target.authority() {
        if let Err(error) = req.head.headers.set("host", authority.as_str()) {
            tracing::warn!("Invalid target authority for Host header: {error}");
        }
    }

    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxyapi_models::HeaderBlock;

    fn request(uri: &str, host: &str) -> crate::ProxyRequest {
        let mut headers = HeaderBlock::new();
        headers.add("host", host).unwrap();
        crate::ProxyRequest::new(
            crate::RequestHead::new(
                http::Method::GET,
                uri.parse().unwrap(),
                http::Version::HTTP_11,
                headers,
            ),
            crate::ProxyBody::empty(),
        )
    }

    #[test]
    fn rewrite_uri_preserves_path_query_and_sets_target_host() {
        let req = request("/api/items?name=one", "client.example");
        let target: Uri = "https://upstream.example:8443".parse().unwrap();

        let req = rewrite_uri(req, &target).unwrap();

        assert_eq!(req.head.uri.scheme_str(), Some("https"));
        assert_eq!(
            req.head.uri.authority().map(|a| a.as_str()),
            Some("upstream.example:8443")
        );
        assert_eq!(req.head.uri.path(), "/api/items");
        assert_eq!(req.head.uri.query(), Some("name=one"));
        assert_eq!(
            req.head.headers.get("host"),
            Some(b"upstream.example:8443".as_slice())
        );
    }

    #[test]
    fn rewrite_uri_leaves_host_when_target_has_no_authority() {
        let req = request("/local", "client.example");
        let target: Uri = "/target-only".parse().unwrap();

        let req = rewrite_uri(req, &target).unwrap();

        assert_eq!(req.head.uri.path(), "/local");
        assert_eq!(
            req.head.headers.get("host"),
            Some(b"client.example".as_slice())
        );
    }

    #[cfg(feature = "http3")]
    #[test]
    fn http3_reverse_target_uses_https_on_the_wire() {
        let target: Uri = "http3://upstream.example:8443/base".parse().unwrap();

        let target = h3_wire_target(&target).unwrap();

        assert_eq!(target.scheme_str(), Some("https"));
        assert_eq!(target.authority().unwrap(), "upstream.example:8443");
    }

    #[cfg(feature = "http3")]
    #[derive(Clone)]
    struct StaticH3Service;

    #[cfg(feature = "http3")]
    impl HttpService for StaticH3Service {
        fn call(
            &mut self,
            request: ProxyRequest,
        ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
            Box::pin(async move {
                assert_eq!(request.head.version, http::Version::HTTP_3);
                assert_eq!(request.head.uri.path(), "/through-proxy");
                assert!(!request.head.headers.contains_key("proxy-authorization"));
                let mut headers = proxyapi_models::HeaderBlock::new();
                headers.add("x-upstream-protocol", "h3").unwrap();
                Ok(ProxyResponse::new(
                    proxelar_proto::ResponseHead::new(
                        http::StatusCode::CREATED,
                        http::Version::HTTP_3,
                        headers,
                    ),
                    proxelar_proto::ProxyBody::full("h3 upstream"),
                ))
            })
        }
    }

    #[cfg(feature = "http3")]
    async fn spawn_test_h3_upstream_with_service<S>(
        service: S,
    ) -> (
        SocketAddr,
        tokio::task::JoinHandle<()>,
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
    )
    where
        S: HttpService + Clone + Send + 'static,
    {
        use futures_util::StreamExt as _;
        use tokio_quiche::metrics::DefaultMetrics;
        use tokio_quiche::settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths};
        use tokio_quiche::{listen, ConnectionParams, ServerH3Driver};

        let ca_dir = tempfile::tempdir().unwrap();
        let ca = Ssl::load_or_generate(ca_dir.path()).unwrap();
        let authority: http::uri::Authority = "127.0.0.1:443".parse().unwrap();
        let certificate = ca.gen_h3_certificate(&authority).await.unwrap();
        let tls_dir = tempfile::tempdir().unwrap();
        let cert_path = tls_dir.path().join("cert.pem");
        let key_path = tls_dir.path().join("key.pem");
        std::fs::write(&cert_path, &certificate.certificate_pem).unwrap();
        std::fs::write(&key_path, &certificate.private_key_pem).unwrap();

        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let params = ConnectionParams::new_server(
            QuicSettings::default(),
            TlsCertificatePaths {
                cert: cert_path.to_str().unwrap(),
                private_key: key_path.to_str().unwrap(),
                kind: CertificateKind::X509,
            },
            Hooks::default(),
        );
        let mut connections = listen([socket], params, DefaultMetrics).unwrap().remove(0);
        let task = tokio::spawn(async move {
            let initial = connections.next().await.unwrap().unwrap();
            let (driver, controller) =
                ServerH3Driver::new(super::super::http3::default_http3_settings());
            let connection = initial.start(driver);
            super::super::http3::serve_connection(connection, controller, service)
                .await
                .unwrap();
        });
        (address, task, tls_dir, cert_path, key_path)
    }

    #[cfg(feature = "http3")]
    async fn spawn_test_h3_upstream() -> (
        SocketAddr,
        tokio::task::JoinHandle<()>,
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        spawn_test_h3_upstream_with_service(StaticH3Service).await
    }

    #[cfg(feature = "http3")]
    #[derive(Clone)]
    struct WebSocketH3Service;

    #[cfg(feature = "http3")]
    impl HttpService for WebSocketH3Service {
        fn call(
            &mut self,
            request: ProxyRequest,
        ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
            Box::pin(async move {
                use futures_util::{SinkExt as _, StreamExt as _};
                use tokio_tungstenite::tungstenite::protocol::Role;
                use tokio_tungstenite::WebSocketStream;

                assert!(super::super::http3::is_extended_websocket(&request));
                assert_eq!(
                    request.head.headers.get("sec-websocket-version"),
                    Some(b"13".as_slice())
                );
                assert!(!request.head.headers.contains_key("proxy-authorization"));
                let (tunnel, outbound) =
                    proxelar_proto::http2::body_tunnel(request.body, 64 * 1024);
                tokio::spawn(async move {
                    let mut websocket =
                        WebSocketStream::from_raw_socket(tunnel, Role::Server, None).await;
                    while let Some(Ok(message)) = websocket.next().await {
                        let close = message.is_close();
                        if websocket.send(message).await.is_err() || close {
                            break;
                        }
                    }
                });
                let mut headers = proxyapi_models::HeaderBlock::new();
                headers.add("sec-websocket-protocol", "chat").unwrap();
                Ok(ProxyResponse::new(
                    proxelar_proto::ResponseHead::new(
                        http::StatusCode::OK,
                        http::Version::HTTP_3,
                        headers,
                    ),
                    outbound,
                ))
            })
        }
    }

    #[cfg(feature = "http3")]
    #[tokio::test]
    async fn reverse_http3_proxies_udp_in_both_directions_and_captures() {
        use std::time::Duration;

        use crate::event::ProxyEvent;
        use crate::handler::DEFAULT_BODY_CAPTURE_LIMIT;
        use crate::proxy::UpstreamTlsConfig;

        let (upstream_addr, upstream_task, tls_dir, cert_path, key_path) =
            spawn_test_h3_upstream().await;
        let ca_dir = tempfile::tempdir().unwrap();
        let ca = Arc::new(Ssl::load_or_generate(ca_dir.path()).unwrap());
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(8);
        let handler =
            CapturingHandler::new(event_tx).with_body_capture_limit(DEFAULT_BODY_CAPTURE_LIMIT);
        let proxy = ReverseH3Server::bind(
            "127.0.0.1:0".parse().unwrap(),
            format!("http3://{upstream_addr}").parse().unwrap(),
            handler,
            ca,
            &UpstreamTlsConfig::Insecure,
        )
        .await
        .unwrap();
        let proxy_addr = proxy.local_addr();
        let proxy_task = tokio::spawn(proxy.serve());

        let verifier = super::super::tls::h3_server_verifier(&UpstreamTlsConfig::Insecure).unwrap();
        let client = super::super::http3::ReverseH3Upstream::new(
            format!("https://{proxy_addr}").parse().unwrap(),
            verifier,
            cert_path,
            key_path,
        );
        let mut headers = proxyapi_models::HeaderBlock::new();
        headers
            .add("proxy-authorization", "Basic reverse-secret")
            .unwrap();
        let request = ProxyRequest::new(
            proxelar_proto::RequestHead::new(
                http::Method::GET,
                format!("https://{proxy_addr}/through-proxy")
                    .parse()
                    .unwrap(),
                http::Version::HTTP_3,
                headers,
            ),
            proxelar_proto::ProxyBody::empty(),
        );
        let response = tokio::time::timeout(Duration::from_secs(5), client.send(request))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.head.status, http::StatusCode::CREATED);
        assert_eq!(
            response.head.headers.get("x-upstream-protocol"),
            Some(b"h3".as_slice())
        );
        assert_eq!(response.body.collect().await.unwrap().data, "h3 upstream");
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), event_rx.recv())
                .await
                .unwrap(),
            Some(ProxyEvent::RequestComplete { .. })
        ));

        proxy_task.abort();
        upstream_task.abort();
        drop(tls_dir);
    }

    #[cfg(feature = "http3")]
    #[tokio::test]
    async fn reverse_http3_extended_connect_websocket_has_event_and_frame_parity() {
        use std::time::Duration;

        use futures_util::{SinkExt as _, StreamExt as _};
        use proxyapi_models::{WsDirection, WsOpcode};
        use tokio_tungstenite::tungstenite::{protocol::Role, Message};
        use tokio_tungstenite::WebSocketStream;

        use crate::event::ProxyEvent;
        use crate::handler::DEFAULT_BODY_CAPTURE_LIMIT;
        use crate::proxy::UpstreamTlsConfig;

        let (upstream_addr, upstream_task, tls_dir, cert_path, key_path) =
            spawn_test_h3_upstream_with_service(WebSocketH3Service).await;
        let ca_dir = tempfile::tempdir().unwrap();
        let ca = Arc::new(Ssl::load_or_generate(ca_dir.path()).unwrap());
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(16);
        let handler =
            CapturingHandler::new(event_tx).with_body_capture_limit(DEFAULT_BODY_CAPTURE_LIMIT);
        #[cfg(feature = "scripting")]
        let (handler, script_file) = {
            let file = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(
                file.path(),
                r#"
                function on_websocket_frame(frame)
                    if frame.direction == "client_to_server" then
                        return "changed over h3"
                    end
                    return nil
                end
                "#,
            )
            .unwrap();
            let handler = handler.with_script_engine(Arc::new(
                crate::scripting::ScriptEngine::new(file.path()).unwrap(),
            ));
            (handler, file)
        };
        let proxy = ReverseH3Server::bind(
            "127.0.0.1:0".parse().unwrap(),
            format!("http3://{upstream_addr}").parse().unwrap(),
            handler,
            ca,
            &UpstreamTlsConfig::Insecure,
        )
        .await
        .unwrap();
        let proxy_addr = proxy.local_addr();
        let proxy_task = tokio::spawn(proxy.serve());

        let verifier = super::super::tls::h3_server_verifier(&UpstreamTlsConfig::Insecure).unwrap();
        let client = super::super::http3::ReverseH3Upstream::new(
            format!("https://{proxy_addr}").parse().unwrap(),
            verifier,
            cert_path,
            key_path,
        );
        let (tunnel, request_body, response_body) =
            proxelar_proto::http2::websocket_body_tunnel(64 * 1024);
        let mut headers = proxyapi_models::HeaderBlock::new();
        headers.add(":protocol", "websocket").unwrap();
        headers.add("sec-websocket-version", "13").unwrap();
        headers.add("sec-websocket-protocol", "chat").unwrap();
        headers
            .add("proxy-authorization", "Basic reverse-secret")
            .unwrap();
        let request = ProxyRequest::new(
            proxelar_proto::RequestHead::new(
                http::Method::CONNECT,
                format!("https://{proxy_addr}/socket").parse().unwrap(),
                http::Version::HTTP_3,
                headers,
            ),
            request_body,
        );
        let response = tokio::time::timeout(Duration::from_secs(5), client.send(request))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.head.status, http::StatusCode::OK);
        assert_eq!(
            response.head.headers.get("sec-websocket-protocol"),
            Some(b"chat".as_slice())
        );
        response_body.send(response.body).unwrap();
        let mut websocket = WebSocketStream::from_raw_socket(tunnel, Role::Client, None).await;

        let connected = tokio::time::timeout(Duration::from_secs(2), event_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let connection_id = match connected {
            ProxyEvent::WebSocketConnected {
                id,
                request,
                response,
            } => {
                assert_eq!(request.method(), http::Method::CONNECT);
                assert_eq!(request.version(), http::Version::HTTP_3);
                assert_eq!(response.status(), http::StatusCode::OK);
                assert_eq!(response.version(), http::Version::HTTP_3);
                id
            }
            other => panic!("expected WebSocketConnected, got {other:?}"),
        };

        websocket
            .send(Message::Text("hello over h3".into()))
            .await
            .unwrap();
        #[cfg(feature = "scripting")]
        let expected_payload = "changed over h3";
        #[cfg(not(feature = "scripting"))]
        let expected_payload = "hello over h3";
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), websocket.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            Message::Text(expected_payload.into())
        );

        let mut directions = Vec::new();
        while directions.len() < 2 {
            match tokio::time::timeout(Duration::from_secs(2), event_rx.recv())
                .await
                .unwrap()
                .unwrap()
            {
                ProxyEvent::WebSocketFrame { conn_id, frame } if frame.opcode == WsOpcode::Text => {
                    assert_eq!(conn_id, connection_id);
                    assert_eq!(frame.payload, expected_payload);
                    directions.push(frame.direction);
                }
                _ => {}
            }
        }
        assert_eq!(
            directions,
            vec![WsDirection::ClientToServer, WsDirection::ServerToClient]
        );

        websocket.close(None).await.unwrap();
        loop {
            if let ProxyEvent::WebSocketClosed { conn_id } =
                tokio::time::timeout(Duration::from_secs(2), event_rx.recv())
                    .await
                    .unwrap()
                    .unwrap()
            {
                assert_eq!(conn_id, connection_id);
                break;
            }
        }

        proxy_task.abort();
        upstream_task.abort();
        drop(tls_dir);
        #[cfg(feature = "scripting")]
        drop(script_file);
    }
}
