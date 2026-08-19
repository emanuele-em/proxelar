use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http::uri::{Authority, Scheme};
use http::{Method, StatusCode, Uri, Version};
use proxelar_proto::http2::{body_tunnel, serve_connection, ConnectionConfig};
use proxelar_proto::{
    BoxFuture, ErrorKind, HttpService, ProtocolError, ProxyRequest, ProxyResponse, ResponseHead,
};
use proxyapi_models::HeaderBlock;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::ca::{CertificateAuthority, Ssl};
use crate::handler::CapturingHandler;
use crate::rewind::Rewind;
use crate::{HttpContext, HttpHandler, RequestOrResponse};

use super::forward::{
    handle_cert_protocol_request, is_cert_protocol_request, is_direct_cert_protocol_request,
    is_h2_preface, reconstruct_protocol_uri, serve_native_stream, sniff_stream_protocol,
    StreamProtocol,
};
use super::http1::{NativePool, NativeUpstream};
use super::BoxError;

const TUNNEL_BUFFER_CAPACITY: usize = 64 * 1024;

#[allow(clippy::too_many_arguments)]
pub(super) async fn serve_forward<I>(
    io: I,
    scheme: Scheme,
    remote_addr: SocketAddr,
    handler: CapturingHandler,
    ca: Arc<Ssl>,
    native_pool: Arc<NativePool>,
    route: Option<String>,
    listen_addr: SocketAddr,
) -> Result<(), BoxError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_with_upstream(
        io,
        scheme,
        remote_addr,
        handler,
        ca,
        NativeUpstream::shared(Arc::clone(&native_pool), route.clone()),
        Some(native_pool),
        route,
        listen_addr,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn serve_with_upstream<I>(
    io: I,
    scheme: Scheme,
    remote_addr: SocketAddr,
    handler: CapturingHandler,
    ca: Arc<Ssl>,
    upstream: NativeUpstream,
    native_pool: Option<Arc<NativePool>>,
    route: Option<String>,
    listen_addr: SocketAddr,
) -> Result<(), BoxError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = ForwardH2Service {
        scheme,
        remote_addr,
        handler,
        ca,
        native_pool,
        route,
        upstream,
        listen_addr,
    };
    serve_connection(io, service, ConnectionConfig::default())
        .await
        .map_err(|error| Box::new(error) as BoxError)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn serve_pinned<I, U>(
    io: I,
    upstream_io: U,
    authority: Authority,
    scheme: Scheme,
    remote_addr: SocketAddr,
    handler: CapturingHandler,
    ca: Arc<Ssl>,
    listen_addr: SocketAddr,
) -> Result<(), BoxError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_with_upstream(
        io,
        scheme,
        remote_addr,
        handler,
        ca,
        NativeUpstream::pinned(upstream_io, authority),
        None,
        None,
        listen_addr,
    )
    .await
}

pub(super) async fn serve_reverse<I>(
    io: I,
    remote_addr: SocketAddr,
    handler: CapturingHandler,
    target: Uri,
    upstream: NativeUpstream,
) -> Result<(), BoxError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = ReverseH2Service {
        remote_addr,
        handler,
        target,
        upstream,
    };
    serve_connection(io, service, ConnectionConfig::default())
        .await
        .map_err(|error| Box::new(error) as BoxError)
}

#[derive(Clone)]
struct ForwardH2Service {
    scheme: Scheme,
    remote_addr: SocketAddr,
    handler: CapturingHandler,
    ca: Arc<Ssl>,
    native_pool: Option<Arc<NativePool>>,
    route: Option<String>,
    upstream: NativeUpstream,
    listen_addr: SocketAddr,
}

impl HttpService for ForwardH2Service {
    fn call(
        &mut self,
        request: ProxyRequest,
    ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
        let service = self.clone();
        Box::pin(async move { service.handle(request).await })
    }
}

impl ForwardH2Service {
    async fn handle(self, request: ProxyRequest) -> Result<ProxyResponse, ProtocolError> {
        if is_direct_cert_protocol_request(&request, self.listen_addr)
            || is_cert_protocol_request(&request)
        {
            return Ok(handle_cert_protocol_request(
                &request,
                &self.ca.ca_cert_pem(),
                Some(self.listen_addr),
            ));
        }

        if request.head.method == Method::CONNECT {
            let authority = request
                .head
                .uri
                .authority()
                .cloned()
                .ok_or_else(|| malformed("CONNECT request is missing authority"))?;
            let (tunnel, outbound) = body_tunnel(request.body, TUNNEL_BUFFER_CAPACITY);
            let service = self.clone();
            tokio::spawn(async move {
                handle_connect_tunnel(tunnel, authority, service).await;
            });
            return Ok(ProxyResponse::new(
                ResponseHead::new(StatusCode::OK, Version::HTTP_2, HeaderBlock::new()),
                outbound,
            ));
        }

        let request = reconstruct_protocol_uri(request, self.scheme)?;
        if is_cert_protocol_request(&request) {
            return Ok(handle_cert_protocol_request(
                &request,
                &self.ca.ca_cert_pem(),
                Some(self.listen_addr),
            ));
        }
        let context = HttpContext {
            remote_addr: self.remote_addr,
        };
        let mut handler = self.handler;
        let request = match handler.handle_request(&context, request).await {
            RequestOrResponse::Request(request) => request,
            RequestOrResponse::Response(response) => return Ok(response),
        };
        match self.upstream.send(request, false).await {
            Ok(response) => Ok(handler.handle_response(&context, response.response).await),
            Err(error) => {
                tracing::error!("Native HTTP/2 forward error: {error}");
                Ok(handler.synthetic_protocol_response(
                    StatusCode::BAD_GATEWAY,
                    http::HeaderMap::new(),
                    Bytes::from_static(b"Bad Gateway"),
                ))
            }
        }
    }
}

#[derive(Clone)]
struct ReverseH2Service {
    remote_addr: SocketAddr,
    handler: CapturingHandler,
    target: Uri,
    upstream: NativeUpstream,
}

impl HttpService for ReverseH2Service {
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
            let request = match handler.handle_request(&context, request).await {
                RequestOrResponse::Request(request) => request,
                RequestOrResponse::Response(response) => return Ok(response),
            };
            let request = match super::reverse::rewrite_uri(request, &target) {
                Ok(request) => request,
                Err(error) => {
                    tracing::error!("Failed to rewrite HTTP/2 reverse URI: {error}");
                    return Ok(handler.synthetic_protocol_response(
                        StatusCode::BAD_GATEWAY,
                        http::HeaderMap::new(),
                        Bytes::from_static(b"Bad Gateway: URI rewrite failed"),
                    ));
                }
            };
            match upstream.send(request, false).await {
                Ok(response) => Ok(handler.handle_response(&context, response.response).await),
                Err(error) => {
                    tracing::error!("Native HTTP/2 reverse error: {error}");
                    Ok(handler.synthetic_protocol_response(
                        StatusCode::BAD_GATEWAY,
                        http::HeaderMap::new(),
                        Bytes::from_static(b"Bad Gateway"),
                    ))
                }
            }
        })
    }
}

async fn handle_connect_tunnel(
    mut tunnel: tokio::io::DuplexStream,
    authority: Authority,
    service: ForwardH2Service,
) {
    let (protocol, buffered) = match sniff_stream_protocol(&mut tunnel).await {
        Ok(detected) => detected,
        Err(error) => {
            tracing::debug!("HTTP/2 CONNECT protocol detection failed: {error}");
            return;
        }
    };
    let nested_h2 = is_h2_preface(&buffered);
    let tunnel = Rewind::new_buffered(tunnel, buffered);
    match protocol {
        StreamProtocol::Http if nested_h2 => {
            let Some(native_pool) = service.native_pool else {
                tracing::debug!("Nested h2c is unavailable on a pinned upstream connection");
                return;
            };
            if let Err(error) = serve_forward(
                tunnel,
                Scheme::HTTP,
                service.remote_addr,
                service.handler,
                service.ca,
                native_pool,
                service.route,
                service.listen_addr,
            )
            .await
            {
                tracing::debug!("Nested h2c CONNECT failed: {error}");
            }
        }
        StreamProtocol::Http => {
            if let Err(error) = serve_native_stream(
                Box::new(tunnel),
                Scheme::HTTP,
                service.handler,
                service.ca,
                None,
                service.upstream,
                service.remote_addr,
                service.listen_addr,
            )
            .await
            {
                tracing::debug!("Nested HTTP/1 CONNECT failed: {error}");
            }
        }
        StreamProtocol::Tls => {
            let server_config = match service.ca.gen_server_config(&authority).await {
                Ok(config) => config,
                Err(error) => {
                    tracing::debug!("HTTP/2 CONNECT certificate error: {error}");
                    return;
                }
            };
            let stream = match tokio_rustls::TlsAcceptor::from(server_config)
                .accept(tunnel)
                .await
            {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::debug!("HTTP/2 CONNECT TLS error: {error}");
                    return;
                }
            };
            if stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice()) {
                let Some(native_pool) = service.native_pool else {
                    tracing::debug!("Nested HTTP/2 is unavailable on a pinned upstream connection");
                    return;
                };
                if let Err(error) = serve_forward(
                    stream,
                    Scheme::HTTPS,
                    service.remote_addr,
                    service.handler,
                    service.ca,
                    native_pool,
                    service.route,
                    service.listen_addr,
                )
                .await
                {
                    tracing::debug!("Nested TLS HTTP/2 CONNECT failed: {error}");
                }
            } else if let Err(error) = serve_native_stream(
                Box::new(stream),
                Scheme::HTTPS,
                service.handler,
                service.ca,
                None,
                service.upstream,
                service.remote_addr,
                service.listen_addr,
            )
            .await
            {
                tracing::debug!("Nested TLS HTTP/1 CONNECT failed: {error}");
            }
        }
        StreamProtocol::Unknown => {
            let mut server = match tokio::net::TcpStream::connect(authority.as_str()).await {
                Ok(server) => server,
                Err(error) => {
                    tracing::debug!("HTTP/2 CONNECT upstream tunnel error: {error}");
                    return;
                }
            };
            let mut tunnel = tunnel;
            if let Err(error) = super::raw::tunnel(
                &mut tunnel,
                &mut server,
                authority.to_string(),
                service.handler.event_tx_clone(),
            )
            .await
            {
                tracing::debug!("HTTP/2 CONNECT raw tunnel failed: {error}");
            }
        }
    }
}

fn malformed(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ErrorKind::MalformedMessage, message)
}
