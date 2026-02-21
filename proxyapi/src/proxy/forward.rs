use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http::uri::{Authority, Scheme};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, Uri};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::body::{self, ProxyBody};
use crate::ca::{cert_server, CertificateAuthority, Ssl};
use crate::handler::{collect_and_emit, collect_body, CapturingHandler};
use crate::rewind::Rewind;
use crate::{HttpContext, HttpHandler, RequestOrResponse};

use super::{is_benign_shutdown_error, Client};

/// First bytes of an HTTP GET request.
const HTTP_GET_PREFIX: &[u8; 4] = b"GET ";
/// TLS record content type: Handshake.
const TLS_RECORD_HANDSHAKE: u8 = 0x16;
/// TLS major version byte (SSLv3 / TLS 1.x).
const TLS_VERSION_MAJOR: u8 = 0x03;

pub async fn handle_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    handler: CapturingHandler,
    ca: Arc<Ssl>,
    client: Arc<Client>,
    listen_addr: SocketAddr,
) {
    let io = TokioIo::new(stream);

    let service = service_fn(move |req: Request<hyper::body::Incoming>| {
        let mut handler = handler.clone();
        let ca = Arc::clone(&ca);
        let client = Arc::clone(&client);

        async move {
            let ctx = HttpContext { remote_addr };

            // Direct request to the proxy itself (relative URI, no host).
            // Serves the cert download page at http://localhost:PORT/
            if req.uri().host().is_none() && !req.uri().path().is_empty() {
                let resp = cert_server::handle(&req, &ca.ca_cert_pem(), None);
                return Ok::<_, hyper::Error>(resp);
            }

            // Proxied request to proxel.ar — serve cert page
            if cert_server::is_cert_request(&req) {
                let resp = cert_server::handle(&req, &ca.ca_cert_pem(), Some(listen_addr));
                return Ok::<_, hyper::Error>(resp);
            }

            if req.method() == Method::CONNECT {
                return process_connect(req, handler, ca, client, remote_addr, listen_addr);
            }

            let req = match handler.handle_request(&ctx, req).await {
                RequestOrResponse::Request(req) => req,
                RequestOrResponse::Response(res) => return Ok(res),
            };

            match client.request(normalize_request(req)).await {
                Ok(res) => {
                    let (parts, body) = res.into_parts();
                    let body_bytes = collect_body(body).await;
                    Ok(collect_and_emit(&mut handler, parts, body_bytes))
                }
                Err(e) => {
                    tracing::error!("Client request error: {e}");
                    Ok(Response::builder()
                        .status(502)
                        .body(body::full(Bytes::from("Bad Gateway")))
                        .unwrap_or_else(|_| Response::new(body::empty())))
                }
            }
        }
    });

    if let Err(e) = hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(io, service)
        .with_upgrades()
        .await
    {
        if !is_benign_shutdown_error(&e) {
            tracing::debug!("Connection error: {e}");
        }
    }
}

/// Handle a CONNECT request by upgrading the connection and tunneling traffic.
///
/// After the upgrade, the first bytes are peeked to detect whether the client
/// is speaking plain HTTP, TLS, or an unknown protocol, and the connection is
/// dispatched accordingly.
fn process_connect(
    req: Request<hyper::body::Incoming>,
    handler: CapturingHandler,
    ca: Arc<Ssl>,
    client: Arc<Client>,
    remote_addr: SocketAddr,
    listen_addr: SocketAddr,
) -> Result<Response<ProxyBody>, hyper::Error> {
    let authority = if let Some(a) = req.uri().authority().cloned() {
        a
    } else {
        tracing::warn!("CONNECT request missing authority");
        return Ok(Response::builder()
            .status(400)
            .body(body::full(Bytes::from("Bad Request: missing authority")))
            .unwrap_or_else(|_| Response::new(body::empty())));
    };

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let mut upgraded = TokioIo::new(upgraded);
                let mut buffer = [0u8; 4];
                let bytes_read = match upgraded.read(&mut buffer).await {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::error!("Failed to read from upgraded connection: {e}");
                        return;
                    }
                };

                let upgraded =
                    Rewind::new_buffered(upgraded, Bytes::copy_from_slice(&buffer[..bytes_read]));

                if buffer == *HTTP_GET_PREFIX {
                    if let Err(e) = serve_stream(
                        upgraded,
                        Scheme::HTTP,
                        handler,
                        ca,
                        client,
                        remote_addr,
                        listen_addr,
                    )
                    .await
                    {
                        tracing::debug!("HTTP connect error: {e}");
                    }
                } else if buffer[0] == TLS_RECORD_HANDSHAKE && buffer[1] == TLS_VERSION_MAJOR {
                    let server_config = match ca.gen_server_config(&authority).await {
                        Ok(cfg) => cfg,
                        Err(e) => {
                            tracing::error!(
                                "Failed to generate server config for {authority}: {e}"
                            );
                            return;
                        }
                    };
                    let stream = match TlsAcceptor::from(server_config).accept(upgraded).await {
                        Ok(stream) => stream,
                        Err(e) => {
                            tracing::debug!("Failed to establish TLS connection: {e}");
                            return;
                        }
                    };

                    if let Err(e) = serve_stream(
                        stream,
                        Scheme::HTTPS,
                        handler,
                        ca,
                        client,
                        remote_addr,
                        listen_addr,
                    )
                    .await
                    {
                        if !is_benign_shutdown_error(&*e) {
                            tracing::warn!("HTTPS connect error for {authority}: {e}");
                        }
                    }
                } else {
                    tracing::debug!(
                        "Unknown protocol, read '{:02X?}' from upgraded connection",
                        &buffer[..bytes_read]
                    );

                    let authority_str = authority.as_str();
                    let mut server = match TcpStream::connect(authority_str).await {
                        Ok(server) => server,
                        Err(e) => {
                            tracing::debug!("Failed to connect to {authority_str}: {e}");
                            return;
                        }
                    };

                    let mut upgraded = upgraded;
                    if let Err(e) = tokio::io::copy_bidirectional(&mut upgraded, &mut server).await
                    {
                        tracing::debug!(
                            "Failed to tunnel unknown protocol to {authority_str}: {e}"
                        );
                    }
                }
            }
            Err(e) => tracing::error!("Upgrade error: {e}"),
        }
    });

    Ok(Response::new(body::empty()))
}

/// Serve HTTP/1.1 requests over an already-established stream (plain or TLS).
///
/// Each request is passed through the [`CapturingHandler`] for inspection before
/// being forwarded to the upstream server via `client`.
async fn serve_stream<I>(
    stream: I,
    scheme: Scheme,
    handler: CapturingHandler,
    ca: Arc<Ssl>,
    client: Arc<Client>,
    remote_addr: SocketAddr,
    listen_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);

    let service = service_fn(move |mut req: Request<hyper::body::Incoming>| {
        let mut handler = handler.clone();
        let ca = Arc::clone(&ca);
        let client = Arc::clone(&client);
        let scheme = scheme.clone();

        async move {
            let ctx = HttpContext { remote_addr };

            // Reconstruct full URI with scheme + authority from Host header
            if req.version() == hyper::Version::HTTP_10 || req.version() == hyper::Version::HTTP_11
            {
                let (mut parts, body) = req.into_parts();

                let host = if let Some(h) = parts.headers.get(hyper::header::HOST) {
                    h.as_bytes()
                } else {
                    tracing::warn!("Request missing Host header");
                    return Ok(Response::builder()
                        .status(400)
                        .body(body::full(Bytes::from("Bad Request: missing Host header")))
                        .unwrap_or_else(|_| Response::new(body::empty())));
                };

                let authority = match Authority::try_from(host) {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::warn!("Failed to parse authority from Host header: {e}");
                        return Ok(Response::builder()
                            .status(400)
                            .body(body::full(Bytes::from("Bad Request: invalid Host header")))
                            .unwrap_or_else(|_| Response::new(body::empty())));
                    }
                };

                parts.uri = {
                    let mut uri_parts = parts.uri.into_parts();
                    uri_parts.scheme = Some(scheme);
                    uri_parts.authority = Some(authority);
                    match Uri::from_parts(uri_parts) {
                        Ok(uri) => uri,
                        Err(e) => {
                            tracing::warn!("Failed to build URI: {e}");
                            return Ok(Response::builder()
                                .status(400)
                                .body(body::full(Bytes::from("Bad Request: invalid URI")))
                                .unwrap_or_else(|_| Response::new(body::empty())));
                        }
                    }
                };

                req = Request::from_parts(parts, body);
            }

            // Check for proxel.ar cert request (inside CONNECT tunnel)
            if cert_server::is_cert_request(&req) {
                let resp = cert_server::handle(&req, &ca.ca_cert_pem(), Some(listen_addr));
                return Ok::<_, hyper::Error>(resp);
            }

            let req = match handler.handle_request(&ctx, req).await {
                RequestOrResponse::Request(req) => req,
                RequestOrResponse::Response(res) => return Ok(res),
            };

            match client.request(normalize_request(req)).await {
                Ok(res) => {
                    let (parts, body) = res.into_parts();
                    let body_bytes = collect_body(body).await;
                    Ok(collect_and_emit(&mut handler, parts, body_bytes))
                }
                Err(e) => {
                    tracing::error!("Client request error: {e}");
                    Ok(Response::builder()
                        .status(502)
                        .body(body::full(Bytes::from("Bad Gateway")))
                        .unwrap_or_else(|_| Response::new(body::empty())))
                }
            }
        }
    });

    hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(io, service)
        .with_upgrades()
        .await
        .map_err(Into::into)
}

/// Strip hop-by-hop artifacts before forwarding a request upstream.
///
/// Removes the `Host` header (hyper sets it from the URI), joins duplicate
/// `Cookie` headers into a single value, and pins the version to HTTP/1.1.
fn normalize_request(mut req: Request<ProxyBody>) -> Request<ProxyBody> {
    req.headers_mut().remove(hyper::header::HOST);

    if let http::header::Entry::Occupied(mut cookies) =
        req.headers_mut().entry(hyper::header::COOKIE)
    {
        let joined_cookies = bstr::join(b"; ", cookies.iter());
        match joined_cookies.try_into() {
            Ok(value) => {
                cookies.insert(value);
            }
            Err(e) => {
                tracing::warn!("Failed to join cookies, removing header: {e}");
                cookies.remove();
            }
        }
    }

    *req.version_mut() = hyper::Version::HTTP_11;
    req
}
