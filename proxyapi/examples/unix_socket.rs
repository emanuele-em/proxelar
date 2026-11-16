//! Example: forward proxy on a Unix socket that only serves its owner.
//!
//! Binds a Unix socket and serves it with
//! [`Proxy::serve_with_handler`](proxyapi::Proxy::serve_with_handler).
//! Unix clients are identified by the credentials of their process
//! ([`ClientInfo::Unix`](proxyapi::ClientInfo::Unix)): the handler serves
//! the user that owns the socket and rejects every other client, root
//! included. Requests inside CONNECT tunnels and raw tunnels are checked the
//! same way.
//!
//! Start a local upstream (e.g. `python3 -m http.server 8000`), run this
//! example, and send a request through the socket:
//!
//! ```console
//! $ curl --unix-socket /tmp/proxyapi-unix-socket-example.sock http://127.0.0.1:8000/
//! ```
//!
//! On a Unix socket, curl ignores `-x` and sends origin-form requests, which
//! the proxy forwards to the `Host` they name. Clients that need CONNECT,
//! e.g. for HTTPS, can reach the socket through a TCP bridge such as
//! `socat TCP-LISTEN:8118,fork UNIX-CONNECT:/tmp/proxyapi-unix-socket-example.sock`.

#[cfg(unix)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    unix::main().await
}

#[cfg(not(unix))]
fn main() {
    eprintln!("This example needs Unix sockets.");
}

#[cfg(unix)]
mod unix {
    use std::net::SocketAddr;
    use std::os::unix::fs::MetadataExt;

    use bytes::Bytes;
    use http::{uri::Authority, HeaderMap, StatusCode};
    use tokio::net::UnixListener;
    use tokio::sync::mpsc;

    use proxyapi::{
        ClientInfo, HttpContext, HttpHandler, Proxy, ProxyConfig, ProxyMode, ProxyRequest,
        ProxyResponse, RequestOrResponse, TunnelDecision, UpstreamTlsConfig,
    };

    const SOCKET: &str = "/tmp/proxyapi-unix-socket-example.sock";

    #[derive(Clone)]
    struct OwnerOnlyHandler {
        owner_uid: u32,
    }

    impl OwnerOnlyHandler {
        fn is_owner(&self, ctx: &HttpContext) -> bool {
            // Any other kind of client, including future ones, is rejected.
            matches!(&ctx.client, ClientInfo::Unix(client) if client.uid == self.owner_uid)
        }
    }

    #[async_trait::async_trait]
    impl HttpHandler for OwnerOnlyHandler {
        async fn handle_request(
            &mut self,
            ctx: &HttpContext,
            request: ProxyRequest,
        ) -> RequestOrResponse {
            if !self.is_owner(ctx) {
                return RequestOrResponse::Response(self.synthetic_protocol_response(
                    StatusCode::FORBIDDEN,
                    HeaderMap::new(),
                    Bytes::from_static(b"blocked: client does not own the socket"),
                ));
            }
            RequestOrResponse::Request(request)
        }

        async fn handle_response(
            &mut self,
            _ctx: &HttpContext,
            response: ProxyResponse,
        ) -> ProxyResponse {
            response
        }

        async fn handle_tunnel(
            &mut self,
            ctx: &HttpContext,
            _authority: &Authority,
        ) -> TunnelDecision {
            if self.is_owner(ctx) {
                TunnelDecision::Forward
            } else {
                TunnelDecision::Close
            }
        }
    }

    pub(super) async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        // A socket file left by an earlier run would make the bind fail.
        let _ = std::fs::remove_file(SOCKET);
        let listener = UnixListener::bind(SOCKET)?;
        // The socket file belongs to the user running the proxy.
        let owner_uid = std::fs::metadata(SOCKET)?.uid();

        // This handler never emits events; the channel exists only because
        // ProxyConfig requires a sender.
        let (event_tx, _event_rx) = mpsc::channel(64);
        let config = ProxyConfig {
            // Ignored by serve_with_handler, which serves `listener`.
            addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            mode: ProxyMode::Forward,
            event_tx,
            ca_dir: std::env::temp_dir().join("proxyapi-unix-socket-example-ca"),
            upstream_tls: UpstreamTlsConfig::Default,
            intercept: None,
            body_capture_limit: None,
            #[cfg(feature = "scripting")]
            script_path: None,
            replay_rx: None,
        };
        println!("unix socket proxy listening on {SOCKET}, serving uid {owner_uid}");
        let result = Proxy::new(config)
            .serve_with_handler(listener, OwnerOnlyHandler { owner_uid }, async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await;
        // The proxy never removes the socket file: whoever bound it does.
        let _ = std::fs::remove_file(SOCKET);
        result?;
        Ok(())
    }
}
