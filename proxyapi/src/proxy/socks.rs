//! Inbound SOCKS5 server built on rama's `Socks5Acceptor`.
//!
//! A no-auth acceptor hands each CONNECT stream to a [`LazyConnector`], which
//! stamps the target into `ConnectorTarget` and passes the raw stream to the
//! shared MITM tunnel — so the CONNECT target pins the upstream regardless of
//! any spoofed inner `Host`, and the same {TLS, HTTP, raw} inspection applies.

use std::sync::Arc;

use rama::error::BoxError;
use rama::extensions::ExtensionsRef;
use rama::io::Io;
use rama::net::client::ConnectorTarget;
use rama::proxy::socks5::{server::LazyConnector, Socks5Acceptor};
use rama::rt::Executor;
use rama::Service;

use super::forward::{serve_mitm_tunnel, MitmConfig};

/// Bridges a SOCKS5 CONNECT stream into the shared MITM tunnel.
#[derive(Clone)]
pub(crate) struct SocksMitmService {
    cfg: Arc<MitmConfig>,
}

impl<S> Service<S> for SocksMitmService
where
    S: Io + Unpin + ExtensionsRef,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, stream: S) -> Result<Self::Output, Self::Error> {
        let target = stream
            .extensions()
            .get_ref::<ConnectorTarget>()
            .map(|target| target.0.clone())
            .ok_or_else(|| BoxError::from("SOCKS5 stream missing connector target".to_owned()))?;
        serve_mitm_tunnel(stream, target, Arc::clone(&self.cfg)).await
    }
}

/// Build a no-auth SOCKS5 acceptor whose connector runs the MITM tunnel.
pub(crate) fn acceptor(
    cfg: Arc<MitmConfig>,
    exec: Executor,
) -> Socks5Acceptor<LazyConnector<SocksMitmService>> {
    Socks5Acceptor::new(exec).with_connector(LazyConnector::new(SocksMitmService { cfg }))
}
