//! Inbound SOCKS5 server built on rama's `Socks5Acceptor`.
//!
//! A no-auth acceptor eagerly establishes the requested direct or proxy-routed
//! egress before reporting CONNECT success, then hands rama's [`BridgeIo`] to
//! the shared MITM tunnel. The selected protocol path reuses that exact egress.

use std::sync::Arc;

use rama::error::BoxError;
use rama::extensions::ExtensionsRef;
use rama::io::{BridgeIo, Io};
use rama::net::client::ConnectorTarget;
use rama::proxy::socks5::{
    server::{Connector as SocksConnector, DefaultConnector},
    Socks5Acceptor,
};
use rama::rt::Executor;
use rama::Service;

use super::connector::{RawConnection, SocketConnector, SocketIo};
use super::forward::{serve_mitm_tunnel, MitmConfig};

/// Bridges a SOCKS5 CONNECT stream into the shared MITM tunnel.
#[derive(Clone)]
pub(crate) struct SocksMitmService {
    cfg: Arc<MitmConfig>,
}

impl<S> Service<BridgeIo<S, SocketIo<RawConnection>>> for SocksMitmService
where
    S: Io + Unpin + ExtensionsRef,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(
        &self,
        BridgeIo(stream, egress): BridgeIo<S, SocketIo<RawConnection>>,
    ) -> Result<Self::Output, Self::Error> {
        let target = egress
            .extensions()
            .get_ref::<ConnectorTarget>()
            .map(|target| target.0.clone())
            .ok_or_else(|| BoxError::from("SOCKS5 egress missing connector target".to_owned()))?;
        let cfg = Arc::new(self.cfg.with_pinned_client(egress.into_inner()?)?);
        serve_mitm_tunnel(stream, target, cfg).await
    }
}

/// Build a no-auth SOCKS5 acceptor whose connector runs the MITM tunnel.
pub(crate) fn acceptor(
    cfg: Arc<MitmConfig>,
    exec: Executor,
) -> Socks5Acceptor<SocksConnector<SocketConnector, SocksMitmService>> {
    // Start from rama's eager default connector so its timeout and SOCKS reply
    // semantics remain intact. Only replace the transport (to honor an
    // upstream proxy) and the byte-forwarding service (to run the MITM path).
    let connector = DefaultConnector::default_with_exec(exec.clone())
        .with_connector(super::connector::socket_capable(cfg.raw_connector()))
        .with_service(SocksMitmService { cfg });
    Socks5Acceptor::new(exec).with_connector(connector)
}
