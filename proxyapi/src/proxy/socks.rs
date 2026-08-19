//! Inbound SOCKS5 server built on rama's `Socks5Acceptor`.
//!
//! A no-auth acceptor eagerly establishes the requested direct or proxy-routed
//! egress before reporting CONNECT success, then hands rama's [`BridgeIo`] to
//! the shared MITM tunnel. The selected protocol path reuses that exact egress.

use std::sync::Arc;

use rama::proxy::socks5::{server::Connector as SocksConnector, Socks5Acceptor};
use rama::rt::Executor;

use super::connector::TimedRawConnector;
use super::forward::{MitmBridgeService, MitmConfig};

/// Build a no-auth SOCKS5 acceptor whose connector runs the MITM tunnel.
pub(crate) fn acceptor(
    cfg: Arc<MitmConfig>,
    exec: Executor,
) -> Socks5Acceptor<SocksConnector<TimedRawConnector, MitmBridgeService>> {
    let connector = SocksConnector::new(
        super::connector::with_timeout(cfg.raw_connector()),
        MitmBridgeService::new(cfg),
    );
    Socks5Acceptor::new(exec).with_connector(connector)
}
