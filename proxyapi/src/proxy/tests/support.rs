use std::sync::Arc;

use http::{Method, Uri, Version};
use proxelar_proto::{ProxyBody, ProxyRequest, RequestHead};
use proxyapi_models::HeaderBlock;
use rustls::pki_types::pem::PemObject as _;
use tokio::sync::mpsc;

use crate::ca::Ssl;
use crate::handler::CapturingHandler;
use crate::ProxyEvent;

pub(super) struct Context {
    pub ca: Arc<Ssl>,
    pub handler: CapturingHandler,
    pub events: mpsc::Receiver<ProxyEvent>,
    pub tls: rustls::ClientConfig,
    _dir: tempfile::TempDir,
}

impl Context {
    pub fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let ca = Arc::new(Ssl::load_or_generate(dir.path()).unwrap());
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from_pem_slice(&ca.ca_cert_pem()).unwrap())
            .unwrap();
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let (tx, events) = mpsc::channel(100);
        Self {
            ca,
            handler: CapturingHandler::new(tx),
            events,
            tls,
            _dir: dir,
        }
    }

    pub fn pool(&self) -> Arc<super::http1::NativePool> {
        Arc::new(super::http1::new_pool(
            super::outbound::OutboundConnector::new(None),
            Arc::new(self.tls.clone()),
        ))
    }
}

pub(super) fn request(method: Method, uri: &str) -> ProxyRequest {
    ProxyRequest::new(
        RequestHead::new(
            method,
            uri.parse::<Uri>().unwrap(),
            Version::HTTP_2,
            HeaderBlock::new(),
        ),
        ProxyBody::empty(),
    )
}
