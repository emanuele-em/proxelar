use std::{
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, ConfigBuilder, DigitallySignedStruct, RootCertStore, SignatureScheme,
    WantsVerifier,
};
use rustls_pki_types::pem::{self, PemObject};

use crate::error::Error;

/// Upstream server TLS trust policy.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum UpstreamTlsConfig {
    /// Trust the bundled Mozilla/WebPKI roots.
    #[default]
    Default,
    /// Trust the bundled Mozilla/WebPKI roots plus the supplied PEM CA file.
    DefaultWithCaFile(PathBuf),
    /// Trust only the supplied PEM CA file.
    CaFileOnly(PathBuf),
    /// Disable upstream certificate and hostname validation.
    Insecure,
}

impl FromStr for UpstreamTlsConfig {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        if value == "default" {
            return Ok(Self::Default);
        }
        if value == "insecure" {
            return Ok(Self::Insecure);
        }
        if let Some(path) = value.strip_prefix("default+ca:") {
            return path_to_policy(path, Self::DefaultWithCaFile);
        }
        if let Some(path) = value.strip_prefix("ca-only:") {
            return path_to_policy(path, Self::CaFileOnly);
        }

        Err("expected `default`, `default+ca:/path/to/ca.pem`, `ca-only:/path/to/ca.pem`, or `insecure`".to_owned())
    }
}

impl UpstreamTlsConfig {
    pub(crate) fn is_insecure(&self) -> bool {
        matches!(self, Self::Insecure)
    }
}

fn path_to_policy(
    path: &str,
    make_policy: impl FnOnce(PathBuf) -> UpstreamTlsConfig,
) -> Result<UpstreamTlsConfig, String> {
    let path = path.trim();
    if path.is_empty() {
        return Err("CA file path must not be empty".to_owned());
    }
    Ok(make_policy(PathBuf::from(path)))
}

pub(super) fn build_client_config(config: &UpstreamTlsConfig) -> Result<ClientConfig, Error> {
    match config {
        UpstreamTlsConfig::Default => Ok(client_config_builder()?
            .with_root_certificates(default_root_store())
            .with_no_client_auth()),
        UpstreamTlsConfig::DefaultWithCaFile(path) => {
            let mut roots = default_root_store();
            append_ca_file_roots(&mut roots, path)?;
            Ok(client_config_builder()?
                .with_root_certificates(roots)
                .with_no_client_auth())
        }
        UpstreamTlsConfig::CaFileOnly(path) => Ok(client_config_builder()?
            .with_root_certificates(load_ca_file_roots(path)?)
            .with_no_client_auth()),
        UpstreamTlsConfig::Insecure => {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            Ok(
                rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
                    .with_safe_default_protocol_versions()?
                    .dangerous()
                    .with_custom_certificate_verifier(InsecureServerCertVerifier::new(provider))
                    .with_no_client_auth(),
            )
        }
    }
}

fn client_config_builder() -> Result<ConfigBuilder<ClientConfig, WantsVerifier>, rustls::Error> {
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
}

fn default_root_store() -> RootCertStore {
    RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
}

fn append_ca_file_roots(roots: &mut RootCertStore, path: &Path) -> Result<(), Error> {
    let ca_roots = load_ca_file_roots(path)?;
    roots.roots.extend(ca_roots.roots);
    Ok(())
}

fn load_ca_file_roots(path: &Path) -> Result<RootCertStore, Error> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(map_pem_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_pem_error)?;

    let mut roots = RootCertStore::empty();
    let (valid_count, invalid_count) = roots.add_parsable_certificates(certs);
    if valid_count == 0 {
        return Err(Error::Other(format!(
            "no usable CA certificates found in {}",
            path.display()
        )));
    }
    if invalid_count > 0 {
        tracing::warn!(
            "Ignored {invalid_count} invalid CA certificate(s) while loading {}",
            path.display()
        );
    }

    Ok(roots)
}

fn map_pem_error(err: pem::Error) -> Error {
    match err {
        pem::Error::Io(err) => Error::Io(err),
        err => Error::Other(format!("failed to parse PEM certificate: {err}")),
    }
}

/// Skips certificate chain and hostname checks while retaining Rustls handshake signature checks.
#[derive(Debug)]
struct InsecureServerCertVerifier(Arc<CryptoProvider>);

impl InsecureServerCertVerifier {
    fn new(provider: Arc<CryptoProvider>) -> Arc<Self> {
        Arc::new(Self(provider))
    }
}

impl ServerCertVerifier for InsecureServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::Ssl;

    #[test]
    fn load_ca_file_roots_accepts_valid_pem() {
        let ca_dir = tempfile::tempdir().unwrap();
        let ssl = Ssl::load_or_generate(ca_dir.path()).unwrap();
        let ca_file = ca_dir.path().join("upstream-ca.pem");
        std::fs::write(&ca_file, ssl.ca_cert_pem()).unwrap();

        let roots = load_ca_file_roots(&ca_file).unwrap();

        assert_eq!(roots.len(), 1);
    }

    #[test]
    fn load_ca_file_roots_rejects_empty_pem() {
        let ca_dir = tempfile::tempdir().unwrap();
        let ca_file = ca_dir.path().join("empty.pem");
        std::fs::write(&ca_file, "").unwrap();

        let err = load_ca_file_roots(&ca_file).unwrap_err();

        assert!(err.to_string().contains("no usable CA certificates"));
    }

    #[test]
    fn load_ca_file_roots_rejects_invalid_pem() {
        let ca_dir = tempfile::tempdir().unwrap();
        let ca_file = ca_dir.path().join("invalid.pem");
        std::fs::write(
            &ca_file,
            "-----BEGIN CERTIFICATE-----\naW52YWxpZA==\n-----END CERTIFICATE-----\n",
        )
        .unwrap();

        let err = load_ca_file_roots(&ca_file).unwrap_err();

        assert!(err.to_string().contains("no usable CA certificates"));
    }

    #[test]
    fn load_ca_file_roots_rejects_missing_file() {
        let ca_dir = tempfile::tempdir().unwrap();
        let ca_file = ca_dir.path().join("missing.pem");

        let err = load_ca_file_roots(&ca_file).unwrap_err();

        assert!(matches!(err, Error::Io(_)));
    }
}
