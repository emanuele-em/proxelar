use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use rama::crypto::native_certs::bundled_root_certs;
use rama::crypto::pki_types::{pem::PemObject, CertificateDer};
use rama::tls::client::{ServerVerifyMode, TlsClientConfig};

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

/// Translate the upstream trust policy into a rama BoringSSL client TLS config.
///
/// rama's trust anchors *replace* the verify store rather than augmenting it, so
/// the "default + extra CA" policy is reproduced by concatenating the bundled
/// WebPKI roots with the extra CA file.
pub(super) fn build_client_tls_config(
    config: &UpstreamTlsConfig,
) -> Result<TlsClientConfig, Error> {
    match config {
        UpstreamTlsConfig::Default => Ok(TlsClientConfig::default_http()),
        UpstreamTlsConfig::DefaultWithCaFile(path) => {
            let mut anchors: Vec<CertificateDer<'static>> = bundled_root_certs().to_vec();
            anchors.extend(load_ca_file_roots(path)?);
            TlsClientConfig::default_http()
                .try_with_server_trust_anchors(anchors)
                .map_err(|error| Error::Tls(error.to_string()))
        }
        UpstreamTlsConfig::CaFileOnly(path) => TlsClientConfig::default_http()
            .try_with_server_trust_anchors(load_ca_file_roots(path)?)
            .map_err(|error| Error::Tls(error.to_string())),
        UpstreamTlsConfig::Insecure => {
            Ok(TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable))
        }
    }
}

fn load_ca_file_roots(path: &Path) -> Result<Vec<CertificateDer<'static>>, Error> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|error| Error::Other(format!("failed to read CA file: {error}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| Error::Other(format!("failed to parse PEM certificate: {error}")))?;

    if certs.is_empty() {
        return Err(Error::Other(format!(
            "no usable CA certificates found in {}",
            path.display()
        )));
    }

    Ok(certs)
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
}
