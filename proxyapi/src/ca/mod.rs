pub mod cert_server;

use std::{num::NonZeroU64, path::Path, time::Duration};

use rama::bytes::Bytes;
use rama::crypto::dep::boring::{pkey::PKey, x509::X509};
use rama::crypto::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rama::error::{BoxError, ErrorContext};
use rama::net::address::Host;
use rama::telemetry::tracing;
use rama::tls::boring::proxy::{
    cert_issuer::{
        BoringMitmCertIssuerCacheConfig, CachedBoringMitmCertIssuer, InMemoryBoringMitmCertIssuer,
    },
    TlsMitmEgressServerAuth, TlsMitmRelay,
};
use rama::tls::boring::server::{
    BoringServerConfigExt as _, CacheKind, ServerCertIssuerData, ServerCertIssuerKind,
};
use rama::tls::server::{
    CertificateAuthorityData, CertificateIdentity, CertificateKeyKind, CertificateSubject,
    CertificateValidity, LeafCertConfig, SelfSignedCaConfig, TlsServerConfig,
};

/// Per-host MITM leaf validity: one year, back-dated slightly for clock skew.
const LEAF_LIFETIME: Duration = Duration::from_secs(365 * 24 * 60 * 60);
const NOT_BEFORE_SKEW: Duration = Duration::from_secs(60);
const LEAF_CACHE_MAX_SIZE: NonZeroU64 =
    NonZeroU64::new(1_000).expect("leaf cache size is non-zero");
const LEAF_CACHE_TTL: Duration = Duration::from_secs(365 * 24 * 60 * 60 / 2);

/// A persistent local certificate authority that mints per-host leaf
/// certificates for MITM interception.
///
/// Rama owns issuance and bounded caching. The default relay issuer mirrors the
/// origin certificate; the provided-CA server issuer supports the explicit
/// HTTP-version adapter path. This type owns both over the same persistent CA.
#[derive(Clone)]
pub struct Ssl {
    ca_cert_pem: Bytes,
    issuer: ServerCertIssuerData,
    relay_issuer: CachedBoringMitmCertIssuer<InMemoryBoringMitmCertIssuer>,
}

impl Ssl {
    /// Load the persistent `proxelar-ca.pem`/`.key` pair from `dir`, generating
    /// and persisting a fresh CA (chmod 600 on the key) when absent.
    pub fn load_or_generate(dir: &Path) -> Result<Self, crate::error::Error> {
        Self::load_or_generate_inner(dir)
            .map_err(|error| crate::error::Error::Tls(error.to_string()))
    }

    fn load_or_generate_inner(dir: &Path) -> Result<Self, BoxError> {
        std::fs::create_dir_all(dir).context("create CA directory")?;

        let cert_path = dir.join("proxelar-ca.pem");
        let key_path = dir.join("proxelar-ca.key");

        let ca = if cert_path.exists() && key_path.exists() {
            tracing::info!("Loading CA certificate from {}", dir.display());
            let cert_pem = std::fs::read(&cert_path).context("read CA certificate")?;
            let key_pem = std::fs::read(&key_path).context("read CA private key")?;
            ca_from_pem(&cert_pem, &key_pem)?
        } else {
            tracing::info!("Generating new CA certificate in {}", dir.display());
            let ca = CertificateAuthorityData::generate(SelfSignedCaConfig {
                subject: CertificateSubject {
                    organisation_name: Some("Proxelar".to_owned()),
                    common_name: Some("proxelar".to_owned()),
                },
                ..Default::default()
            })
            .context("generate CA")?;

            let (cert_pem, key_pem) = ca_to_pem(&ca)?;
            std::fs::write(&key_path, &key_pem).context("write CA private key")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                    .context("chmod CA private key")?;
            }
            std::fs::write(&cert_path, &cert_pem).context("write CA certificate")?;
            ca
        };

        let ca_cert_pem = Bytes::from(ca_to_pem(&ca)?.0);
        let (ca_cert, ca_key) = ca_to_boring_pair(&ca)?;

        // A ProvidedCa issuer mints per-identity leaves from our CA and caches
        // them (bounded, in-memory). Leaves carry a 1-year validity and an IP or
        // DNS SAN derived from the connection identity.
        let issuer = ServerCertIssuerData::new(ServerCertIssuerKind::ProvidedCa {
            ca,
            leaf: LeafCertConfig {
                subject: CertificateSubject::default(),
                validity: CertificateValidity::new(LEAF_LIFETIME, NOT_BEFORE_SKEW),
                key_kind: CertificateKeyKind::EcP256,
            },
        })
        .with_cache_kind(CacheKind::MemCache {
            max_size: LEAF_CACHE_MAX_SIZE,
            ttl: Some(LEAF_CACHE_TTL),
        });

        let relay_issuer = CachedBoringMitmCertIssuer::new_with_config(
            InMemoryBoringMitmCertIssuer::new(ca_cert, ca_key),
            relay_cache_config(),
        );

        Ok(Self {
            ca_cert_pem,
            issuer,
            relay_issuer,
        })
    }

    /// The CA certificate in PEM form, served by the certificate install page.
    pub fn ca_cert_pem(&self) -> Bytes {
        self.ca_cert_pem.clone()
    }

    /// Build a BoringSSL server TLS config that issues (and caches) a leaf
    /// certificate for `host` on demand.
    ///
    /// The issuer prefers the client's SNI; `host` (the known tunnel target) is
    /// the fallback identity, which is what lets it serve an IP-SAN leaf for an
    /// IP target that carries no SNI. The issuer clone shares the CA material and
    /// leaf cache with every other tunnel.
    pub(crate) fn tls_server_config(&self, host: &Host) -> TlsServerConfig {
        let issuer = self
            .issuer
            .clone()
            .maybe_with_fallback_identity(CertificateIdentity::try_from_host(host).ok());
        TlsServerConfig::new()
            .with_cert_issuer(issuer)
            .with_alpn_http_auto()
    }

    /// Build rama's TLS relay with the persistent CA and Proxelar's upstream
    /// authentication policy. The issuer mirrors the origin leaf and shares a
    /// bounded cache across all intercepted connections.
    pub(crate) fn tls_mitm_relay(
        &self,
        egress_server_auth: TlsMitmEgressServerAuth,
    ) -> TlsMitmRelay<CachedBoringMitmCertIssuer<InMemoryBoringMitmCertIssuer>> {
        TlsMitmRelay::new(self.relay_issuer.clone()).with_egress_server_auth(egress_server_auth)
    }
}

fn relay_cache_config() -> BoringMitmCertIssuerCacheConfig {
    BoringMitmCertIssuerCacheConfig {
        max_size: LEAF_CACHE_MAX_SIZE,
        ttl: Some(LEAF_CACHE_TTL),
    }
}

/// Reconstruct rama CA material from a stored PEM cert + key pair.
fn ca_from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<CertificateAuthorityData, BoxError> {
    let cert = X509::from_pem(cert_pem).context("parse CA certificate")?;
    let key = PKey::private_key_from_pem(key_pem).context("parse CA private key")?;
    let cert_der = CertificateDer::from(cert.to_der().context("serialize CA certificate to DER")?);
    let key_der: PrivateKeyDer<'static> = PrivatePkcs8KeyDer::from(
        key.private_key_to_der_pkcs8()
            .context("serialize CA private key to PKCS#8 DER")?,
    )
    .into();
    CertificateAuthorityData::try_new(vec![cert_der], key_der)
}

/// Serialize rama CA material to a PEM cert + key pair (issuing cert first).
fn ca_to_pem(ca: &CertificateAuthorityData) -> Result<(Vec<u8>, Vec<u8>), BoxError> {
    let cert_der = ca
        .certificate_chain()
        .first()
        .ok_or_else(|| BoxError::from("CA chain is empty".to_owned()))?;
    let cert_pem = X509::from_der(cert_der.as_ref())
        .context("parse CA certificate DER")?
        .to_pem()
        .context("serialize CA certificate to PEM")?;
    let key_pem = PKey::private_key_from_der(ca.private_key().secret_der())
        .context("parse CA private key DER")?
        .private_key_to_pem_pkcs8()
        .context("serialize CA private key to PEM")?;
    Ok((cert_pem, key_pem))
}

fn ca_to_boring_pair(
    ca: &CertificateAuthorityData,
) -> Result<(X509, PKey<rama::crypto::dep::boring::pkey::Private>), BoxError> {
    let cert_der = ca
        .certificate_chain()
        .first()
        .ok_or_else(|| BoxError::from("CA chain is empty".to_owned()))?;
    let cert = X509::from_der(cert_der.as_ref()).context("parse CA certificate DER")?;
    let key = PKey::private_key_from_der(ca.private_key().secret_der())
        .context("parse CA private key DER")?;
    Ok((cert, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_cert_pem_round_trips() {
        let directory = tempfile::tempdir().unwrap();
        let ssl = Ssl::load_or_generate(directory.path()).unwrap();
        assert!(ssl
            .ca_cert_pem()
            .starts_with(b"-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn ca_is_reloaded_from_disk_across_instances() {
        let directory = tempfile::tempdir().unwrap();
        let first = Ssl::load_or_generate(directory.path()).unwrap();
        let second = Ssl::load_or_generate(directory.path()).unwrap();
        // The second instance reloads the persisted CA rather than regenerating.
        assert_eq!(first.ca_cert_pem(), second.ca_cert_pem());
    }

    #[test]
    fn leaf_cache_preserves_proxelar_limits() {
        let directory = tempfile::tempdir().unwrap();
        let ssl = Ssl::load_or_generate(directory.path()).unwrap();

        match ssl.issuer.cache_kind() {
            CacheKind::MemCache { max_size, ttl } => {
                assert_eq!(*max_size, LEAF_CACHE_MAX_SIZE);
                assert_eq!(*ttl, Some(LEAF_CACHE_TTL));
            }
            CacheKind::Disabled => panic!("leaf certificate cache must be enabled"),
        }

        let relay = relay_cache_config();
        assert_eq!(relay.max_size, LEAF_CACHE_MAX_SIZE);
        assert_eq!(relay.ttl, Some(LEAF_CACHE_TTL));
    }

    #[test]
    fn tls_server_config_builds_for_dns_and_ip_targets() {
        let directory = tempfile::tempdir().unwrap();
        let ssl = Ssl::load_or_generate(directory.path()).unwrap();
        // Both a DNS target and a (no-SNI) IP target yield a usable acceptor
        // config; the IP path is what requires an IP-SAN fallback identity.
        let _dns = ssl.tls_server_config(&Host::try_from("api.example.test").unwrap());
        let _ip = ssl.tls_server_config(&Host::try_from("127.0.0.1").unwrap());
    }
}
