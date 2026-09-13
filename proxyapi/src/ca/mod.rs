pub mod cert_server;

use std::{path::Path, sync::Arc, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;
use http::uri::Authority;
use moka::future::Cache;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio_rustls::rustls::ServerConfig;

const TTL_SECS: i64 = 365 * 24 * 60 * 60;
const CACHE_TTL: u64 = TTL_SECS as u64 / 2;
const NOT_BEFORE_OFFSET: i64 = 60;
const CA_TTL_SECS: i64 = 10 * 365 * 24 * 60 * 60;

#[async_trait]
pub trait CertificateAuthority: Send + Sync + 'static {
    async fn gen_server_config(
        &self,
        authority: &Authority,
    ) -> Result<Arc<ServerConfig>, crate::error::Error>;
}

#[cfg(feature = "http3")]
#[derive(Clone, Debug)]
pub(crate) struct H3Certificate {
    pub(crate) certificate_pem: Bytes,
    pub(crate) private_key_pem: Bytes,
}

struct GeneratedCertificate {
    certificate: CertificateDer<'static>,
    private_key_der: Vec<u8>,
    #[cfg(feature = "http3")]
    certificate_pem: Bytes,
    #[cfg(feature = "http3")]
    private_key_pem: Bytes,
}

#[derive(Clone)]
pub struct Ssl {
    issuer: Arc<Issuer<'static, KeyPair>>,
    ca_cert_pem: Bytes,
    cache: Cache<Authority, Arc<ServerConfig>>,
    #[cfg(feature = "http3")]
    h3_cache: moka::sync::Cache<Authority, Arc<H3Certificate>>,
}

impl Ssl {
    pub fn load_or_generate(dir: &Path) -> Result<Self, crate::error::Error> {
        std::fs::create_dir_all(dir)?;

        let cert_path = dir.join("proxelar-ca.pem");
        let key_path = dir.join("proxelar-ca.key");

        let (issuer, ca_cert_pem) = if cert_path.exists() && key_path.exists() {
            tracing::info!("Loading CA certificate from {}", dir.display());
            let key_pem = std::fs::read(&key_path)?;
            let cert_pem = std::fs::read(&cert_path)?;
            verify_certificate_key_pair(&cert_pem, &key_pem)?;

            let key_pem_str = std::str::from_utf8(&key_pem)
                .map_err(|error| crate::error::Error::Other(error.to_string()))?;
            let cert_pem_str = std::str::from_utf8(&cert_pem)
                .map_err(|error| crate::error::Error::Other(error.to_string()))?;
            let key_pair = KeyPair::from_pem(key_pem_str)?;
            let issuer = Issuer::from_ca_cert_pem(cert_pem_str, key_pair)?;
            (issuer, Bytes::from(cert_pem))
        } else {
            tracing::info!("Generating new CA certificate in {}", dir.display());
            let (issuer, cert_pem, key_pem) = generate_ca()?;

            std::fs::write(&key_path, key_pem.as_bytes())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
            }
            std::fs::write(&cert_path, cert_pem.as_bytes())?;

            (issuer, Bytes::from(cert_pem))
        };

        Ok(Self {
            issuer: Arc::new(issuer),
            ca_cert_pem,
            cache: Cache::builder()
                .max_capacity(1_000)
                .time_to_live(Duration::from_secs(CACHE_TTL))
                .build(),
            #[cfg(feature = "http3")]
            h3_cache: moka::sync::Cache::builder()
                .max_capacity(1_000)
                .time_to_live(Duration::from_secs(CACHE_TTL))
                .build(),
        })
    }

    pub fn ca_cert_pem(&self) -> Bytes {
        self.ca_cert_pem.clone()
    }

    fn gen_cert(&self, authority: &Authority) -> Result<GeneratedCertificate, crate::error::Error> {
        let host = authority.host();
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        let mut params = CertificateParams::new(vec![host.to_owned()])?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.use_authority_key_identifier_extension = true;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        params.not_before = OffsetDateTime::now_utc()
            .checked_sub(TimeDuration::seconds(NOT_BEFORE_OFFSET))
            .ok_or_else(|| crate::error::Error::Other("certificate validity underflow".into()))?;
        params.not_after = params
            .not_before
            .checked_add(TimeDuration::seconds(TTL_SECS))
            .ok_or_else(|| crate::error::Error::Other("certificate validity overflow".into()))?;

        // Every leaf gets its own key. Reusing the CA key would expose the root
        // of trust to every endpoint handshake.
        let leaf_key = KeyPair::generate()?;
        let certificate = params.signed_by(&leaf_key, self.issuer.as_ref())?;
        let private_key_der = leaf_key.serialize_der();

        Ok(GeneratedCertificate {
            certificate: certificate.der().clone(),
            private_key_der,
            #[cfg(feature = "http3")]
            certificate_pem: Bytes::from(certificate.pem()),
            #[cfg(feature = "http3")]
            private_key_pem: Bytes::from(leaf_key.serialize_pem()),
        })
    }

    #[cfg(feature = "http3")]
    pub(crate) fn gen_h3_certificate(
        &self,
        authority: &Authority,
    ) -> Result<Arc<H3Certificate>, crate::error::Error> {
        if let Some(certificate) = self.h3_cache.get(authority) {
            return Ok(certificate);
        }

        let generated = self.gen_cert(authority)?;
        let certificate = Arc::new(H3Certificate {
            certificate_pem: generated.certificate_pem,
            private_key_pem: generated.private_key_pem,
        });
        self.h3_cache
            .insert(authority.clone(), Arc::clone(&certificate));
        Ok(certificate)
    }
}

fn verify_certificate_key_pair(
    certificate_pem: &[u8],
    private_key_pem: &[u8],
) -> Result<(), crate::error::Error> {
    let certificate = CertificateDer::from_pem_slice(certificate_pem)
        .map_err(|error| crate::error::Error::Other(error.to_string()))?;
    let private_key = PrivateKeyDer::from_pem_slice(private_key_pem)
        .map_err(|error| crate::error::Error::Other(error.to_string()))?;
    let provider = rustls::crypto::ring::default_provider();
    rustls::sign::CertifiedKey::from_der(vec![certificate], private_key, &provider)?;
    Ok(())
}

fn generate_ca() -> Result<(Issuer<'static, KeyPair>, String, String), crate::error::Error> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "proxelar");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Proxelar");
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    params.not_before = OffsetDateTime::now_utc()
        .checked_sub(TimeDuration::seconds(NOT_BEFORE_OFFSET))
        .ok_or_else(|| crate::error::Error::Other("CA validity underflow".into()))?;
    params.not_after = params
        .not_before
        .checked_add(TimeDuration::seconds(CA_TTL_SECS))
        .ok_or_else(|| crate::error::Error::Other("CA validity overflow".into()))?;

    let key_pair = KeyPair::generate()?;
    let certificate = params.self_signed(&key_pair)?;
    let certificate_pem = certificate.pem();
    let private_key_pem = key_pair.serialize_pem();
    Ok((
        Issuer::new(params, key_pair),
        certificate_pem,
        private_key_pem,
    ))
}

#[async_trait]
impl CertificateAuthority for Ssl {
    async fn gen_server_config(
        &self,
        authority: &Authority,
    ) -> Result<Arc<ServerConfig>, crate::error::Error> {
        if let Some(server_cfg) = self.cache.get(authority).await {
            tracing::debug!("Using cached server config for {authority}");
            return Ok(server_cfg);
        }
        tracing::debug!("Generating server config for {authority}");

        let generated = self.gen_cert(authority)?;
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(generated.private_key_der));
        let mut server_cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![generated.certificate], private_key)?;

        server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let server_cfg = Arc::new(server_cfg);

        self.cache
            .insert(authority.clone(), Arc::clone(&server_cfg))
            .await;
        Ok(server_cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minted_leaf_uses_a_distinct_matching_private_key() {
        let directory = tempfile::tempdir().unwrap();
        let ssl = Ssl::load_or_generate(directory.path()).unwrap();
        let authority: Authority = "api.example.test:443".parse().unwrap();

        let first = ssl.gen_cert(&authority).unwrap();
        let second = ssl.gen_cert(&authority).unwrap();
        let provider = rustls::crypto::ring::default_provider();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(first.private_key_der.clone()));
        rustls::sign::CertifiedKey::from_der(vec![first.certificate], key, &provider).unwrap();

        assert_ne!(first.private_key_der, second.private_key_der);
    }

    #[test]
    fn minted_ip_leaf_uses_an_ip_subject_alternative_name() {
        use x509_parser::extensions::GeneralName;

        let directory = tempfile::tempdir().unwrap();
        let ssl = Ssl::load_or_generate(directory.path()).unwrap();
        let authority: Authority = "127.0.0.1:443".parse().unwrap();

        let generated = ssl.gen_cert(&authority).unwrap();
        let (_, leaf) =
            x509_parser::parse_x509_certificate(generated.certificate.as_ref()).unwrap();
        let names = leaf.subject_alternative_name().unwrap().unwrap();

        assert!(names
            .value
            .general_names
            .iter()
            .any(|name| matches!(name, GeneralName::IPAddress(bytes) if *bytes == [127, 0, 0, 1])));
        assert!(names
            .value
            .general_names
            .iter()
            .all(|name| !matches!(name, GeneralName::DNSName(_))));
    }

    #[cfg(feature = "http3")]
    #[tokio::test]
    async fn h3_certificate_material_is_cached_as_pem() {
        let directory = tempfile::tempdir().unwrap();
        let ssl = Ssl::load_or_generate(directory.path()).unwrap();
        let authority: Authority = "api.example.test:443".parse().unwrap();

        let first = ssl.gen_h3_certificate(&authority).unwrap();
        let second = ssl.gen_h3_certificate(&authority).unwrap();

        assert!(Arc::ptr_eq(&first, &second));
        assert!(first
            .certificate_pem
            .starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(first
            .private_key_pem
            .starts_with(b"-----BEGIN PRIVATE KEY-----"));
    }
}
