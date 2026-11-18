pub mod cert_server;

use std::{path::Path, sync::Arc, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;
use http::uri::Authority;
use moka::future::Cache;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, DnValue, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose,
};
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio_rustls::rustls::ServerConfig;
use x509_parser::{der_parser::asn1_rs::Tag, extensions::ParsedExtension, prelude::FromDer as _};

const TTL_SECS: i64 = 365 * 24 * 60 * 60;
const CACHE_TTL: u64 = TTL_SECS as u64 / 2;
const NOT_BEFORE_OFFSET: i64 = 60;
const CA_TTL_SECS: i64 = 10 * 365 * 24 * 60 * 60;
const LEGACY_CA_BACKUP: &str = "proxelar-ca.legacy.pem";

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

            // Roots written by older releases have no Subject Key Identifier,
            // which strict verifiers (Python 3.13+) reject. Re-issue the
            // certificate around the same key instead of minting a new root, so
            // clients that already trust the old certificate keep working.
            let cert_pem = match reissue_with_subject_key_identifier(cert_pem_str, &key_pair) {
                Ok(Some(reissued_pem)) => {
                    verify_certificate_key_pair(reissued_pem.as_bytes(), &key_pem)?;
                    let backup_path = dir.join(LEGACY_CA_BACKUP);
                    std::fs::write(&backup_path, &cert_pem)?;
                    replace_file(&cert_path, reissued_pem.as_bytes())?;
                    tracing::warn!(
                        "Re-issued the CA certificate in {} with a Subject Key Identifier \
                         (same key and subject; previous certificate kept as {}). \
                         Clients that already trust the old certificate keep working; \
                         clients that verify in strict X.509 mode must trust the new one.",
                        dir.display(),
                        LEGACY_CA_BACKUP,
                    );
                    reissued_pem.into_bytes()
                }
                Ok(None) => cert_pem,
                Err(error) => {
                    tracing::warn!(
                        "CA certificate in {} has no Subject Key Identifier and could not \
                         be re-issued ({error}); strict X.509 verifiers will reject it",
                        dir.display(),
                    );
                    cert_pem
                }
            };
            let cert_pem_str = std::str::from_utf8(&cert_pem)
                .map_err(|error| crate::error::Error::Other(error.to_string()))?;
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

/// Re-issues a root certificate that lacks a Subject Key Identifier.
///
/// Returns `Ok(None)` when the certificate already has the extension, or when
/// it is not a root in the shape Proxelar itself generates (self-signed, CA,
/// no extensions beyond Basic Constraints and Key Usage). A certificate the
/// user supplied with anything else in it is left untouched.
///
/// The new certificate keeps the key, subject, validity, key usages and path
/// length of the old one, so it is interchangeable with it as a trust anchor:
/// leaves chain to either. Only the serial number, the signature and the added
/// extension differ.
fn reissue_with_subject_key_identifier(
    certificate_pem: &str,
    key_pair: &KeyPair,
) -> Result<Option<String>, crate::error::Error> {
    let other = |message: &str| crate::error::Error::Other(message.to_owned());
    let old_der = CertificateDer::from_pem_slice(certificate_pem.as_bytes())
        .map_err(|error| crate::error::Error::Other(error.to_string()))?;
    let (_, old) = x509_parser::certificate::X509Certificate::from_der(old_der.as_ref())
        .map_err(|error| crate::error::Error::Other(error.to_string()))?;

    let mut path_len = None;
    let mut is_ca = false;
    for extension in old.extensions() {
        match extension.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(_) => return Ok(None),
            ParsedExtension::BasicConstraints(constraints) => {
                is_ca = constraints.ca;
                path_len = constraints.path_len_constraint;
            }
            ParsedExtension::KeyUsage(_) => {}
            _ => return Ok(None),
        }
    }
    if !is_ca || old.subject().as_raw() != old.issuer().as_raw() {
        return Ok(None);
    }

    let issuer = Issuer::from_ca_cert_der(&old_der, key_pair)?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(match path_len {
        Some(length) => BasicConstraints::Constrained(
            u8::try_from(length).map_err(|_| other("CA path length out of range"))?,
        ),
        None => BasicConstraints::Unconstrained,
    });
    params.distinguished_name = rcgen::DistinguishedName::new();
    for attribute in old.subject().iter_attributes() {
        let oid = attribute
            .attr_type()
            .iter()
            .ok_or_else(|| other("unsupported CA subject attribute"))?
            .collect::<Vec<_>>();
        let text = std::str::from_utf8(attribute.attr_value().data)
            .map_err(|_| other("unsupported CA subject encoding"))?;
        let value = match attribute.attr_value().header.tag() {
            Tag::Utf8String => DnValue::Utf8String(text.to_owned()),
            Tag::PrintableString => DnValue::PrintableString(text.try_into()?),
            _ => return Err(other("unsupported CA subject encoding")),
        };
        params
            .distinguished_name
            .push(DnType::from_oid(&oid), value);
    }
    params.key_usages = issuer.key_usages().to_vec();
    params.not_before = old.validity().not_before.to_datetime();
    params.not_after = old.validity().not_after.to_datetime();

    let reissued = params.self_signed(key_pair)?;
    let (_, new) = x509_parser::certificate::X509Certificate::from_der(reissued.der().as_ref())
        .map_err(|error| crate::error::Error::Other(error.to_string()))?;
    // Verifiers that match names byte for byte (webpki) must still chain
    // leaves to the old certificate, so the subject encoding may not change.
    if new.subject().as_raw() != old.subject().as_raw() {
        return Err(other("re-issued CA subject differs from the original"));
    }
    Ok(Some(reissued.pem()))
}

/// Writes `contents` to `path` through a sibling temporary file, so a crash
/// cannot leave a truncated CA certificate behind.
fn replace_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let temporary = path.with_extension("pem.tmp");
    std::fs::write(&temporary, contents)?;
    std::fs::rename(&temporary, path)
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

    fn subject_key_identifier(der: &[u8]) -> Option<Vec<u8>> {
        let (_, certificate) = x509_parser::parse_x509_certificate(der).unwrap();
        certificate
            .extensions()
            .iter()
            .find_map(|extension| match extension.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(id) => Some(id.0.to_vec()),
                _ => None,
            })
    }

    fn authority_key_identifier(der: &[u8]) -> Option<Vec<u8>> {
        let (_, certificate) = x509_parser::parse_x509_certificate(der).unwrap();
        certificate
            .extensions()
            .iter()
            .find_map(|extension| match extension.parsed_extension() {
                ParsedExtension::AuthorityKeyIdentifier(id) => {
                    id.key_identifier.as_ref().map(|id| id.0.to_vec())
                }
                _ => None,
            })
    }

    fn pem_to_der(pem: &[u8]) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(pem).unwrap()
    }

    /// Writes a root shaped like the ones older releases generated: Basic
    /// Constraints and Key Usage only, no Subject Key Identifier.
    fn write_legacy_ca(dir: &Path) -> Vec<u8> {
        let mut subject = rcgen::DistinguishedName::new();
        subject.push(DnType::CommonName, "proxelar");
        subject.push(DnType::OrganizationName, "Proxelar");
        // `SEQUENCE { BOOLEAN TRUE }`: a CA with no path length constraint.
        write_root_without_key_identifier(dir, vec![0x30, 0x03, 0x01, 0x01, 0xff], subject)
    }

    /// Writes a self-signed root with only the given Basic Constraints value
    /// and Key Usage, and returns its DER.
    fn write_root_without_key_identifier(
        dir: &Path,
        basic_constraints: Vec<u8>,
        subject: rcgen::DistinguishedName,
    ) -> Vec<u8> {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        // rcgen always adds a Subject Key Identifier to a CA, so Basic
        // Constraints is written by hand.
        let mut basic_constraints =
            rcgen::CustomExtension::from_oid_content(&[2, 5, 29, 19], basic_constraints);
        basic_constraints.set_criticality(true);
        params.custom_extensions.push(basic_constraints);
        params.distinguished_name = subject;
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key_pair = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key_pair).unwrap();
        std::fs::write(dir.join("proxelar-ca.pem"), certificate.pem()).unwrap();
        std::fs::write(dir.join("proxelar-ca.key"), key_pair.serialize_pem()).unwrap();
        certificate.der().to_vec()
    }

    #[test]
    fn generated_ca_has_a_subject_key_identifier_matching_leaf_authority_key_identifier() {
        let directory = tempfile::tempdir().unwrap();
        let ssl = Ssl::load_or_generate(directory.path()).unwrap();

        let ca = pem_to_der(&std::fs::read(directory.path().join("proxelar-ca.pem")).unwrap());
        let ca_key_id = subject_key_identifier(&ca).expect("CA has no Subject Key Identifier");
        assert!(!ca_key_id.is_empty());

        let leaf = ssl
            .gen_cert(&"api.example.test:443".parse().unwrap())
            .unwrap();
        assert_eq!(authority_key_identifier(&leaf.certificate), Some(ca_key_id));
    }

    #[test]
    fn legacy_ca_without_subject_key_identifier_is_reissued_around_the_same_key() {
        let directory = tempfile::tempdir().unwrap();
        let legacy = write_legacy_ca(directory.path());
        assert_eq!(subject_key_identifier(&legacy), None);
        let key_before = std::fs::read(directory.path().join("proxelar-ca.key")).unwrap();

        let ssl = Ssl::load_or_generate(directory.path()).unwrap();

        let cert_pem = std::fs::read(directory.path().join("proxelar-ca.pem")).unwrap();
        let reissued = pem_to_der(&cert_pem);
        let ca_key_id = subject_key_identifier(&reissued).expect("CA was not re-issued");
        assert_eq!(ssl.ca_cert_pem(), cert_pem);
        assert_eq!(
            std::fs::read(directory.path().join("proxelar-ca.key")).unwrap(),
            key_before
        );
        assert_eq!(
            pem_to_der(&std::fs::read(directory.path().join(LEGACY_CA_BACKUP)).unwrap()).as_ref(),
            legacy.as_slice()
        );

        let (_, old) = x509_parser::parse_x509_certificate(&legacy).unwrap();
        let (_, new) = x509_parser::parse_x509_certificate(&reissued).unwrap();
        assert_eq!(new.subject().as_raw(), old.subject().as_raw());
        assert_eq!(new.public_key().raw, old.public_key().raw);
        assert_eq!(new.validity(), old.validity());
        assert!(new.basic_constraints().unwrap().unwrap().value.ca);
        assert_eq!(
            new.key_usage().unwrap().unwrap().value.flags,
            old.key_usage().unwrap().unwrap().value.flags
        );

        // A leaf chains to the new certificate and, for clients that trusted
        // the root before the upgrade, to the old one as well.
        let leaf = ssl
            .gen_cert(&"api.example.test:443".parse().unwrap())
            .unwrap();
        assert_eq!(authority_key_identifier(&leaf.certificate), Some(ca_key_id));
        let (_, leaf) = x509_parser::parse_x509_certificate(&leaf.certificate).unwrap();
        assert_eq!(leaf.issuer().as_raw(), old.subject().as_raw());
        leaf.verify_signature(Some(old.public_key())).unwrap();

        // The second start finds a compliant certificate and leaves it alone.
        Ssl::load_or_generate(directory.path()).unwrap();
        assert_eq!(
            std::fs::read(directory.path().join("proxelar-ca.pem")).unwrap(),
            cert_pem
        );
    }

    #[test]
    fn ca_with_other_extensions_is_not_rewritten() {
        let directory = tempfile::tempdir().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        let mut basic_constraints = rcgen::CustomExtension::from_oid_content(
            &[2, 5, 29, 19],
            vec![0x30, 0x03, 0x01, 0x01, 0xff],
        );
        basic_constraints.set_criticality(true);
        params.custom_extensions.push(basic_constraints);
        params
            .distinguished_name
            .push(DnType::CommonName, "corporate root");
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        let key_pair = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key_pair).unwrap();
        let cert_path = directory.path().join("proxelar-ca.pem");
        std::fs::write(&cert_path, certificate.pem()).unwrap();
        std::fs::write(
            directory.path().join("proxelar-ca.key"),
            key_pair.serialize_pem(),
        )
        .unwrap();

        Ssl::load_or_generate(directory.path()).unwrap();

        assert_eq!(
            std::fs::read(&cert_path).unwrap(),
            certificate.pem().as_bytes()
        );
        assert!(!directory.path().join(LEGACY_CA_BACKUP).exists());
    }

    #[test]
    fn legacy_ca_path_length_and_printable_subject_survive_reissue() {
        let directory = tempfile::tempdir().unwrap();
        let mut subject = rcgen::DistinguishedName::new();
        subject.push(
            DnType::CommonName,
            DnValue::PrintableString("proxelar".try_into().unwrap()),
        );
        // `SEQUENCE { BOOLEAN TRUE, INTEGER 0 }`: a CA with pathLen 0.
        let legacy = write_root_without_key_identifier(
            directory.path(),
            vec![0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00],
            subject,
        );

        Ssl::load_or_generate(directory.path()).unwrap();

        let reissued =
            pem_to_der(&std::fs::read(directory.path().join("proxelar-ca.pem")).unwrap());
        assert!(subject_key_identifier(&reissued).is_some());
        let (_, old) = x509_parser::parse_x509_certificate(&legacy).unwrap();
        let (_, new) = x509_parser::parse_x509_certificate(&reissued).unwrap();
        assert_eq!(new.subject().as_raw(), old.subject().as_raw());
        let constraints = new.basic_constraints().unwrap().unwrap().value;
        assert!(constraints.ca);
        assert_eq!(constraints.path_len_constraint, Some(0));
    }

    #[test]
    fn legacy_ca_with_unsupported_subject_encoding_is_kept_as_is() {
        let directory = tempfile::tempdir().unwrap();
        let mut subject = rcgen::DistinguishedName::new();
        subject.push(
            DnType::CommonName,
            DnValue::Ia5String("proxelar".try_into().unwrap()),
        );
        let legacy = write_root_without_key_identifier(
            directory.path(),
            vec![0x30, 0x03, 0x01, 0x01, 0xff],
            subject,
        );

        let ssl = Ssl::load_or_generate(directory.path()).unwrap();

        let cert_pem = std::fs::read(directory.path().join("proxelar-ca.pem")).unwrap();
        assert_eq!(pem_to_der(&cert_pem).as_ref(), legacy.as_slice());
        assert_eq!(ssl.ca_cert_pem(), cert_pem);
        assert!(!directory.path().join(LEGACY_CA_BACKUP).exists());
    }

    #[test]
    fn non_ca_certificate_is_not_reissued() {
        let directory = tempfile::tempdir().unwrap();
        let mut subject = rcgen::DistinguishedName::new();
        subject.push(DnType::CommonName, "proxelar");
        // `SEQUENCE {}`: Basic Constraints with the CA flag left at FALSE.
        write_root_without_key_identifier(directory.path(), vec![0x30, 0x00], subject);
        let cert_pem = std::fs::read(directory.path().join("proxelar-ca.pem")).unwrap();
        let key_pair = KeyPair::from_pem(
            &std::fs::read_to_string(directory.path().join("proxelar-ca.key")).unwrap(),
        )
        .unwrap();

        let reissued =
            reissue_with_subject_key_identifier(std::str::from_utf8(&cert_pem).unwrap(), &key_pair)
                .unwrap();

        assert_eq!(reissued, None);
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
