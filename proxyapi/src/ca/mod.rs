pub mod cert_server;

use rama::telemetry::tracing;
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use rama::bytes::Bytes;

use rama::crypto::cert::boring::self_signed_server_auth_gen_ca;
use rama::crypto::dep::boring::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{
        extension::{BasicConstraints, KeyUsage, SubjectAlternativeName, SubjectKeyIdentifier},
        X509NameBuilder, X509,
    },
};
use rama::crypto::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rama::error::{BoxError, ErrorContext};
use rama::net::address::{Domain, Host};
use rama::tls::boring::server::{BoringServerConfigExt as _, CacheKind, ServerCertIssuerData};
use rama::tls::client::ClientHello;
use rama::tls::server::{DynamicCertIssuer, SelfSignedData, ServerAuthData, TlsServerConfig};

/// Leaf certificate validity: one year.
const LEAF_TTL_SECS: i64 = 365 * 24 * 60 * 60;
/// Back-date the leaf `notBefore` slightly to tolerate client clock skew.
const NOT_BEFORE_OFFSET: i64 = 60;

/// Persistent CA material used to mint per-host MITM leaf certificates.
struct CaMaterial {
    cert: X509,
    key: PKey<Private>,
}

// SAFETY(soundness): boring's `X509`/`PKey` are internally reference-counted
// OpenSSL-style handles that are safe to share across threads; rama exposes
// them from a thread-safe backend. Wrapping in `Arc` keeps clones cheap.
type LeafCache = Arc<Mutex<HashMap<String, ServerAuthData>>>;

/// A persistent local certificate authority that mints per-host leaf
/// certificates for MITM interception, backed by rama's BoringSSL provider.
#[derive(Clone)]
pub struct Ssl {
    ca: Arc<CaMaterial>,
    ca_cert_pem: Bytes,
    cache: LeafCache,
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

        let (key, cert) = if cert_path.exists() && key_path.exists() {
            tracing::info!("Loading CA certificate from {}", dir.display());
            let key_pem = std::fs::read(&key_path).context("read CA private key")?;
            let cert_pem = std::fs::read(&cert_path).context("read CA certificate")?;
            let key = PKey::private_key_from_pem(&key_pem).context("parse CA private key")?;
            let cert = X509::from_pem(&cert_pem).context("parse CA certificate")?;

            // Verify the loaded key matches the certificate.
            if !cert
                .public_key()
                .context("read CA public key")?
                .public_eq(&key)
            {
                return Err(BoxError::from(
                    "CA certificate does not match private key".to_owned(),
                ));
            }

            (key, cert)
        } else {
            tracing::info!("Generating new CA certificate in {}", dir.display());
            let (cert, key) = self_signed_server_auth_gen_ca(&SelfSignedData {
                organisation_name: Some("Proxelar".to_owned()),
                common_name: Some(Domain::from_static("proxelar")),
                ..Default::default()
            })
            .context("generate CA")?;

            let key_pem = key
                .private_key_to_pem_pkcs8()
                .context("serialize CA private key")?;
            let cert_pem = cert.to_pem().context("serialize CA certificate")?;

            std::fs::write(&key_path, &key_pem).context("write CA private key")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                    .context("chmod CA private key")?;
            }
            std::fs::write(&cert_path, &cert_pem).context("write CA certificate")?;

            (key, cert)
        };

        let ca_cert_pem = Bytes::from(cert.to_pem().context("serialize CA certificate to PEM")?);

        Ok(Self {
            ca: Arc::new(CaMaterial { cert, key }),
            ca_cert_pem,
            cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// The CA certificate in PEM form, served by the certificate install page.
    pub fn ca_cert_pem(&self) -> Bytes {
        self.ca_cert_pem.clone()
    }

    /// Build a BoringSSL server TLS config that issues (and caches) a leaf
    /// certificate for `host` on demand.
    ///
    /// The leaf carries a 1-year validity and an IP or DNS SAN matching the
    /// target host — behaviour rama's built-in `ServerCertIssuerKind::Single`
    /// path cannot express (it hardcodes 90-day DNS-only leaves), so we plug a
    /// bespoke [`DynamicCertIssuer`] into rama's BoringSSL acceptor.
    pub(crate) fn tls_server_config(&self, host: &Host) -> TlsServerConfig {
        let issuer = ProxelarCertIssuer {
            ca: Arc::clone(&self.ca),
            cache: Arc::clone(&self.cache),
            host: host.clone(),
        };
        TlsServerConfig::new()
            .with_cert_issuer(ServerCertIssuerData {
                kind: issuer.into(),
                // We keep our own per-host leaf cache (below), so the acceptor's
                // SNI-keyed cache is redundant here.
                cache_kind: CacheKind::Disabled,
            })
            .with_alpn_http_auto()
    }
}

/// A [`DynamicCertIssuer`] bound to a single MITM target host.
///
/// Because proxelar builds a fresh acceptor per intercepted tunnel with the
/// target authority already known, the issuer does not depend on SNI to pick
/// the host — which is what lets it serve IP-SAN leaves for IP targets that
/// carry no SNI.
struct ProxelarCertIssuer {
    ca: Arc<CaMaterial>,
    cache: LeafCache,
    host: Host,
}

impl std::fmt::Debug for ProxelarCertIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxelarCertIssuer")
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

impl DynamicCertIssuer for ProxelarCertIssuer {
    async fn issue_cert(
        &self,
        _client_hello: ClientHello,
        _server_name: Option<Domain>,
    ) -> Result<ServerAuthData, BoxError> {
        let key = self.host.to_str().to_string();
        if let Some(data) = self
            .cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
            .cloned()
        {
            tracing::debug!("Using cached leaf certificate for {key}");
            return Ok(data);
        }
        tracing::debug!("Minting leaf certificate for {key}");
        let data = mint_leaf(&self.ca, &self.host)?;
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, data.clone());
        Ok(data)
    }
}

/// Mint a per-host leaf certificate signed by the CA.
///
/// Every leaf gets its own P-256 key (reusing the CA key would needlessly
/// expose the root of trust on every handshake), a 1-year validity, and an IP
/// or DNS SAN matching the host.
fn mint_leaf(ca: &CaMaterial, host: &Host) -> Result<ServerAuthData, BoxError> {
    let host_str = host.to_str();

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).context("create P-256 EC group")?;
    let leaf_key = PKey::from_ec_key(EcKey::generate(&group).context("generate leaf EC key")?)
        .context("wrap leaf EC key")?;

    let mut name = X509NameBuilder::new().context("create leaf name builder")?;
    name.append_entry_by_nid(Nid::COMMONNAME, host_str.as_ref())
        .context("append leaf common name")?;
    let name = name.build();

    let mut builder = X509::builder().context("create leaf cert builder")?;
    builder.set_version(2).context("set leaf version")?;
    builder
        .set_subject_name(&name)
        .context("set leaf subject")?;
    builder
        .set_issuer_name(ca.cert.subject_name())
        .context("set leaf issuer")?;
    builder
        .set_pubkey(&leaf_key)
        .context("set leaf public key")?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("read system time")?
        .as_secs() as i64;
    let not_before = now - NOT_BEFORE_OFFSET;
    builder
        .set_not_before(
            Asn1Time::from_unix(not_before)
                .context("leaf notBefore")?
                .as_ref(),
        )
        .context("set leaf notBefore")?;
    builder
        .set_not_after(
            Asn1Time::from_unix(not_before + LEAF_TTL_SECS)
                .context("leaf notAfter")?
                .as_ref(),
        )
        .context("set leaf notAfter")?;

    let serial = {
        let mut serial = BigNum::new().context("create serial big num")?;
        serial
            .rand(159, MsbOption::MAYBE_ZERO, false)
            .context("randomise serial")?;
        serial.to_asn1_integer().context("serial to ASN1")?
    };
    builder
        .set_serial_number(&serial)
        .context("set leaf serial")?;

    builder
        .append_extension(
            BasicConstraints::new()
                .build()
                .context("build leaf basic constraints")?
                .as_ref(),
        )
        .context("append leaf basic constraints")?;
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .non_repudiation()
                .digital_signature()
                .key_encipherment()
                .build()
                .context("build leaf key usage")?
                .as_ref(),
        )
        .context("append leaf key usage")?;

    let mut san = SubjectAlternativeName::new();
    if matches!(host, Host::Address(_)) {
        san.ip(host_str.as_ref());
    } else {
        san.dns(host_str.as_ref());
    }
    let san = san
        .build(&builder.x509v3_context(Some(&ca.cert), None))
        .context("build leaf SAN")?;
    builder
        .append_extension(san.as_ref())
        .context("append leaf SAN")?;

    let ski = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(Some(&ca.cert), None))
        .context("build leaf subject key id")?;
    builder
        .append_extension(ski.as_ref())
        .context("append leaf subject key id")?;

    builder
        .sign(&ca.key, MessageDigest::sha256())
        .context("sign leaf certificate")?;
    let leaf = builder.build();

    let leaf_der = CertificateDer::from(leaf.to_der().context("serialize leaf to DER")?);
    let key_der: PrivateKeyDer<'static> = PrivatePkcs8KeyDer::from(
        leaf_key
            .private_key_to_der_pkcs8()
            .context("serialize leaf key to PKCS#8 DER")?,
    )
    .into();

    Ok(ServerAuthData {
        cert_chain: vec![leaf_der],
        private_key: key_der,
        ocsp: None,
    })
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
    fn minted_leaf_uses_a_distinct_matching_private_key() {
        let directory = tempfile::tempdir().unwrap();
        let ssl = Ssl::load_or_generate(directory.path()).unwrap();
        let host = Host::try_from("api.example.test").unwrap();

        let data = mint_leaf(&ssl.ca, &host).unwrap();
        let leaf = X509::from_der(data.cert_chain[0].as_ref()).unwrap();
        let leaf_key = PKey::private_key_from_pkcs8(data.private_key.secret_der()).unwrap();
        let leaf_public = leaf.public_key().unwrap();

        // The leaf carries its own key, never the CA's root key.
        assert!(leaf_public.public_eq(&leaf_key));
        assert!(!leaf_public.public_eq(&ssl.ca.key));
    }

    #[test]
    fn minted_ip_leaf_uses_an_ip_subject_alternative_name() {
        let directory = tempfile::tempdir().unwrap();
        let ssl = Ssl::load_or_generate(directory.path()).unwrap();
        let host = Host::try_from("127.0.0.1").unwrap();

        let data = mint_leaf(&ssl.ca, &host).unwrap();
        let leaf = X509::from_der(data.cert_chain[0].as_ref()).unwrap();
        let names = leaf.subject_alt_names().unwrap();

        assert!(names
            .iter()
            .any(|name| name.ipaddress() == Some([127, 0, 0, 1].as_slice())));
        assert!(names.iter().all(|name| name.dnsname().is_none()));
    }
}
