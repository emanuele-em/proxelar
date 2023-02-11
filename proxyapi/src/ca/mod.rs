use std::{sync::Arc, time::{Duration, SystemTime}};

use async_trait::async_trait;
use http::uri::Authority;
use moka::future::Cache;
use openssl::{pkey::{Private, PKey}, x509::{X509, X509NameBuilder, X509Builder, extension::SubjectAlternativeName}, hash::MessageDigest, asn1::{Asn1Time, Asn1Integer}, rand, bn::BigNum, error::ErrorStack};
use tokio_rustls::rustls::{self, ServerConfig};

const TTL_SECS: i64 = 365 * 24 * 60 * 60;
const CACHE_TTL: u64 = TTL_SECS as u64 / 2;
const NOT_BEFORE_OFFSET: i64 = 60;

#[async_trait]
pub trait CertificateAuthority: Send + Sync + 'static{
    async fn gen_server_config(&self, authority: &Authority) -> Arc<ServerConfig>;
}

#[derive(Clone)]
pub struct Ssl{
    pkey: PKey<Private>,
    private_key: rustls::PrivateKey,
    ca_cert: X509,
    hash: MessageDigest,
    cache: Cache<Authority, Arc<ServerConfig>>,
}

impl Ssl{
    pub fn new() -> Self{
        let private_key_bytes: &[u8] = include_bytes!("mitmproxy.key");
        let ca_cert_bytes: &[u8] = include_bytes!("mitmproxy.cer");

        let pkey = PKey::private_key_from_pem(private_key_bytes).expect("Failed to parse private key");

        let private_key = rustls::PrivateKey(
            pkey.private_key_to_der()
                .expect("Failed to encode private key"),
        );

        let ca_cert = X509::from_pem(ca_cert_bytes).expect("Failed to parse CA certificate");

        Self {
            pkey,
            private_key,
            ca_cert,
            hash: MessageDigest::sha256(),
            cache: Cache::builder()
            .max_capacity(1_000)
            .time_to_live(Duration::from_secs(CACHE_TTL))
            .build(),
        }
    }

    fn gen_cert(&self, authority: &Authority) -> Result<rustls::Certificate, ErrorStack> {
        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("CN", authority.host())?;
        let name = name_builder.build();

        let mut x509_builder = X509Builder::new()?;
        x509_builder.set_subject_name(&name)?;
        x509_builder.set_version(2)?;

        let not_before = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Failed to determine current UNIX time")
            .as_secs() as i64
            - NOT_BEFORE_OFFSET;
        x509_builder.set_not_before(Asn1Time::from_unix(not_before)?.as_ref())?;
        x509_builder.set_not_after(Asn1Time::from_unix(not_before + TTL_SECS)?.as_ref())?;

        x509_builder.set_pubkey(&self.pkey)?;
        x509_builder.set_issuer_name(self.ca_cert.subject_name())?;

        let alternative_name = SubjectAlternativeName::new()
            .dns(authority.host())
            .build(&x509_builder.x509v3_context(Some(&self.ca_cert), None))?;
        x509_builder.append_extension(alternative_name)?;

        let mut serial_number = [0; 16];
        rand::rand_bytes(&mut serial_number)?;

        let serial_number = BigNum::from_slice(&serial_number)?;
        let serial_number = Asn1Integer::from_bn(&serial_number)?;
        x509_builder.set_serial_number(&serial_number)?;

        x509_builder.sign(&self.pkey, self.hash)?;
        let x509 = x509_builder.build();
        Ok(rustls::Certificate(x509.to_der()?))
    }
}

#[async_trait]
impl CertificateAuthority for Ssl {
    async fn gen_server_config(&self, authority: &Authority) -> Arc<ServerConfig> {
        if let Some(server_cfg) = self.cache.get(authority) {
            println!("Using cached server config");
            return server_cfg;
        }
        println!("Generating server config");

        let certs = vec![self
            .gen_cert(authority)
            .unwrap_or_else(|_| panic!("Failed to generate certificate for {}", authority))];

        let mut server_cfg = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, self.private_key.clone())
            .expect("Failed to build ServerConfig");

        server_cfg.alpn_protocols = vec![
            #[cfg(feature = "http2")]
            b"h2".to_vec(),
            b"http/1.1".to_vec(),
        ];

        let server_cfg = Arc::new(server_cfg);

        self.cache
            .insert(authority.clone(), Arc::clone(&server_cfg))
            .await;

        server_cfg
    }
}