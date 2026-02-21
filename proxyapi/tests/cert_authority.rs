use http::uri::Authority;
use proxyapi::ca::{CertificateAuthority, Ssl};

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[test]
fn test_ssl_load_or_generate_creates_valid_ca() {
    let dir = tempfile::tempdir().unwrap();
    let _ssl = Ssl::load_or_generate(dir.path()).unwrap();
}

#[test]
fn test_ssl_load_or_generate_reloads_existing() {
    let dir = tempfile::tempdir().unwrap();
    let ssl1 = Ssl::load_or_generate(dir.path()).unwrap();
    let pem1 = ssl1.ca_cert_pem();

    let ssl2 = Ssl::load_or_generate(dir.path()).unwrap();
    let pem2 = ssl2.ca_cert_pem();

    assert_eq!(pem1, pem2, "Reloaded cert should match the original");
}

#[tokio::test]
async fn test_gen_server_config_creates_cert() {
    install_crypto_provider();
    let dir = tempfile::tempdir().unwrap();
    let ssl = Ssl::load_or_generate(dir.path()).unwrap();
    let authority: Authority = "example.com:443".parse().unwrap();
    let config = ssl.gen_server_config(&authority).await.unwrap();
    assert!(!config.alpn_protocols.is_empty());
}

#[tokio::test]
async fn test_cert_caching() {
    install_crypto_provider();
    let dir = tempfile::tempdir().unwrap();
    let ssl = Ssl::load_or_generate(dir.path()).unwrap();
    let authority: Authority = "cached.example.com:443".parse().unwrap();
    let config1 = ssl.gen_server_config(&authority).await.unwrap();
    let config2 = ssl.gen_server_config(&authority).await.unwrap();
    // Both should return the same Arc (cached)
    assert!(std::sync::Arc::ptr_eq(&config1, &config2));
}

#[test]
fn test_ca_cert_pem_returns_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let ssl = Ssl::load_or_generate(dir.path()).unwrap();
    let pem = ssl.ca_cert_pem();
    assert!(!pem.is_empty());
    // PEM should start with -----BEGIN
    let pem_str = std::str::from_utf8(&pem).expect("PEM should be valid UTF-8");
    assert!(pem_str.contains("BEGIN CERTIFICATE"));
}
