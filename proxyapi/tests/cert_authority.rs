use proxyapi::ca::Ssl;

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
