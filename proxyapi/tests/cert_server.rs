use http::Request;
use proxyapi::ca::{cert_server, Ssl};

#[test]
fn test_is_cert_request_with_host_header() {
    let req = Request::builder()
        .uri("/")
        .header("host", "proxel.ar")
        .body(())
        .unwrap();
    assert!(cert_server::is_cert_request(&req));
}

#[test]
fn test_is_cert_request_negative() {
    let req = Request::builder()
        .uri("http://example.com/")
        .header("host", "example.com")
        .body(())
        .unwrap();
    assert!(!cert_server::is_cert_request(&req));
}

#[test]
fn test_handle_root_returns_html() {
    let dir = tempfile::tempdir().unwrap();
    let ssl = Ssl::load_or_generate(dir.path()).unwrap();
    let req = Request::builder()
        .uri("/")
        .header("host", "proxel.ar")
        .body(())
        .unwrap();
    let res = cert_server::handle(&req, &ssl.ca_cert_pem(), None);
    assert_eq!(res.status(), 200);
    assert_eq!(
        res.headers().get("content-type").unwrap(),
        "text/html; charset=utf-8"
    );
}

#[test]
fn test_handle_cert_pem_returns_cert() {
    let dir = tempfile::tempdir().unwrap();
    let ssl = Ssl::load_or_generate(dir.path()).unwrap();
    let req = Request::builder()
        .uri("/cert/pem")
        .header("host", "proxel.ar")
        .body(())
        .unwrap();
    let res = cert_server::handle(&req, &ssl.ca_cert_pem(), None);
    assert_eq!(res.status(), 200);
    assert_eq!(
        res.headers().get("content-type").unwrap(),
        "application/x-x509-ca-cert"
    );
    assert!(res.headers().get("content-disposition").is_some());
    assert!(res.headers().get("content-length").is_some());
}
