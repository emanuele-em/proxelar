use http::Request;
use http_body_util::BodyExt;
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

#[tokio::test]
async fn test_handle_root_rewrites_download_links_when_proxy_addr_is_known() {
    let dir = tempfile::tempdir().unwrap();
    let ssl = Ssl::load_or_generate(dir.path()).unwrap();
    let proxy_addr = "127.0.0.1:8080".parse().unwrap();
    let req = Request::builder()
        .uri("/")
        .header("host", "proxel.ar")
        .body(())
        .unwrap();

    let res = cert_server::handle(&req, &ssl.ca_cert_pem(), Some(proxy_addr));

    let body = res.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("href=\"http://127.0.0.1:8080/cert/pem\""));
    assert!(html.contains("href=\"http://127.0.0.1:8080/cert/cer\""));
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

#[tokio::test]
async fn test_handle_cert_cer_returns_der_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let ssl = Ssl::load_or_generate(dir.path()).unwrap();
    let req = Request::builder()
        .uri("/cert/cer")
        .header("host", "proxel.ar")
        .body(())
        .unwrap();

    let res = cert_server::handle(&req, &ssl.ca_cert_pem(), None);

    assert_eq!(res.status(), 200);
    assert_eq!(
        res.headers().get("content-type").unwrap(),
        "application/x-x509-ca-cert"
    );
    assert_eq!(
        res.headers().get("content-disposition").unwrap(),
        "attachment; filename=\"proxelar-ca-cert.cer\""
    );
    let body = res.into_body().collect().await.unwrap().to_bytes();
    assert!(body.starts_with(&[0x30]));
}

#[tokio::test]
async fn test_handle_cert_cer_returns_empty_body_for_invalid_pem() {
    let req = Request::builder()
        .uri("/cert/cer")
        .header("host", "proxel.ar")
        .body(())
        .unwrap();

    let res = cert_server::handle(&req, b"not a certificate", None);

    assert_eq!(res.status(), 200);
    assert_eq!(res.headers().get("content-length").unwrap(), "0");
    let body = res.into_body().collect().await.unwrap().to_bytes();
    assert!(body.is_empty());
}
