use bytes::Bytes;
use hyper::{Request, Response};

use crate::body::{self, ProxyBody};

const CERT_PAGE_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Proxelar - Certificate Installation</title>
    <style>
        :root {
            --bg: #0f172a;
            --surface: #1e293b;
            --border: #334155;
            --text: #e2e8f0;
            --text-muted: #94a3b8;
            --accent: #e94560;
            --accent-hover: #d6336c;
            --green: #22c55e;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
        }

        .container {
            max-width: 720px;
            margin: 0 auto;
            padding: 60px 24px;
        }

        .header {
            text-align: center;
            margin-bottom: 48px;
        }

        .header h1 {
            font-size: 42px;
            font-weight: 700;
            letter-spacing: -1px;
            margin-bottom: 8px;
        }

        .header h1 span { color: var(--accent); }

        .header p {
            color: var(--text-muted);
            font-size: 16px;
            line-height: 1.6;
        }

        .status {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(34, 197, 94, 0.1);
            border: 1px solid rgba(34, 197, 94, 0.3);
            color: var(--green);
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 500;
            margin-bottom: 24px;
        }

        .status::before {
            content: '';
            width: 8px;
            height: 8px;
            background: var(--green);
            border-radius: 50%;
        }

        .platforms {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 48px;
        }

        .platform-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            text-align: center;
            transition: border-color 0.2s, transform 0.2s;
        }

        .platform-card:hover {
            border-color: var(--accent);
            transform: translateY(-2px);
        }

        .platform-icon {
            font-size: 36px;
            margin-bottom: 12px;
        }

        .platform-card h3 {
            font-size: 16px;
            margin-bottom: 4px;
        }

        .platform-card .ext {
            color: var(--text-muted);
            font-size: 13px;
            margin-bottom: 16px;
        }

        .platform-card a {
            display: inline-block;
            padding: 8px 20px;
            background: var(--accent);
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 500;
            transition: background 0.2s;
        }

        .platform-card a:hover {
            background: var(--accent-hover);
        }

        .instructions {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
        }

        .instructions summary {
            padding: 16px 24px;
            cursor: pointer;
            font-weight: 600;
            font-size: 15px;
            list-style: none;
            display: flex;
            align-items: center;
            gap: 8px;
            border-bottom: 1px solid var(--border);
        }

        .instructions summary::-webkit-details-marker { display: none; }

        .instructions summary::before {
            content: '\25B6';
            font-size: 10px;
            transition: transform 0.2s;
        }

        .instructions[open] summary::before {
            transform: rotate(90deg);
        }

        .instructions .content {
            padding: 20px 24px;
        }

        .instructions h4 {
            font-size: 14px;
            color: var(--accent);
            margin: 16px 0 8px;
        }

        .instructions h4:first-child { margin-top: 0; }

        .instructions ol, .instructions ul {
            margin-left: 20px;
            color: var(--text-muted);
            line-height: 1.8;
            font-size: 14px;
        }

        .instructions code {
            background: var(--bg);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 13px;
            color: var(--green);
        }

        .instructions pre {
            background: var(--bg);
            padding: 12px 16px;
            border-radius: 6px;
            margin: 8px 0;
            overflow-x: auto;
            font-size: 13px;
            color: var(--green);
        }

        .note {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px 24px;
            margin-bottom: 32px;
            font-size: 14px;
            color: var(--text-muted);
            line-height: 1.6;
        }

        .note strong { color: var(--text); }
        .note code {
            background: var(--bg);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 13px;
            color: var(--green);
        }

        .footer {
            text-align: center;
            margin-top: 48px;
            color: var(--text-muted);
            font-size: 13px;
        }

        .footer a {
            color: var(--accent);
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="status">Proxy is running</div>
            <h1>Proxe<span>lar</span></h1>
            <p>
                To intercept HTTPS traffic, you need to install the Proxelar
                Certificate Authority (CA) certificate on your device.
            </p>
        </div>

        <div class="note">
            <strong>Tip:</strong> If you reached this page through the proxy
            (<code>http://proxel.ar</code>), open
            <code>http://localhost:PORT</code> directly in your browser
            (replacing PORT with your proxy port, e.g. 8080) for reliable
            certificate downloads.
        </div>

        <div class="platforms">
            <div class="platform-card">
                <div class="platform-icon">&#127823;</div>
                <h3>macOS</h3>
                <div class="ext">proxelar-ca.cer</div>
                <a href="/cert/cer">Download</a>
            </div>
            <div class="platform-card">
                <div class="platform-icon">&#128039;</div>
                <h3>Linux</h3>
                <div class="ext">proxelar-ca.pem</div>
                <a href="/cert/pem">Download</a>
            </div>
            <div class="platform-card">
                <div class="platform-icon">&#128187;</div>
                <h3>Windows</h3>
                <div class="ext">proxelar-ca.cer</div>
                <a href="/cert/cer">Download</a>
            </div>
            <div class="platform-card">
                <div class="platform-icon">&#128241;</div>
                <h3>iOS</h3>
                <div class="ext">proxelar-ca.pem</div>
                <a href="/cert/pem">Download</a>
            </div>
            <div class="platform-card">
                <div class="platform-icon">&#129302;</div>
                <h3>Android</h3>
                <div class="ext">proxelar-ca.cer</div>
                <a href="/cert/cer">Download</a>
            </div>
            <div class="platform-card">
                <div class="platform-icon">&#128272;</div>
                <h3>Other</h3>
                <div class="ext">PEM format</div>
                <a href="/cert/pem">Download</a>
            </div>
        </div>

        <details class="instructions">
            <summary>macOS Installation</summary>
            <div class="content">
                <ol>
                    <li>Download the certificate above</li>
                    <li>Double-click the downloaded <code>.pem</code> file &mdash; it opens in Keychain Access</li>
                    <li>The certificate is added to your <strong>login</strong> keychain</li>
                    <li>Find <strong>proxelar</strong> in the list, double-click it</li>
                    <li>Expand <strong>Trust</strong>, set <em>When using this certificate</em> to <strong>Always Trust</strong></li>
                    <li>Close the dialog and enter your password to confirm</li>
                </ol>
                <h4>Or via command line:</h4>
                <pre>curl http://localhost:8080/cert/pem -o /tmp/proxelar-ca.pem
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain /tmp/proxelar-ca.pem</pre>
            </div>
        </details>

        <details class="instructions" style="margin-top: 8px">
            <summary>Linux Installation</summary>
            <div class="content">
                <h4>Debian / Ubuntu</h4>
                <pre>curl http://localhost:8080/cert/pem | sudo tee /usr/local/share/ca-certificates/proxelar-ca.crt
sudo update-ca-certificates</pre>
                <h4>Fedora / RHEL</h4>
                <pre>curl http://localhost:8080/cert/pem | sudo tee /etc/pki/ca-trust/source/anchors/proxelar-ca.pem
sudo update-ca-trust</pre>
                <h4>Firefox (all distros)</h4>
                <ol>
                    <li>Open <code>about:preferences#privacy</code></li>
                    <li>Scroll to <strong>Certificates</strong> &rarr; <strong>View Certificates</strong></li>
                    <li><strong>Import</strong> the <code>.pem</code> file</li>
                    <li>Check <em>Trust this CA to identify websites</em></li>
                </ol>
            </div>
        </details>

        <details class="instructions" style="margin-top: 8px">
            <summary>Windows Installation</summary>
            <div class="content">
                <ol>
                    <li>Download the <code>.cer</code> certificate above</li>
                    <li>Double-click the file</li>
                    <li>Click <strong>Install Certificate</strong></li>
                    <li>Select <strong>Local Machine</strong>, click Next</li>
                    <li>Select <strong>Place all certificates in the following store</strong></li>
                    <li>Click Browse, select <strong>Trusted Root Certification Authorities</strong></li>
                    <li>Click Next, then Finish</li>
                </ol>
            </div>
        </details>

        <details class="instructions" style="margin-top: 8px">
            <summary>iOS Installation</summary>
            <div class="content">
                <ol>
                    <li>Download the certificate on your iOS device</li>
                    <li>Go to <strong>Settings</strong> &rarr; <strong>General</strong> &rarr; <strong>VPN & Device Management</strong></li>
                    <li>Tap the <strong>proxelar</strong> profile and install it</li>
                    <li>Go to <strong>Settings</strong> &rarr; <strong>General</strong> &rarr; <strong>About</strong> &rarr; <strong>Certificate Trust Settings</strong></li>
                    <li>Enable full trust for <strong>proxelar</strong></li>
                </ol>
            </div>
        </details>

        <details class="instructions" style="margin-top: 8px">
            <summary>Android Installation</summary>
            <div class="content">
                <ol>
                    <li>Download the certificate on your Android device</li>
                    <li>Go to <strong>Settings</strong> &rarr; <strong>Security</strong> &rarr; <strong>Encryption & credentials</strong></li>
                    <li>Tap <strong>Install a certificate</strong> &rarr; <strong>CA certificate</strong></li>
                    <li>Select the downloaded file</li>
                </ol>
                <p style="color: var(--text-muted); margin-top: 12px; font-size: 13px;">
                    Note: On Android 7+, user-installed CAs are only trusted by apps that explicitly opt in.
                    For system-wide trust, a rooted device is required.
                </p>
            </div>
        </details>

        <div class="footer">
            <p>
                <a href="https://github.com/emanuele-em/proxelar">Proxelar</a>
                &mdash; Man in the Middle proxy
            </p>
        </div>
    </div>
</body>
</html>"#;

pub fn is_cert_request<T>(req: &Request<T>) -> bool {
    req.uri().host().is_some_and(|h| h == "proxel.ar")
        || req
            .headers()
            .get("host")
            .and_then(|h| h.to_str().ok())
            .is_some_and(|h| h == "proxel.ar" || h.starts_with("proxel.ar:"))
}

pub fn handle<T>(
    req: &Request<T>,
    ca_cert_pem: &[u8],
    proxy_addr: Option<std::net::SocketAddr>,
) -> Response<ProxyBody> {
    match req.uri().path() {
        "/cert/pem" => {
            let len = ca_cert_pem.len();
            Response::builder()
                .header("content-type", "application/x-x509-ca-cert")
                .header("content-length", len.to_string())
                .header(
                    "content-disposition",
                    "attachment; filename=\"proxelar-ca-cert.pem\"",
                )
                .body(body::full(Bytes::from(ca_cert_pem.to_vec())))
                .unwrap_or_else(|e| {
                    tracing::error!("Failed to build PEM response: {e}");
                    Response::new(body::empty())
                })
        }
        "/cert/cer" => {
            let der = pem_to_der(ca_cert_pem);
            let len = der.len();
            Response::builder()
                .header("content-type", "application/x-x509-ca-cert")
                .header("content-length", len.to_string())
                .header(
                    "content-disposition",
                    "attachment; filename=\"proxelar-ca-cert.cer\"",
                )
                .body(body::full(Bytes::from(der)))
                .unwrap_or_else(|e| {
                    tracing::error!("Failed to build DER response: {e}");
                    Response::new(body::empty())
                })
        }
        _ => {
            // When accessed via proxel.ar (proxied), rewrite download links
            // to point directly at the proxy server (http://localhost:PORT/cert/...)
            // so that downloads bypass the proxy and work in all browsers.
            let html = if let Some(addr) = proxy_addr {
                let base = format!("http://{addr}");
                CERT_PAGE_HTML
                    .replace("href=\"/cert/pem\"", &format!("href=\"{base}/cert/pem\""))
                    .replace("href=\"/cert/cer\"", &format!("href=\"{base}/cert/cer\""))
            } else {
                CERT_PAGE_HTML.to_string()
            };

            let len = html.len();
            Response::builder()
                .header("content-type", "text/html; charset=utf-8")
                .header("content-length", len.to_string())
                .body(body::full(Bytes::from(html)))
                .unwrap_or_else(|e| {
                    tracing::error!("Failed to build cert page response: {e}");
                    Response::new(body::empty())
                })
        }
    }
}

fn pem_to_der(pem: &[u8]) -> Vec<u8> {
    match openssl::x509::X509::from_pem(pem).and_then(|cert| cert.to_der()) {
        Ok(der) => der,
        Err(e) => {
            tracing::error!("Failed to convert PEM to DER: {e}");
            // Return empty rather than corrupt data
            Vec::new()
        }
    }
}
