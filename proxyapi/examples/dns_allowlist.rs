//! Example: DNS proxy with hardcoded domain allowlist.
//!
//! Uses [`Proxy::start_with_dns_handler`] with a handler that forwards
//! queries for allowlisted domains and their subdomains to the upstream
//! resolver. Every other query is answered with NXDOMAIN without contacting
//! the upstream.
//!
//! Run this example and query the proxy:
//!
//! ```console
//! $ dig @127.0.0.1 -p 5335 www.example.org
//! $ dig @127.0.0.1 -p 5335 example.com
//! ```

use std::net::SocketAddr;

use tokio::sync::mpsc;

use proxyapi::{
    DnsConfig, DnsDecision, DnsHandler, Proxy, ProxyConfig, ProxyMode, UpstreamTlsConfig,
};

const LISTEN: &str = "127.0.0.1:5335";
const UPSTREAM: &str = "1.1.1.1:53";
const ALLOWED_DOMAINS: &[&str] = &["example.org"];

#[derive(Clone)]
struct AllowlistDnsHandler {
    allowed_domains: &'static [&'static str],
}

#[async_trait::async_trait]
impl DnsHandler for AllowlistDnsHandler {
    async fn handle_query(&self, name: &str, _query_type: u16) -> DnsDecision {
        let name = name.to_ascii_lowercase();
        let allowed = self
            .allowed_domains
            .iter()
            .any(|domain| name == *domain || name.ends_with(&format!(".{domain}")));
        if allowed {
            DnsDecision::Forward
        } else {
            DnsDecision::NxDomain
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Events are not consumed here; the proxy drops them once the channel
    // is full.
    let (event_tx, _event_rx) = mpsc::channel(64);
    let config = ProxyConfig {
        addr: LISTEN.parse::<SocketAddr>()?,
        mode: ProxyMode::Dns {
            config: DnsConfig::new(UPSTREAM.parse()?),
        },
        event_tx,
        // Unused: DNS mode does not load a CA.
        ca_dir: std::env::temp_dir(),
        upstream_tls: UpstreamTlsConfig::Default,
        intercept: None,
        body_capture_limit: None,
        #[cfg(feature = "scripting")]
        script_path: None,
        replay_rx: None,
    };
    let handler = AllowlistDnsHandler {
        allowed_domains: ALLOWED_DOMAINS,
    };
    println!("DNS allowlist proxy listening on udp://{LISTEN}, upstream {UPSTREAM}");
    Proxy::new(config)
        .start_with_dns_handler(handler, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
