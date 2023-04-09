use std::net::SocketAddr;

use proxyapi::{models::MitmSslConfig, proxy::Proxy};

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

#[tokio::main]
async fn main() {
    if let Err(e) = Proxy::new(
        SocketAddr::new([127, 0, 0, 1].into(), 8080),
        None,
        MitmSslConfig {
            cert: concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../mitm_proxy/",
                "mitmproxy.cer"
            )
            .into(),
            key: concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../mitm_proxy/",
                "mitmproxy.key"
            )
            .into(),
        },
    )
    .await
    .start(shutdown_signal())
    .await
    {
        eprintln!("{e}");
    }
}
