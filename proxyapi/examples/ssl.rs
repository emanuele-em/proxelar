use std::{net::SocketAddr, path::PathBuf};

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
            cert: PathBuf::default(),
            key: PathBuf::default(),
        },
    )
    .await
    .start(shutdown_signal())
    .await
    {
        eprintln!("{e}");
    }
}
