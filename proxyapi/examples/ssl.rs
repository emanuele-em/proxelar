use std::net::SocketAddr;

use proxyapi::proxy::Proxy;

use tokio;

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

#[tokio::main]
async fn main() {
    if let Err(e) = Proxy::new(SocketAddr::new([127, 0, 0, 1].into(), 8080), None)
        .start(shutdown_signal())
        .await
    {
        eprintln!("{e}");
    }
}
