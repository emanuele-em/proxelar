use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
pub struct Opts {
    /// Path to certificate file
    #[clap(long = "cert", default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/", "mitmproxy.cer"))]
    pub cert: PathBuf,
    /// Path to key file
    #[clap(long = "key", default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/", "mitmproxy.key"))]
    pub key: PathBuf,
}
