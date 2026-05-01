use clap::{Parser, ValueEnum};
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "proxelar",
    version,
    about = "MITM proxy for HTTP/HTTPS traffic"
)]
pub struct Args {
    /// Interface mode
    #[arg(short, long, default_value = "tui", value_enum)]
    pub interface: Interface,

    /// Proxy mode
    #[arg(short, long, default_value = "forward", value_enum)]
    pub mode: Mode,

    /// Port to listen on
    #[arg(short, long, default_value_t = 8080)]
    pub port: u16,

    /// Bind address
    #[arg(short = 'b', long, default_value = "127.0.0.1")]
    pub addr: IpAddr,

    /// Target upstream (required for reverse mode)
    #[arg(short, long, required_if_eq("mode", "reverse"))]
    pub target: Option<String>,

    /// Web GUI port (only used with -i gui)
    #[arg(long, default_value_t = 8081)]
    pub gui_port: u16,

    /// Directory for CA certificate and key (default: ~/.proxelar)
    #[arg(long, value_name = "DIR")]
    pub ca_dir: Option<PathBuf>,

    /// Path to a Lua script for request/response hooks
    #[arg(short = 's', long = "script", value_name = "FILE")]
    pub script: Option<PathBuf>,

    /// Maximum body bytes buffered for capture/editing before passthrough
    #[arg(
        long = "body-capture-limit",
        value_name = "BYTES",
        default_value_t = proxyapi::DEFAULT_BODY_CAPTURE_LIMIT
    )]
    pub body_capture_limit: usize,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum Interface {
    Terminal,
    Tui,
    Gui,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum Mode {
    Forward,
    Reverse,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_args() {
        let args = Args::parse_from(["proxelar"]);
        assert!(matches!(args.interface, Interface::Tui));
        assert!(matches!(args.mode, Mode::Forward));
        assert_eq!(args.port, 8080);
        assert_eq!(
            args.body_capture_limit,
            proxyapi::DEFAULT_BODY_CAPTURE_LIMIT
        );
    }

    #[test]
    fn test_reverse_requires_target() {
        let result = Args::try_parse_from(["proxelar", "-m", "reverse"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_gui_interface_sets_gui_port() {
        let args = Args::parse_from(["proxelar", "-i", "gui", "--gui-port", "9090"]);
        assert!(matches!(args.interface, Interface::Gui));
        assert_eq!(args.gui_port, 9090);
    }

    #[test]
    fn test_body_capture_limit_arg() {
        let args = Args::parse_from(["proxelar", "--body-capture-limit", "4096"]);

        assert_eq!(args.body_capture_limit, 4096);
    }
}
