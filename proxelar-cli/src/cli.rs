#[cfg(feature = "scripting")]
use clap::Subcommand;
use clap::{Parser, ValueEnum};
use proxyapi::{UpstreamHttpVersion, UpstreamProxyConfig, UpstreamTlsConfig};
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Parser)]
#[command(
    name = "proxelar",
    version,
    about = "MITM proxy for HTTP/HTTPS traffic"
)]
pub struct Args {
    #[cfg(feature = "scripting")]
    #[command(subcommand)]
    pub command: Option<Command>,

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

    /// Target upstream (required for reverse and UDP)
    #[arg(
        short,
        long,
        required_if_eq_any([("mode", "reverse"), ("mode", "udp")])
    )]
    pub target: Option<String>,

    /// Web GUI port (only used with -i gui)
    #[arg(long, default_value_t = 8081)]
    pub gui_port: u16,

    /// Directory for CA certificate and key (default: ~/.proxelar)
    #[arg(long, value_name = "DIR")]
    pub ca_dir: Option<PathBuf>,

    /// Lua script file or addon directory containing init.lua
    #[arg(short = 's', long = "script", value_name = "FILE")]
    pub script: Option<PathBuf>,

    /// Load a validated addon by name from the local addon catalog
    #[cfg(feature = "scripting")]
    #[arg(long, value_name = "NAME", conflicts_with = "script")]
    pub addon: Option<String>,

    /// Local addon catalog (default: CA_DIR/addons)
    #[cfg(feature = "scripting")]
    #[arg(long, global = true, value_name = "DIR")]
    pub addons_dir: Option<PathBuf>,

    /// Suppress per-request output (only used with -i terminal)
    #[arg(short, long)]
    pub quiet: bool,

    /// Maximum body bytes buffered for capture/editing before passthrough (`free` for unlimited)
    #[arg(
        long = "body-capture-limit",
        value_name = "BYTES|free",
        default_value = "free"
    )]
    pub body_capture_limit: BodyCaptureLimit,

    /// Upstream HTTPS trust policy: default, default+ca:/path/to/ca.pem, ca-only:/path/to/ca.pem, or insecure
    #[arg(
        long = "upstream-trust",
        value_name = "POLICY",
        default_value = "default"
    )]
    pub upstream_trust: UpstreamTlsConfig,

    /// Chain upstream traffic through `http://HOST:PORT` or `socks5://HOST:PORT`
    #[arg(long, value_name = "URL")]
    pub upstream_proxy: Option<UpstreamProxyConfig>,

    /// Upstream proxy credentials (`USERNAME:PASSWORD`)
    #[arg(long, value_name = "USERNAME:PASSWORD", requires = "upstream_proxy")]
    pub upstream_proxy_auth: Option<String>,

    /// Upstream HTTP version: `auto` (preserve the client's negotiated version), `http1`, or `http2`
    #[arg(
        long = "upstream-http-version",
        value_name = "VERSION",
        default_value = "auto"
    )]
    pub upstream_http_version: UpstreamHttpVersion,

    /// Load a native Proxelar session before capture starts
    #[arg(long, value_name = "FILE", conflicts_with = "import_har")]
    pub load_session: Option<PathBuf>,

    /// Import a HAR file before capture starts
    #[arg(long, value_name = "FILE", conflicts_with = "load_session")]
    pub import_har: Option<PathBuf>,

    /// Save the complete session on clean shutdown
    #[arg(long, value_name = "FILE")]
    pub save_session: Option<PathBuf>,

    /// Export captured HTTP flows as HAR on clean shutdown
    #[arg(long, value_name = "FILE")]
    pub export_har: Option<PathBuf>,

    /// Export captured requests as executable curl commands on clean shutdown
    #[arg(long, value_name = "FILE")]
    pub export_curl: Option<PathBuf>,

    /// Export captured flows as raw HTTP request/response files
    #[arg(long, value_name = "DIR")]
    pub export_raw: Option<PathBuf>,

    /// Include credentials and common secret query parameters in exports
    #[arg(long)]
    pub export_secrets: bool,

    /// Fixed bearer token for the GUI/headless REST API (random by default)
    #[arg(long, value_name = "TOKEN")]
    pub api_token: Option<String>,

    /// Launch an isolated Chromium profile preconfigured to use this proxy
    #[arg(long)]
    pub launch_browser: bool,

    /// Load declarative routing rules from JSON
    #[arg(long, value_name = "FILE")]
    pub rules: Option<PathBuf>,

    /// Serve matching URLs from a local directory (`URL_PREFIX=DIR`)
    #[arg(long, value_name = "URL_PREFIX=DIR")]
    pub map_local: Vec<Mapping>,

    /// Rewrite matching URL prefixes (`URL_PREFIX=TARGET_PREFIX`)
    #[arg(long, value_name = "URL_PREFIX=TARGET_PREFIX")]
    pub map_remote: Vec<Mapping>,

    /// Recursive DNS server used by DNS mode
    #[arg(long, default_value = "1.1.1.1:53", value_name = "HOST:PORT")]
    pub dns_upstream: String,

    /// Override a DNS name (`DOMAIN=IP`); repeat for multiple names
    #[arg(long, value_name = "DOMAIN=IP")]
    pub dns_map: Vec<Mapping>,

    /// Public/LAN HOST:PORT written to the generated WireGuard client config
    #[arg(long, value_name = "HOST:PORT")]
    pub wireguard_endpoint: Option<String>,
}

#[cfg(feature = "scripting")]
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Manage validated Lua addon packages
    Addon {
        #[command(subcommand)]
        command: AddonCommand,
    },
}

#[cfg(feature = "scripting")]
#[derive(Debug, Subcommand)]
pub enum AddonCommand {
    /// List installed addons
    List,
    /// Print a validated addon's manifest
    Inspect {
        /// Installed addon name or package directory
        addon: PathBuf,
    },
    /// Verify a package without installing it
    Verify {
        /// Addon package directory
        package: PathBuf,
    },
    /// Verify and atomically install a local package
    Install {
        /// Addon package directory
        package: PathBuf,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mapping {
    pub source: String,
    pub target: String,
}

impl FromStr for Mapping {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (source, target) = value
            .split_once('=')
            .ok_or_else(|| "expected SOURCE=TARGET".to_owned())?;
        if source.is_empty() || target.is_empty() {
            return Err("SOURCE and TARGET must not be empty".to_owned());
        }
        Ok(Self {
            source: source.to_owned(),
            target: target.to_owned(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyCaptureLimit {
    Unlimited,
    Bytes(usize),
}

impl BodyCaptureLimit {
    pub fn into_option(self) -> Option<usize> {
        match self {
            Self::Unlimited => None,
            Self::Bytes(bytes) => Some(bytes),
        }
    }
}

impl FromStr for BodyCaptureLimit {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        match value.to_ascii_lowercase().as_str() {
            "free" | "unlimited" | "none" => Ok(Self::Unlimited),
            _ => value
                .parse()
                .map(Self::Bytes)
                .map_err(|_| "expected a byte count, `free`, `unlimited`, or `none`".to_owned()),
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Interface {
    Terminal,
    Tui,
    Gui,
    Api,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Mode {
    Forward,
    Reverse,
    Socks5,
    Dns,
    Udp,
    Wireguard,
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
            args.body_capture_limit.into_option(),
            proxyapi::DEFAULT_BODY_CAPTURE_LIMIT
        );
        assert_eq!(args.upstream_trust, UpstreamTlsConfig::Default);
        #[cfg(feature = "scripting")]
        assert!(args.command.is_none());
    }

    #[test]
    fn test_quiet_flag() {
        assert!(!Args::parse_from(["proxelar"]).quiet);
        assert!(Args::parse_from(["proxelar", "-q"]).quiet);
        assert!(Args::parse_from(["proxelar", "--quiet"]).quiet);
    }

    #[test]
    fn test_reverse_requires_target() {
        let result = Args::try_parse_from(["proxelar", "-m", "reverse"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_udp_requires_target_and_dns_accepts_hostname_upstream() {
        assert!(Args::try_parse_from(["proxelar", "-m", "udp"]).is_err());
        let args = Args::parse_from([
            "proxelar",
            "-m",
            "dns",
            "--dns-upstream",
            "resolver.example:53",
        ]);
        assert_eq!(args.dns_upstream, "resolver.example:53");
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

        assert_eq!(args.body_capture_limit, BodyCaptureLimit::Bytes(4096));
    }

    #[test]
    fn test_body_capture_limit_free_arg() {
        let args = Args::parse_from(["proxelar", "--body-capture-limit", "free"]);

        assert_eq!(args.body_capture_limit, BodyCaptureLimit::Unlimited);
    }

    #[test]
    fn test_upstream_trust_default_arg() {
        let args = Args::parse_from(["proxelar", "--upstream-trust", "default"]);

        assert_eq!(args.upstream_trust, UpstreamTlsConfig::Default);
    }

    #[test]
    fn test_upstream_trust_default_with_ca_arg() {
        let args = Args::parse_from(["proxelar", "--upstream-trust", "default+ca:/tmp/ca.pem"]);

        assert_eq!(
            args.upstream_trust,
            UpstreamTlsConfig::DefaultWithCaFile(PathBuf::from("/tmp/ca.pem"))
        );
    }

    #[test]
    fn test_upstream_trust_ca_only_arg() {
        let args = Args::parse_from(["proxelar", "--upstream-trust", "ca-only:/tmp/ca.pem"]);

        assert_eq!(
            args.upstream_trust,
            UpstreamTlsConfig::CaFileOnly(PathBuf::from("/tmp/ca.pem"))
        );
    }

    #[test]
    fn test_upstream_trust_insecure_arg() {
        let args = Args::parse_from(["proxelar", "--upstream-trust", "insecure"]);

        assert_eq!(args.upstream_trust, UpstreamTlsConfig::Insecure);
    }

    #[test]
    fn test_upstream_trust_rejects_malformed_values() {
        for value in [
            "default+ca:",
            "default+ca:   ",
            "ca-only:",
            "ca-only:   ",
            "default+ca",
            "ca-only",
            "unknown",
            "",
        ] {
            let result = Args::try_parse_from(["proxelar", "--upstream-trust", value]);
            assert!(result.is_err(), "{value:?} should be rejected");
        }
    }

    #[cfg(feature = "scripting")]
    #[test]
    fn test_addon_commands_and_runtime_selection_parse() {
        let args = Args::parse_from(["proxelar", "addon", "install", "./my-addon"]);
        assert!(matches!(
            args.command,
            Some(Command::Addon {
                command: AddonCommand::Install { .. }
            })
        ));

        let args = Args::parse_from(["proxelar", "--addon", "header-tagger"]);
        assert_eq!(args.addon.as_deref(), Some("header-tagger"));
        assert!(Args::try_parse_from([
            "proxelar",
            "--addon",
            "header-tagger",
            "--script",
            "dev.lua"
        ])
        .is_err());
    }
}
