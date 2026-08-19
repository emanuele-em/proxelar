mod browser;
mod cli;
mod interface;
mod wireguard_setup;

use clap::Parser;
#[cfg(feature = "scripting")]
use cli::{AddonCommand, Command};
use cli::{Args, Interface, Mode};
use proxyapi::session::{
    export_curl, export_har, export_raw, import_har, load_session, save_session, session_events,
};
use proxyapi::{
    DnsConfig, InterceptConfig, Proxy, ProxyConfig, ProxyMode, RedactionPolicy, RouteRules,
    SessionRecorder, WireGuardConfig,
};
use rama::net::uri::Uri;
use rama::telemetry::tracing;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

/// Capacity of the event channel between the proxy core and the UI.
const EVENT_CHANNEL_CAPACITY: usize = 10_000;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    tracing::subscriber::fmt()
        .with_env_filter(tracing::subscriber::EnvFilter::from_default_env())
        .init();

    let ca_dir = args.ca_dir.clone().unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| {
                tracing::warn!("Could not determine home directory, using current directory");
                std::path::PathBuf::from(".")
            })
            .join(".proxelar")
    });
    #[cfg(feature = "scripting")]
    let addons_dir = args
        .addons_dir
        .clone()
        .unwrap_or_else(|| ca_dir.join("addons"));
    #[cfg(feature = "scripting")]
    if let Some(command) = &args.command {
        handle_addon_command(command, &addons_dir)?;
        return Ok(());
    }

    let initial_session = if let Some(path) = &args.load_session {
        load_session(path)?
    } else if let Some(path) = &args.import_har {
        import_har(path)?
    } else {
        proxyapi_models::TrafficSession::new(chrono::Utc::now().timestamp_millis())
    };
    let initial_events = session_events(&initial_session);
    let recorder = Arc::new(RwLock::new(SessionRecorder::from_session(initial_session)?));

    let (event_tx, mut core_event_rx) = tokio::sync::mpsc::channel(EVENT_CHANNEL_CAPACITY);
    let (ui_event_tx, event_rx) = tokio::sync::mpsc::channel(EVENT_CHANNEL_CAPACITY);
    let (replay_tx, replay_rx) = tokio::sync::mpsc::channel(100);
    let cancel = CancellationToken::new();
    let intercept = InterceptConfig::new();

    let browser_profile = ca_dir.join("browser-profile");

    #[cfg(feature = "scripting")]
    let script_path = if let Some(name) = &args.addon {
        Some(proxyapi::find_addon(&addons_dir, name)?.root().to_owned())
    } else {
        args.script.clone()
    };

    let mut wireguard_setup = None;
    let proxy_mode = match args.mode {
        Mode::Forward => ProxyMode::Forward,
        Mode::Reverse => {
            let target_str = args.target.as_deref().expect("clap enforces --target");
            let target: Uri = target_str.parse()?;
            if target.scheme().is_none() || target.authority().is_none() {
                return Err(
                    "Reverse proxy target must include scheme and authority (e.g. http://localhost:3000)".into(),
                );
            }
            ProxyMode::Reverse { target }
        }
        Mode::Socks5 => ProxyMode::Socks5,
        Mode::Dns => {
            let mut config = DnsConfig::new(resolve_socket_addr(&args.dns_upstream).await?);
            for mapping in &args.dns_map {
                config.add_override(&mapping.source, mapping.target.parse::<std::net::IpAddr>()?);
            }
            ProxyMode::Dns { config }
        }
        Mode::Udp => {
            let target_value = args
                .target
                .as_deref()
                .ok_or("UDP mode requires --target HOST:PORT")?;
            let target = resolve_socket_addr(target_value).await?;
            ProxyMode::Udp { target }
        }
        Mode::Wireguard => {
            let mut dns = DnsConfig::new(resolve_socket_addr(&args.dns_upstream).await?);
            for mapping in &args.dns_map {
                dns.add_override(&mapping.source, mapping.target.parse::<std::net::IpAddr>()?);
            }
            let endpoint = match &args.wireguard_endpoint {
                Some(endpoint) => endpoint.clone(),
                None => default_wireguard_endpoint(args.addr, args.port, dns.upstream)
                    .await?
                    .to_string(),
            };
            let (config, client_config) =
                WireGuardConfig::load_or_generate(&ca_dir, &endpoint, dns)?;
            wireguard_setup = Some(Arc::new(wireguard_setup::WireGuardSetup::from_config(
                &client_config,
            )?));
            eprintln!(
                "WireGuard client configuration: {}",
                client_config.display()
            );
            ProxyMode::WireGuard { config }
        }
    };

    let proxy_config = ProxyConfig {
        addr: SocketAddr::new(args.addr, args.port),
        mode: proxy_mode,
        event_tx,
        ca_dir,
        upstream_tls: args.upstream_trust,
        upstream_http_version: args.upstream_http_version,
        intercept: Some(Arc::clone(&intercept)),
        body_capture_limit: args.body_capture_limit.into_option(),
        #[cfg(feature = "scripting")]
        script_path,
        replay_rx: Some(replay_rx),
    };

    let mut route_rules = if let Some(path) = &args.rules {
        RouteRules::load(path)?
    } else {
        RouteRules::default()
    };
    for mapping in &args.map_local {
        route_rules.map_local(&mapping.source, &mapping.target)?;
    }
    for mapping in &args.map_remote {
        route_rules.map_remote(&mapping.source, &mapping.target)?;
    }
    let proxy = if route_rules.rules.is_empty() {
        Proxy::new(proxy_config)
    } else {
        Proxy::new(proxy_config).with_route_rules(Arc::new(route_rules))
    }
    .with_peek_timeout_policy(args.peek_timeout_policy);
    let proxy = if let Some(mut upstream_proxy) = args.upstream_proxy {
        if let Some(credentials) = &args.upstream_proxy_auth {
            let (username, password) = credentials
                .split_once(':')
                .ok_or("--upstream-proxy-auth must be USERNAME:PASSWORD")?;
            upstream_proxy = upstream_proxy.with_auth(username, password);
        }
        proxy.with_upstream_proxy(upstream_proxy)
    } else {
        proxy
    };

    // Record every event once, then fan it out to the selected interface. The
    // imported history is replayed to the UI without recording it a second time.
    let recorder_for_events = Arc::clone(&recorder);
    let mut event_fanout_task = tokio::spawn(async move {
        for event in initial_events {
            let _ = ui_event_tx.send(event).await;
        }
        while let Some(event) = core_event_rx.recv().await {
            recorder_for_events.write().await.record(&event);
            let _ = ui_event_tx.send(event).await;
        }
    });

    // Ctrl+C cancels everything
    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        cancel_clone.cancel();
    });

    // Spawn the proxy; cancel the token on failure so the UI exits too
    let cancel_for_proxy = cancel.clone();
    let proxy_task = tokio::spawn(async move {
        if let Err(e) = proxy
            .start(cancel_for_proxy.clone().cancelled_owned())
            .await
        {
            tracing::error!("Proxy error: {e}");
            cancel_for_proxy.cancel();
        }
    });

    // Brief delay to catch immediate startup failures (bind errors, CA errors)
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    if cancel.is_cancelled() {
        return Err("Proxy failed to start (check logs for details)".into());
    }

    match args.interface {
        Interface::Terminal => {
            interface::terminal::run(event_rx, args.quiet, wireguard_setup, cancel.clone()).await
        }
        Interface::Tui => {
            interface::tui::run(
                event_rx,
                Arc::clone(&intercept),
                replay_tx,
                wireguard_setup,
                cancel.clone(),
            )
            .await
        }
        Interface::Gui | Interface::Api => {
            let open_browser = matches!(args.interface, Interface::Gui);
            interface::web::run(
                event_rx,
                Arc::clone(&intercept),
                replay_tx,
                Arc::clone(&recorder),
                interface::web::ServerConfig {
                    addr: args.addr,
                    port: args.gui_port,
                    token: args.api_token,
                    open_browser,
                    wireguard_setup,
                    browser_proxy: args.launch_browser.then(|| {
                        let browser_addr = if args.addr.is_unspecified() {
                            if args.addr.is_ipv6() {
                                std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
                            } else {
                                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                            }
                        } else {
                            args.addr
                        };
                        (SocketAddr::new(browser_addr, args.port), browser_profile)
                    }),
                },
                cancel.clone(),
            )
            .await
        }
    }

    cancel.cancel();
    let _ = proxy_task.await;

    // Let completed connection tasks flush their final events before taking the
    // persistence snapshot. Long-lived connections are detached from the
    // listener, so bound the drain rather than hanging shutdown indefinitely.
    if tokio::time::timeout(
        std::time::Duration::from_millis(500),
        &mut event_fanout_task,
    )
    .await
    .is_err()
    {
        event_fanout_task.abort();
        let _ = event_fanout_task.await;
    }
    let session = recorder.read().await.snapshot();
    let redaction = (!args.export_secrets).then(RedactionPolicy::default);
    if let Some(path) = args.save_session {
        save_session(path, &session)?;
    }
    if let Some(path) = args.export_har {
        export_har(path, &session, redaction.as_ref())?;
    }
    if let Some(path) = args.export_curl {
        export_curl(path, &session, redaction.as_ref())?;
    }
    if let Some(path) = args.export_raw {
        export_raw(path, &session, redaction.as_ref())?;
    }

    Ok(())
}

#[cfg(feature = "scripting")]
fn handle_addon_command(
    command: &Command,
    addons_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::Addon { command } => match command {
            AddonCommand::List => {
                let addons = proxyapi::discover_addons(addons_dir)?;
                if addons.is_empty() {
                    println!("No addons installed in {}", addons_dir.display());
                } else {
                    for addon in addons {
                        let native = if addon.manifest().requires_native_modules {
                            " [native modules]"
                        } else {
                            ""
                        };
                        println!(
                            "{} {}{} - {}",
                            addon.manifest().name,
                            addon.manifest().version,
                            native,
                            addon.manifest().description
                        );
                    }
                }
            }
            AddonCommand::Inspect { addon } => {
                let package = addon_from_path_or_catalog(addon, addons_dir)?;
                println!("{}", serde_json::to_string_pretty(package.manifest())?);
            }
            AddonCommand::Verify { package } => {
                let package = proxyapi::AddonPackage::load(package)?;
                println!(
                    "Verified {} {} ({} files)",
                    package.manifest().name,
                    package.manifest().version,
                    package.manifest().files.len()
                );
            }
            AddonCommand::Install { package } => {
                let installed = proxyapi::install_addon(package, addons_dir)?;
                println!(
                    "Installed {} {} to {}",
                    installed.manifest().name,
                    installed.manifest().version,
                    installed.root().display()
                );
            }
        },
    }
    Ok(())
}

#[cfg(feature = "scripting")]
fn addon_from_path_or_catalog(
    addon: &std::path::Path,
    addons_dir: &std::path::Path,
) -> Result<proxyapi::AddonPackage, Box<dyn std::error::Error>> {
    if addon.exists() {
        Ok(proxyapi::AddonPackage::load(addon)?)
    } else {
        let name = addon.to_str().ok_or("addon name must be valid UTF-8")?;
        Ok(proxyapi::find_addon(addons_dir, name)?)
    }
}

async fn resolve_socket_addr(value: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    if let Ok(address) = value.parse() {
        return Ok(address);
    }
    tokio::net::lookup_host(value)
        .await?
        .next()
        .ok_or_else(|| format!("{value} did not resolve to an address").into())
}

async fn default_wireguard_endpoint(
    bind_address: std::net::IpAddr,
    port: u16,
    route_probe: SocketAddr,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    if !bind_address.is_unspecified() {
        return Ok(SocketAddr::new(bind_address, port));
    }
    let wildcard = if route_probe.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = tokio::net::UdpSocket::bind(wildcard).await?;
    socket.connect(route_probe).await?;
    Ok(SocketAddr::new(socket.local_addr()?.ip(), port))
}
