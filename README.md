<div align="center">
<img style="width:100px; margin:auto" src="assets/logo.png">
<h1> Proxelar </h1>
<h2> A Man In The Middle proxy with multiple interface modes</h2>
</div>

[![build](https://github.com/emanuele-em/proxelar/actions/workflows/autofix.yml/badge.svg?branch=master)](https://github.com/emanuele-em/proxelar/actions/workflows/autofix.yml)
![GitHub](https://img.shields.io/github/license/emanuele-em/proxelar)
![GitHub last commit](https://img.shields.io/github/last-commit/emanuele-em/proxelar)
![GitHub top language](https://img.shields.io/github/languages/top/emanuele-em/proxelar)

## Description

Rust-based **Man in the Middle proxy** providing visibility into HTTP and HTTPS network traffic. Supports forward and reverse proxy modes with three interface options: terminal output, interactive TUI, and web GUI.

## Features

- HTTP / HTTPS interception (forward proxy with CONNECT tunneling)
- Reverse proxy mode with URI rewriting
- Certificate download via `http://proxel.ar` (when proxy is configured)
- Three interface modes:
  - **Terminal** — colored log output
  - **TUI** — interactive ratatui-based interface with filtering and detail views
  - **Web GUI** — browser-based UI with WebSocket live updates
- Filtering and request/response detail inspection

## Installation

```bash
cargo install --path proxelar-cli
```

## Getting Started

1. Start the proxy — a CA certificate is automatically generated in `~/.proxelar/` on first run.

2. Install the CA certificate so your system trusts proxied HTTPS traffic. You have two options:
   - Visit `http://proxel.ar` through the proxy to download the certificate interactively.
   - Or find the generated `proxelar-ca.pem` in `~/.proxelar/` and install it manually:
     - [macOS guide](https://support.apple.com/guide/keychain-access/change-the-trust-settings-of-a-certificate-kyca11871/mac)
     - [Ubuntu guide](https://ubuntu.com/server/docs/security-trust-store)
     - [Windows guide](https://learn.microsoft.com/en-us/skype-sdk/sdn/articles/installing-the-trusted-root-certificate)

3. Configure your local system proxy to `127.0.0.1:8080`.

## Usage

```bash
# Forward proxy with terminal output (default)
proxelar

# Forward proxy with TUI
proxelar -i tui

# Forward proxy with web GUI (opens browser)
proxelar -i gui

# Reverse proxy targeting an upstream server
proxelar -m reverse --target http://localhost:3000

# Custom address and port
proxelar -b 0.0.0.0 -p 9090
```

### CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --interface` | Interface mode: `terminal`, `tui`, `gui` | `terminal` |
| `-m, --mode` | Proxy mode: `forward`, `reverse` | `forward` |
| `-p, --port` | Listening port | `8080` |
| `-b, --addr` | Bind address | `127.0.0.1` |
| `-t, --target` | Upstream target (required for reverse mode) | - |
| `--gui-port` | Web GUI port (gui mode only) | `8081` |

### TUI Key Bindings

| Key | Action |
|-----|--------|
| `q` / `Ctrl+C` | Quit |
| `j` / `k` / arrows | Navigate requests |
| `Enter` | Toggle detail panel |
| `Tab` | Switch between Request/Response |
| `/` | Filter mode |
| `Esc` | Close detail / clear filter |
| `g` / `G` | Go to top / bottom |
| `c` | Clear all requests |

## Documentation and Help

If you have questions on how to use [Proxelar](https://github.com/emanuele-em/proxelar), please use GitHub Discussions!
![GitHub Discussions](https://img.shields.io/github/discussions/emanuele-em/proxelar)

## Contributing

Contributions are always welcome!

See `contributing.md` for ways to get started.

## Licenses

See [LICENSE-APACHE](LICENSE-APACHE), [LICENSE-MIT](LICENSE-MIT) for details
