<div align="center">

<img src="assets/logo.png" width="120">

# Proxelar

**A Man-in-the-Middle proxy written in Rust.**

Intercept, inspect, and debug HTTP/HTTPS traffic with a terminal, TUI, or web interface.

[![build](https://github.com/emanuele-em/proxelar/actions/workflows/autofix.yml/badge.svg?branch=master)](https://github.com/emanuele-em/proxelar/actions/workflows/autofix.yml)
[![license](https://img.shields.io/github/license/emanuele-em/proxelar)](LICENSE-MIT)

</div>

---

## Features

- **HTTPS interception** — automatic CA generation and per-host certificate minting
- **Forward & reverse proxy** — CONNECT tunneling or upstream URI rewriting
- **Three interfaces** — terminal, interactive TUI (ratatui), web GUI (axum + WebSocket)
- **Request filtering** — search and inspect request/response pairs in detail
- **Easy CA install** — visit `http://proxel.ar` through the proxy to download the certificate

## Quick Start

```bash
# Install
cargo install --path proxelar-cli

# Run (forward proxy, TUI)
proxelar

# Install the CA certificate
# Option A: visit http://proxel.ar through the proxy
# Option B: manually install ~/.proxelar/proxelar-ca.pem

# Configure your system proxy to 127.0.0.1:8080
```

## Usage

```bash
proxelar                                          # interactive TUI (default)
proxelar -i terminal                              # terminal output
proxelar -i gui                                   # web GUI at localhost:8081
proxelar -m reverse --target http://localhost:3000 # reverse proxy
proxelar -b 0.0.0.0 -p 9090                       # custom bind address and port
```

<details>
<summary><strong>All CLI options</strong></summary>

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --interface` | `terminal` · `tui` · `gui` | `tui` |
| `-m, --mode` | `forward` · `reverse` | `forward` |
| `-p, --port` | Listening port | `8080` |
| `-b, --addr` | Bind address | `127.0.0.1` |
| `-t, --target` | Upstream target (required for reverse) | — |
| `--gui-port` | Web GUI port | `8081` |
| `--ca-dir` | CA certificate directory | `~/.proxelar` |

</details>

<details>
<summary><strong>TUI key bindings</strong></summary>

| Key | Action |
|-----|--------|
| `j` / `k` / arrows | Navigate |
| `Enter` | Toggle detail panel |
| `Tab` | Switch Request / Response |
| `/` | Filter |
| `Esc` | Close panel / clear filter |
| `g` / `G` | Top / bottom |
| `c` | Clear requests |
| `q` / `Ctrl+C` | Quit |

</details>

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.

## License

[MIT](LICENSE-MIT)
