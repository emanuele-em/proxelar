<div align="center">

<img src="assets/logo.png" width="120">

# Proxelar

**A Man-in-the-Middle proxy written in Rust.**

Intercept, inspect, and debug HTTP/HTTPS traffic with a terminal, TUI, or web interface.

[![CI](https://github.com/emanuele-em/proxelar/actions/workflows/autofix.yml/badge.svg)](https://github.com/emanuele-em/proxelar/actions/workflows/autofix.yml)
[![Dependabot Updates](https://github.com/emanuele-em/proxelar/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/emanuele-em/proxelar/actions/workflows/dependabot/dependabot-updates)
[![Dependency check](https://github.com/emanuele-em/proxelar/actions/workflows/deny.yml/badge.svg)](https://github.com/emanuele-em/proxelar/actions/workflows/deny.yml)

<table><tr>
<td><img  height="500" alt="image" src="https://github.com/user-attachments/assets/f02b81f1-49f2-41b2-b2c7-70bd01ff1bb7" /></td>
<td><img  height="500" alt="image" src="https://github.com/user-attachments/assets/dc1e16ad-3b7a-4ff2-8f02-b40036ba9c01" /></td>
</tr></table>
</div>

---

## Features

- **HTTPS interception** — automatic CA generation and per-host certificate minting
- **Forward & reverse proxy** — CONNECT tunneling or upstream URI rewriting
- **Three interfaces** — terminal, interactive TUI (ratatui), web GUI (axum + WebSocket)
- **Request filtering** — search and inspect request/response pairs in detail
- **Easy CA install** — visit `http://proxel.ar` through the proxy to download the certificate

## Installation

```bash
cargo install proxelar
```


## Quick Start

```bash
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
