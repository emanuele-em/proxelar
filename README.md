<div align="center">
<img src="assets/logo.png" width="100"><br>
<h1>Proxelar</h1>
<p><strong>A Man-in-the-Middle proxy written in Rust.</strong><br>
Intercept, inspect, and modify HTTP/HTTPS traffic with Lua scripting, a TUI, and a web interface.</p>
<p>
<a href="https://crates.io/crates/proxelar"><img src="https://img.shields.io/crates/v/proxelar" alt="Crates.io"></a>
<a href="LICENSE-MIT"><img src="https://img.shields.io/crates/l/proxelar" alt="License: MIT"></a>
<a href="https://github.com/emanuele-em/proxelar/actions/workflows/autofix.yml"><img src="https://github.com/emanuele-em/proxelar/actions/workflows/autofix.yml/badge.svg" alt="CI"></a>
<a href="https://proxelar.micheletti.io"><img src="https://img.shields.io/badge/docs-proxelar.micheletti.io-blue" alt="Docs"></a>
</p>
<table><tr>
<td><img height="500" alt="TUI" src="https://github.com/user-attachments/assets/f02b81f1-49f2-41b2-b2c7-70bd01ff1bb7"></td>
<td><img height="500" alt="Web GUI" src="https://github.com/user-attachments/assets/dc1e16ad-3b7a-4ff2-8f02-b40036ba9c01"></td>
</tr></table>
</div>

## Features

- **Lua scripting** — write `on_request` / `on_response` hooks to modify, block, or mock traffic at runtime
- **HTTPS interception** — automatic CA generation and per-host certificate minting
- **Forward & reverse proxy** — CONNECT tunneling or upstream URI rewriting
- **Three interfaces** — terminal, interactive TUI (ratatui), web GUI (axum + WebSocket)
- **Request filtering** — search and inspect request/response pairs in detail
- **Easy CA install** — visit `http://proxel.ar` through the proxy to download the certificate

## Installation

### Homebrew (macOS / Linux)

```bash
brew install proxelar
```

### Cargo

```bash
cargo install proxelar
```

## Quick Start

```bash
# Start the proxy (forward mode, interactive TUI)
proxelar

# Install the CA certificate — visit http://proxel.ar through the proxy
# or manually install ~/.proxelar/proxelar-ca.pem

# Configure your system proxy to 127.0.0.1:8080
```

## Usage

```bash
proxelar                                          # interactive TUI (default)
proxelar -i terminal                              # terminal output
proxelar -i gui                                   # web GUI at localhost:8081
proxelar -m reverse --target http://localhost:3000 # reverse proxy
proxelar -b 0.0.0.0 -p 9090                       # custom bind address and port
proxelar --script examples/scripts/block_domain.lua # run with a Lua script
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
| `-s, --script` | Lua script for request/response hooks | — |

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

## Scripting

Write Lua scripts to intercept and transform traffic. Define `on_request` and/or `on_response` hooks:

```lua
function on_request(request)
    -- request.method, request.url, request.headers, request.body
    -- Return the request to forward it (modified or not)
    -- Return a response table to short-circuit: { status = 403, headers = {}, body = "Blocked" }
    -- Return nil to pass through unchanged
end

function on_response(request, response)
    -- response.status, response.headers, response.body
    -- Return the response (modified or not), or nil to pass through
end
```

<details>
<summary><strong>Example: block domains</strong></summary>

```lua
local blocked = { "ads%.example%.com", "tracker%.example%.com" }

function on_request(request)
    for _, pattern in ipairs(blocked) do
        if string.find(request.url, pattern) then
            return { status = 403, headers = {}, body = "Blocked" }
        end
    end
end
```

</details>

<details>
<summary><strong>Example: add CORS headers</strong></summary>

```lua
function on_response(request, response)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response
end
```

</details>

<details>
<summary><strong>Example: mock API endpoints</strong></summary>

```lua
function on_request(request)
    if request.method == "GET" and string.find(request.url, "/api/user/me") then
        return {
            status = 200,
            headers = { ["Content-Type"] = "application/json" },
            body = '{"id": 1, "name": "Test User"}',
        }
    end
end
```

</details>

See [`examples/scripts/`](examples/scripts/) for more examples including header injection, cookie stripping, HTML rewriting, request body modification, and traffic logging. Full scripting documentation is available at [proxelar.micheletti.io](https://proxelar.micheletti.io).

## Documentation

Full documentation is available at **[proxelar.micheletti.io](https://proxelar.micheletti.io)**, covering:

- [Getting started](https://proxelar.micheletti.io/quick-start.html)
- [Forward & reverse proxy modes](https://proxelar.micheletti.io/proxy-modes/forward.html)
- [Lua scripting API reference](https://proxelar.micheletti.io/scripting/api-reference.html)
- [CA certificate installation](https://proxelar.micheletti.io/ca-certificate.html)

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.

## License

[MIT](LICENSE-MIT)
