<div align="center">
<img src="assets/logo.png" width="80"><br><br>
<h1>Proxelar</h1>
<p><strong>A Man-in-the-Middle proxy written in Rust.</strong><br>
Intercept, inspect, and modify HTTP/HTTPS traffic with Lua scripting, a TUI, and a web interface.</p>

<p>
<a href="https://crates.io/crates/proxelar"><img src="https://img.shields.io/crates/v/proxelar" alt="Crates.io"></a>
<a href="https://formulae.brew.sh/formula/proxelar"><img src="https://img.shields.io/homebrew/v/proxelar" alt="Homebrew"></a>
<a href="LICENSE-MIT"><img src="https://img.shields.io/crates/l/proxelar" alt="License: MIT"></a>
<a href="https://github.com/emanuele-em/proxelar/actions/workflows/autofix.yml"><img src="https://github.com/emanuele-em/proxelar/actions/workflows/autofix.yml/badge.svg" alt="CI"></a>
<a href="https://proxelar.micheletti.io"><img src="https://img.shields.io/badge/docs-proxelar.micheletti.io-blue" alt="Docs"></a>
</p>

<img src="assets/screenshots/tui.gif" alt="TUI demo" width="800"><br><br>
<img src="assets/screenshots/gui.gif" alt="Web GUI demo" width="800">

</div>

---

## What is Proxelar?

Proxelar sits between your application and the internet, giving you full visibility into every HTTP/HTTPS request — and the power to transform it on the fly with Lua.

```
Your App  ──►  Proxelar :8080  ──►  Internet
                    │
              Inspect · Modify · Mock
```

Useful for debugging APIs, reverse engineering third-party services, testing mobile apps, injecting headers, mocking responses, or automating any request/response transform without touching your source code.

---

## Features

- **Lua scripting** — write `on_request` / `on_response` hooks to modify, block, or mock traffic at runtime
- **HTTPS interception** — automatic CA generation and per-host certificate minting
- **Forward & reverse proxy** — CONNECT tunneling or upstream URI rewriting
- **Three interfaces** — terminal (stdout), interactive TUI (ratatui), web GUI (axum + WebSocket)
- **WebSocket inspection** — connections captured alongside HTTP traffic; browse frames by direction, opcode, and payload
- **Column-scoped filtering** — `time:14:`, `proto:https`, `method:POST`, `host:github`, `path:/api`, `status:404`, `type:json`, `size:1KB`, `duration:slow` or plain text search
- **Easy CA install** — visit `http://proxel.ar` through the proxy to download and install the root cert

---

## Installation

### Homebrew (macOS / Linux)

```bash
brew install proxelar
```

### Cargo

```bash
cargo install proxelar
```

### Docker / Podman

```bash
# Web GUI
docker run --rm -it -v ~/.proxelar:/root/.proxelar -p 8080:8080 -p 127.0.0.1:8081:8081 ghcr.io/emanuele-em/proxelar --interface gui --addr 0.0.0.0

# Terminal
docker run --rm -it -v ~/.proxelar:/root/.proxelar -p 8080:8080 ghcr.io/emanuele-em/proxelar --interface terminal --addr 0.0.0.0
```

The `-v ~/.proxelar:/root/.proxelar` mount reuses your existing trusted CA certificate so you won't get browser warnings.

---

## Quick Start

**1. Start the proxy**
```bash
proxelar
```

**2. Install the CA certificate**

Visit `http://proxel.ar` while routing traffic through the proxy — it serves the cert with install instructions.  
Or install it manually: `~/.proxelar/proxelar-ca.pem`

**3. Configure your system proxy**

Set HTTP and HTTPS proxy to `127.0.0.1:8080` in your OS, browser, or tool of choice.

Traffic will start appearing in the TUI immediately.

---

## Interfaces

```bash
proxelar              # interactive TUI (default)
proxelar -i terminal  # plain terminal output
proxelar -i gui       # web GUI at http://localhost:8081
```

---

## Usage

```bash
proxelar -m reverse --target http://localhost:3000   # reverse proxy
proxelar -b 0.0.0.0 -p 9090                         # custom bind/port
proxelar --script examples/scripts/block_domain.lua  # with a Lua script
proxelar --body-capture-limit 1048576                # cap captured/editable body bytes
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
| `--body-capture-limit` | Maximum body bytes buffered for capture/editing; use `free`, `unlimited`, or `none` for unlimited | `free` |

</details>

<details>
<summary><strong>TUI key bindings</strong></summary>

| Key | Action |
|-----|--------|
| `j` / `k` / arrows | Navigate |
| `Enter` | Open detail panel; press again to focus and scroll |
| `Tab` | Switch Request / Response / Frames tabs |
| `/` | Filter (plain text or `column:value`) |
| `r` | Replay selected request |
| `Esc` | Close panel / clear filter |
| `g` / `G` | Top / bottom |
| `c` | Clear requests |
| `?` | Keybinding help |
| `q` / `Ctrl+C` | Quit |

</details>

---

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

More examples in [`examples/scripts/`](examples/scripts/) — header injection, cookie stripping, HTML rewriting, request body modification, traffic logging, and more. Full scripting API reference at [proxelar.micheletti.io](https://proxelar.micheletti.io/scripting/api-reference.html).

---

## Documentation

Latest release: **[Proxelar 0.4.4 — Body Capture Limits for Large Traffic](https://github.com/emanuele-em/proxelar/releases/tag/v0.4.4)**

Full documentation at **[proxelar.micheletti.io](https://proxelar.micheletti.io)**:

- [Getting started](https://proxelar.micheletti.io/quick-start.html)
- [Forward & reverse proxy modes](https://proxelar.micheletti.io/proxy-modes/forward.html)
- [Lua scripting API reference](https://proxelar.micheletti.io/scripting/api-reference.html)
- [CA certificate installation](https://proxelar.micheletti.io/ca-certificate.html)

---

## Contributing

Contributions are welcome. Open an issue or submit a pull request.

## License

[MIT](LICENSE-MIT)
