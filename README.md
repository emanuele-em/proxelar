<div align="center">
<img src="assets/logo.png" width="80"><br><br>
<h1>Proxelar</h1>
<p><strong>A scriptable local traffic workbench for HTTP, HTTPS, and WebSocket debugging.</strong><br>
Capture, inspect, intercept, replay, and rewrite traffic from your terminal or browser.</p>

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

Proxelar is a single-binary MITM proxy for developers who need to see and change what an app is doing on the wire without running a full security suite.

```
Your app  ──►  Proxelar :8080  ──►  Upstream service
                    │
              Inspect · Intercept · Rewrite · Mock
```

It is useful for debugging APIs, inspecting browser or mobile traffic, testing WebSocket clients, injecting headers, mocking local services, replaying captured requests, and automating request/response transforms with Lua.

Proxelar is intentionally developer-oriented: terminal-first, scriptable, Rust-native, and usable as a CLI tool or as the `proxyapi` library.

---

## Why use it?

- **One local binary** — install with Homebrew, winget, Cargo, Docker/Podman, or GitHub releases.
- **Four interfaces** — TUI, plain terminal output, browser GUI, or a headless REST API.
- **Lua scripting** — `on_request` and `on_response` hooks can rewrite, block, short-circuit, or mock traffic.
- **Interactive intercept** — pause requests, edit method/URI/headers/body, forward, drop, or replay.
- **HTTPS MITM** — local CA generation, per-host certificates, and a built-in certificate install page.
- **Forward and reverse modes** — inspect configured clients or put Proxelar in front of a local service.
- **Six capture modes** — forward, reverse, WireGuard, SOCKS5, DNS inspection/rewrite, and fixed-target raw UDP.
- **WebSocket inspection** — capture connections and browse frames by direction, opcode, and payload preview.
- **Portable sessions** — save/reload native captures or import/export HAR, curl, and raw HTTP files with secret redaction.
- **Rules and automation** — map local/remote URLs, mock and redirect requests, hot-reload Lua, or drive the bearer-token REST API.

---

## Installation

### Homebrew (macOS / Linux)

```bash
brew install proxelar
```

### winget (Windows)

```bash
winget install --id EmanueleMicheletti.Proxelar --exact
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

The `-v ~/.proxelar:/root/.proxelar` mount reuses your existing trusted CA certificate so you do not get browser warnings after trusting the CA once.

---

## Quick Start

**1. Start the proxy**

```bash
proxelar
```

**2. Configure a client**

Set HTTP and HTTPS proxy to `127.0.0.1:8080` in your browser, OS, mobile device, app, or tool.

**3. Install the CA certificate for HTTPS**

Visit `http://proxel.ar` while routing traffic through Proxelar. It serves the generated root certificate and install instructions.

Traffic appears in the TUI immediately.

```bash
# quick smoke test
curl -x http://127.0.0.1:8080 http://httpbin.org/get
curl -x http://127.0.0.1:8080 https://httpbin.org/get
```

---

## Example: mock an API response

Create `mock_user.lua`:

```lua
function on_request(request)
    if request.method == "GET" and string.find(request.url, "/api/user/me") then
        return {
            status = 200,
            headers = { ["Content-Type"] = "application/json" },
            body = '{"id":1,"name":"Local Test User"}',
        }
    end
end
```

Run Proxelar in front of a local service:

```bash
proxelar -m reverse --target http://localhost:3000 --script mock_user.lua
```

Then call `http://127.0.0.1:8080/api/user/me` to receive the mocked response.

More scripts are in [`examples/scripts/`](examples/scripts/), including auth injection, CORS headers, HTML rewriting, cookie stripping, redirects, traffic logging, and JSON body edits.

Portable addons use a versioned `proxelar-addon.json` manifest with semantic
versioning, declared hooks/native-code requirements, and SHA-256 coverage for
every package file. Proxelar rejects traversal, symlinks, undeclared files, and
tampered content before installation or execution:

```bash
proxelar addon verify ./examples/addons/header-tagger
proxelar addon install ./examples/addons/header-tagger
proxelar addon list
proxelar --addon header-tagger
```

See [`examples/addons/header-tagger/`](examples/addons/header-tagger/) for a
minimal distributable package. Existing manifest-free `--script` directories
remain supported for local development.

---

## Interfaces

```bash
proxelar              # interactive TUI (default)
proxelar -i terminal  # plain terminal output
proxelar -i gui       # web GUI at http://localhost:8081
proxelar -i api       # headless REST API at http://localhost:8081
```

Common options:

```bash
proxelar -m reverse --target http://localhost:3000   # reverse proxy
proxelar -b 0.0.0.0 -p 9090                         # custom bind/port
proxelar --script examples/scripts/block_domain.lua  # with a Lua script
proxelar --body-capture-limit 1048576                # cap captured/editable body bytes
proxelar --upstream-trust default+ca:/path/ca.pem    # trust an extra upstream CA
proxelar --save-session debug.proxelar.json           # save on Ctrl+C
proxelar -i gui --launch-browser                      # isolated Chromium proxy profile
proxelar -m wireguard -b 0.0.0.0 -p 51820 \
  --wireguard-endpoint 192.168.1.10:51820             # mobile/IoT capture
```

<details>
<summary><strong>All CLI options</strong></summary>

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --interface` | `terminal` · `tui` · `gui` · `api` | `tui` |
| `-m, --mode` | `forward` · `reverse` · `wireguard` · `socks5` · `dns` · `udp` | `forward` |
| `-p, --port` | Listening port | `8080` |
| `-b, --addr` | Bind address | `127.0.0.1` |
| `-t, --target` | Upstream URI for reverse or `HOST:PORT` for UDP | — |
| `--gui-port` | Web GUI port | `8081` |
| `--ca-dir` | CA certificate directory | `~/.proxelar` |
| `-s, --script` | Lua script file or addon directory (`init.lua`) | — |
| `--addon` | Load a validated installed addon by name | — |
| `--addons-dir` | Local addon catalog used by runtime and `addon` commands | `CA_DIR/addons` |
| `--body-capture-limit` | Maximum body bytes buffered for capture/editing; use `free`, `unlimited`, or `none` for unlimited | `free` |
| `--upstream-trust` | Upstream TLS trust policy: `default`, `default+ca:/path/ca.pem`, `ca-only:/path/ca.pem`, or `insecure` | `default` |
| `--upstream-proxy` | Chain through `http://HOST:PORT` or `socks5://HOST:PORT` | — |
| `--load-session`, `--import-har` | Load prior traffic before capture | — |
| `--save-session`, `--export-har`, `--export-curl`, `--export-raw` | Write captures on clean shutdown | — |
| `--rules`, `--map-local`, `--map-remote` | Declarative routing, mocks, redirects, and rewrites | — |
| `--api-token` | Fixed bearer token for the GUI/headless API; random when omitted | random |
| `--launch-browser` | Launch an isolated Chromium-family profile using the proxy | off |
| `--wireguard-endpoint` | Public/LAN `HOST:PORT` written to the generated client config | derived from bind route |

</details>

`--upstream-trust insecure` disables upstream certificate and hostname verification. Use it only for controlled debugging.

---

## How it compares

| Tool | Best fit | Proxelar tradeoff |
|------|----------|-------------------|
| mitmproxy | Mature general-purpose MITM proxy with a large addon ecosystem, local capture modes, rich flow formats, and years of protocol hardening. | Proxelar is smaller and Rust-native, with integrity-checked Lua addon packages and TUI/web interfaces, but it does not yet match mitmproxy's protocol depth or community inventory. |
| proxyfor | Lightweight Rust proxy with TUI/WebUI and export-oriented workflows. | Proxelar adds interactive interception, replay, portable/redacted exports, Lua transforms, rules, and an embeddable core. |
| Burp Suite / Caido | Professional web security testing, scanning, collaboration, and deep manual testing workflows. | Proxelar is not a security suite. It is better suited to local debugging, scripting, and development workflows. |
| Charles / Proxyman / HTTP Toolkit | Polished desktop app experience for inspecting app traffic. | Proxelar is terminal-first and scriptable, with less desktop polish but a simpler open-source CLI workflow. |

See the [full comparison](https://proxelar.micheletti.io/reference/comparison.html) for details.

---

## Current limitations

Proxelar is usable today, but it intentionally has a narrower scope than a full security suite:

- HTTP/1.1 and HTTP/2 are preserved upstream by default and can be forced with `--upstream-http-version`. HTTP/3 and QUIC interception are planned for later this year but are not available today.
- Generic TCP streams are captured as directional chunks, and fixed-target or WireGuard UDP traffic records request/response datagrams. Protobuf has a lossless wire-field JSON editor and MessagePack has a JSON editor; descriptor-backed field names and raw-TCP schemas are not yet available.
- WireGuard mode currently generates one client identity per CA directory. Proxelar does not modify system proxy settings; `--launch-browser` uses a reversible, isolated browser profile instead.
- HTTPS interception requires trusting Proxelar's local CA. Certificate-pinned apps and many Android apps will not trust user-installed CAs.
- Remote web GUI use is not a hardened multi-user deployment mode; keep it local or tunnel it carefully.

See [Known limitations](https://proxelar.micheletti.io/reference/limitations.html) and the [roadmap](ROADMAP.md).

---

## Documentation

Full documentation: **[proxelar.micheletti.io](https://proxelar.micheletti.io)**

- [Quick start](https://proxelar.micheletti.io/quick-start.html)
- [Inspect browser and curl traffic](https://proxelar.micheletti.io/guides/browser-curl.html)
- [Mock or modify a local API](https://proxelar.micheletti.io/guides/reverse-proxy-mocking.html)
- [Lua scripting API](https://proxelar.micheletti.io/scripting/api-reference.html)
- [CA trust and uninstall](https://proxelar.micheletti.io/guides/ca-trust.html)
- [Sessions and export](https://proxelar.micheletti.io/guides/sessions-and-export.html)
- [Rules and headless API](https://proxelar.micheletti.io/guides/rules-and-api.html)

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and [ROADMAP.md](ROADMAP.md).

## License

[MIT](LICENSE-MIT)
