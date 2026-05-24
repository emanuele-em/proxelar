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

- **One local binary** — install with Homebrew, Cargo, Docker/Podman, or GitHub releases.
- **Three interfaces** — TUI by default, plain terminal output, or a browser GUI.
- **Lua scripting** — `on_request` and `on_response` hooks can rewrite, block, short-circuit, or mock traffic.
- **Interactive intercept** — pause requests, edit method/URI/headers/body, forward, drop, or replay.
- **HTTPS MITM** — local CA generation, per-host certificates, and a built-in certificate install page.
- **Forward and reverse modes** — inspect configured clients or put Proxelar in front of a local service.
- **WebSocket inspection** — capture connections and browse frames by direction, opcode, and payload preview.

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

---

## Interfaces

```bash
proxelar              # interactive TUI (default)
proxelar -i terminal  # plain terminal output
proxelar -i gui       # web GUI at http://localhost:8081
```

Common options:

```bash
proxelar -m reverse --target http://localhost:3000   # reverse proxy
proxelar -b 0.0.0.0 -p 9090                         # custom bind/port
proxelar --script examples/scripts/block_domain.lua  # with a Lua script
proxelar --body-capture-limit 1048576                # cap captured/editable body bytes
proxelar --upstream-trust default+ca:/path/ca.pem    # trust an extra upstream CA
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
| `--upstream-trust` | Upstream TLS trust policy: `default`, `default+ca:/path/ca.pem`, `ca-only:/path/ca.pem`, or `insecure` | `default` |

</details>

`--upstream-trust insecure` disables upstream certificate and hostname verification. Use it only for controlled debugging.

---

## How it compares

| Tool | Best fit | Proxelar tradeoff |
|------|----------|-------------------|
| mitmproxy | Mature general-purpose MITM proxy with a large addon ecosystem, transparent/local capture modes, rich flow formats, and years of protocol hardening. | Proxelar is smaller and Rust-native, with Lua scripting and TUI/web interfaces, but it does not yet match mitmproxy's depth. |
| proxyfor | Lightweight Rust proxy with TUI/WebUI and export-oriented workflows. | Proxelar emphasizes Lua transforms, interactive intercept, replay, and an embeddable core; proxyfor currently has stronger export ergonomics. |
| Burp Suite / Caido | Professional web security testing, scanning, collaboration, and deep manual testing workflows. | Proxelar is not a security suite. It is better suited to local debugging, scripting, and development workflows. |
| Charles / Proxyman / HTTP Toolkit | Polished desktop app experience for inspecting app traffic. | Proxelar is terminal-first and scriptable, with less desktop polish but a simpler open-source CLI workflow. |

See the [full comparison](https://proxelar.micheletti.io/reference/comparison.html) for details.

---

## Current limitations

Proxelar is usable today, but some mature proxy workflows are still on the roadmap:

- Captured sessions are in memory; HAR, curl, raw-flow export, and session reload are not implemented yet.
- Body views and editors are byte-oriented; gzip/br/zstd decoding, charset handling, and richer pretty views are limited.
- Transparent/local capture, SOCKS5 mode, upstream proxy chaining, and DNS inspection are not implemented.
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

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and [ROADMAP.md](ROADMAP.md).

## License

[MIT](LICENSE-MIT)
