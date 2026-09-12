# CLI Reference

```
proxelar [OPTIONS]
proxelar addon <list|inspect|verify|install> [OPTIONS]
```

## Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--interface` | `-i` | `tui` | Interface: `terminal`, `tui`, `gui`, or headless `api` |
| `--mode` | `-m` | `forward` | Mode: `forward`, `reverse`, `wireguard`, `socks5`, `dns`, or `udp` |
| `--port` | `-p` | `8080` | Port to listen on |
| `--addr` | `-b` | `127.0.0.1` | Bind address |
| `--target` | `-t` | — | `http://`, `https://`, or `http3://` upstream URI for reverse; `HOST:PORT` for UDP |
| `--script` | `-s` | — | Lua script file or addon directory containing `init.lua` |
| `--addon` | | — | Load a validated installed addon by name (conflicts with `--script`) |
| `--addons-dir` | | `CA_DIR/addons` | Local addon catalog used by runtime and addon commands |
| `--quiet` | `-q` | | Suppress per-request output (only used with `-i terminal`) |
| `--gui-port` | | `8081` | Web GUI port (only used with `-i gui`) |
| `--ca-dir` | | `~/.proxelar` | Directory for CA certificate and key files |
| `--body-capture-limit` | | `free` | Maximum body bytes buffered for capture/editing; use `free`, `unlimited`, or `none` for unlimited |
| `--upstream-trust` | | `default` | Upstream TLS trust policy: `default`, `default+ca:/path/ca.pem`, `ca-only:/path/ca.pem`, or `insecure` |
| `--upstream-proxy` | | — | Chain traffic through `http://HOST:PORT` or `socks5://HOST:PORT` |
| `--upstream-proxy-auth` | | — | Upstream proxy credentials as `USERNAME:PASSWORD` |
| `--load-session` | | — | Load a native session before capture |
| `--import-har` | | — | Import HAR before capture (conflicts with `--load-session`) |
| `--save-session` | | — | Save a native session on clean shutdown |
| `--export-har` | | — | Export HTTP flows as HAR on clean shutdown |
| `--export-curl` | | — | Export requests as curl commands on clean shutdown |
| `--export-raw` | | — | Write raw request/response files to a directory on clean shutdown |
| `--export-secrets` | | off | Disable default credential/query-secret redaction in exports |
| `--rules` | | — | Load declarative routing rules from JSON |
| `--map-local` | | — | Repeatable `URL_PREFIX=DIR` local mapping |
| `--map-remote` | | — | Repeatable `URL_PREFIX=TARGET_PREFIX` rewrite |
| `--api-token` | | random | Fixed bearer token for the GUI/headless API |
| `--launch-browser` | | off | Launch an isolated Chromium-family profile through the proxy |
| `--dns-upstream` | | `1.1.1.1:53` | Recursive resolver used in DNS mode |
| `--dns-map` | | — | Repeatable DNS override as `DOMAIN=IP` |
| `--wireguard-endpoint` | | derived | Public/LAN `HOST:PORT` written to the generated WireGuard client config |

`--upstream-trust insecure` disables upstream certificate and hostname verification. Use it only for controlled debugging; it makes upstream HTTPS traffic vulnerable to MITM.

## Environment variables

| Variable | Description |
|----------|-------------|
| `RUST_LOG` | Controls log verbosity. Examples: `debug`, `proxyapi=trace`, `warn`. TUI logs go to `CA_DIR/proxelar.log`; other interfaces log to stderr. |

## Examples

```bash
# Default: forward proxy with TUI
proxelar

# Terminal output on custom port
proxelar -i terminal -p 9090

# Web GUI accessible from the network
proxelar -i gui -b 0.0.0.0

# Reverse proxy with script
proxelar -m reverse --target http://localhost:3000 --script auth.lua

# UDP-only HTTP/3 reverse proxy
proxelar -m reverse --target http3://localhost:4433

# Forward proxy with logging script
proxelar --script log_traffic.lua

# Verify, install, discover, and run an integrity-checked addon package
proxelar addon verify ./examples/addons/header-tagger
proxelar addon install ./examples/addons/header-tagger
proxelar addon list
proxelar --addon header-tagger

# Show only the script's print() output, no per-request lines
proxelar -i terminal -q --script log_traffic.lua

# Capture only the first 1 MiB of large bodies while streaming traffic through
proxelar --body-capture-limit 1048576

# Trust a private upstream CA in addition to the default Mozilla roots
proxelar --upstream-trust default+ca:/path/to/ca.pem

# Trust only a private upstream CA
proxelar --upstream-trust ca-only:/path/to/ca.pem

# Capture through a corporate proxy and save redacted interoperable exports
proxelar --upstream-proxy http://proxy.example:8080 \
  --save-session capture.proxelar.json --export-har capture.har

# SOCKS5 listener
proxelar -m socks5 -p 1080

# DNS inspection with a local override
proxelar -m dns -p 5353 --dns-map api.example.test=127.0.0.1

# Fixed-target raw UDP inspection
proxelar -m udp -p 9001 --target upstream.example:9000

# Mobile/IoT capture; scan the displayed QR or import ~/.proxelar/proxelar-wg.conf
proxelar -m wireguard -b 0.0.0.0 -p 51820 \
  --wireguard-endpoint 192.168.1.10:51820

# Headless bearer-token API
proxelar -i api --api-token "$PROXELAR_TOKEN"
```

Session and export outputs are finalized after Ctrl+C or another clean shutdown. Native session files contain the full captured data; HAR, curl, and raw exports redact authorization, proxy authorization, cookies, and common secret query parameters unless `--export-secrets` is supplied.
