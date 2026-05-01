# CLI Reference

```
proxelar [OPTIONS]
```

## Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--interface` | `-i` | `tui` | Interface mode: `terminal`, `tui`, or `gui` |
| `--mode` | `-m` | `forward` | Proxy mode: `forward` or `reverse` |
| `--port` | `-p` | `8080` | Port to listen on |
| `--addr` | `-b` | `127.0.0.1` | Bind address |
| `--target` | `-t` | — | Upstream target URI (required for reverse mode) |
| `--script` | `-s` | — | Path to a Lua script for request/response hooks |
| `--gui-port` | | `8081` | Web GUI port (only used with `-i gui`) |
| `--ca-dir` | | `~/.proxelar` | Directory for CA certificate and key files |
| `--body-capture-limit` | | `free` | Maximum body bytes buffered for capture/editing; use `free`, `unlimited`, or `none` for unlimited |

## Environment variables

| Variable | Description |
|----------|-------------|
| `RUST_LOG` | Controls log verbosity. Examples: `debug`, `proxyapi=trace`, `warn` |

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

# Forward proxy with logging script
proxelar --script log_traffic.lua

# Capture only the first 1 MiB of large bodies while streaming traffic through
proxelar --body-capture-limit 1048576
```
