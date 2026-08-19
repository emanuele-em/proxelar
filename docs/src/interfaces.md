# Interfaces

Proxelar provides terminal, TUI, web GUI, and headless API interfaces over the same capture stream.

## TUI (default)

```bash
proxelar
# or
proxelar -i tui
```

An interactive terminal interface built with [ratatui](https://github.com/ratatui/ratatui). Shows a table of all captured requests and WebSocket connections with nine columns: time, protocol, method, host, path, status, content-type, size, and duration.

While the alternate-screen TUI is active, tracing output is written to `~/.proxelar/proxelar.log` (or `CA_DIR/proxelar.log` when `--ca-dir` is set) so log lines cannot corrupt the display. Set `RUST_LOG` as usual and inspect the file in another terminal, for example `tail -f ~/.proxelar/proxelar.log`.

In WireGuard mode, an empty capture displays the generated client profile as a QR code. Scan it from the WireGuard mobile app; the table replaces it when the first event arrives.

### Key bindings

| Key | Action |
|-----|--------|
| `j` / `k` / `↑` / `↓` | Navigate requests |
| `Enter` | Open detail panel; press again to focus it for scrolling |
| `j` / `k` (focused) | Scroll detail content |
| `Tab` | Switch between Request and Response (or Frames) tabs |
| `/` | Enter filter mode |
| `Esc` | Close detail panel or clear filter |
| `g` / `G` | Jump to first / last request |
| `r` | Replay selected request |
| `c` | Clear all captured requests |
| `?` | Show keybinding help |
| `q` / `Ctrl+C` | Quit |

The detail panel shows headers plus decoded content-aware body views and a visible truncation marker when only a prefix was captured. JSON/XML/HTML/forms/multipart are formatted, CSS/JavaScript and structured values are highlighted, and validated raster formats render inline in the web UI. Protobuf wire fields and MessagePack values open as editable JSON; other binary request bodies open as hexadecimal bytes so invalid UTF-8 is never silently replaced. For WebSocket connections the Frames tab lists every captured frame with its direction (`↑` client→server, `↓` server→client), opcode, size, and payload preview. Raw TCP, DNS, and fixed-target/WireGuard UDP exchanges also appear as inspectable rows.

### Filtering

Press `/` to enter filter mode. Plain text searches across the flow. Use `column:value` to scope a term:

| Syntax | Matches |
|--------|---------|
| `time:14:` | rows captured after 14:00 |
| `proto:https` | rows using HTTPS or WSS |
| `method:POST` | rows whose method contains `POST` |
| `host:github` | rows whose host contains `github` |
| `path:/api` | rows whose path contains `/api` |
| `status:404` | rows whose status contains `404` |
| `type:json` | rows whose content-type contains `json` |
| `size:1.5` | rows whose formatted size contains `1.5` |
| `duration:slow` | rows whose formatted duration contains `slow` |
| `body:error` | request or response body contains `error` |
| `header:x-trace` | request or response header contains `x-trace` |

Column names are case-insensitive. Combine terms with `&`, `|`, `!`, parentheses, or implicit AND. Press `Enter` to apply, `Esc` to cancel.

## Terminal

```bash
proxelar -i terminal
```

Prints each request/response as a colored line to stdout. Useful for quick inspection or when piping output to other tools.

In WireGuard mode, terminal output begins with the client-profile QR code and configuration path before printing captured events.

Output includes timestamp, HTTP method (color-coded), URL, status code, and response size.

Pass `--quiet` (`-q`) to suppress the per-request lines; errors still go to stderr. This is useful with a [Lua script](scripting/overview.md) that produces its own output via `print()`:

```bash
proxelar -i terminal -q --script log_traffic.lua
```

## Web GUI

```bash
proxelar -i gui
```

Opens a web interface at `http://127.0.0.1:8081` (configurable with `--gui-port`). Built with [axum](https://github.com/tokio-rs/axum) and WebSocket for real-time streaming.

Features:

- Interactive request table with live updates — nine columns: Time, Proto, Method, Host, Path, Status, Type, Size, Duration
- WebSocket inspection — connections appear as live/closed rows; click to browse frames
- Unified `column:value` search bar — same syntax as the TUI filter (e.g. `status:404`, `type:json`, `proto:https`)
- Click a row to view full request/response detail
- Intercept mode — pause requests, edit method/URI/headers/body, then forward or drop
- Decoded and content-aware request/response views with truncation metadata
- Lossless text/hex request-body editing and raw TCP/DNS/UDP detail views
- Authenticated WireGuard client QR shown until the first captured event
- Light and dark mode (follows system preference)

To make the web GUI accessible from other machines:

```bash
proxelar -i gui -b 0.0.0.0
```

The current web GUI is designed for local use. Proxelar opens a login URL whose token is carried in the URL fragment, exchanges it for an `HttpOnly`, `SameSite=Strict` browser-session cookie, and immediately removes the fragment from browser history. The token is never embedded in downloadable assets. REST automation uses a separate bearer token. WebSocket connections additionally validate browser origin/host consistency. There is no TLS or multi-user authorization, so remote browser access should use an authenticated TLS tunnel.

## Headless API

```bash
proxelar -i api --api-token "$PROXELAR_TOKEN"
```

This serves the same bearer-token REST API without opening a browser. See [Rules and headless API](guides/rules-and-api.md) for endpoints and examples.
