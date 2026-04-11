# Interfaces

Proxelar provides three interface modes, all showing the same live traffic data.

## TUI (default)

```bash
proxelar
# or
proxelar -i tui
```

An interactive terminal interface built with [ratatui](https://github.com/ratatui/ratatui). Shows a table of all captured requests and WebSocket connections with method, status, host, path, and response size.

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

The detail panel shows the full request or response including headers and body. For WebSocket connections the Frames tab lists every captured frame with its direction (`↑` client→server, `↓` server→client), opcode, size, and payload preview.

### Filtering

Press `/` to enter filter mode. Plain text searches across method and URL. Use `column:value` to scope the search to a single column:

| Syntax | Matches |
|--------|---------|
| `method:POST` | rows whose method contains `POST` |
| `status:404` | rows whose status contains `404` |
| `host:github` | rows whose host contains `github` |
| `path:/api` | rows whose path contains `/api` |
| `size:1.5` | rows whose formatted size contains `1.5` |

Column names are case-insensitive. Press `Enter` to apply, `Esc` to cancel.

## Terminal

```bash
proxelar -i terminal
```

Prints each request/response as a colored line to stdout. Useful for quick inspection or when piping output to other tools.

Output includes timestamp, HTTP method (color-coded), URL, status code, and response size.

## Web GUI

```bash
proxelar -i gui
```

Opens a web interface at `http://127.0.0.1:8081` (configurable with `--gui-port`). Built with [axum](https://github.com/tokio-rs/axum) and WebSocket for real-time streaming.

Features:

- Interactive request table with live updates
- WebSocket inspection — connections appear as live/closed rows; click to browse frames
- Filter by HTTP method or URL
- Click a row to view full request/response detail
- JSON pretty-printing in the detail view
- Light and dark mode (follows system preference)

To make the web GUI accessible from other machines:

```bash
proxelar -i gui -b 0.0.0.0
```
