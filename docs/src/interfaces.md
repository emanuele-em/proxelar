# Interfaces

Proxelar provides three interface modes, all showing the same live traffic data.

## TUI (default)

```bash
proxelar
# or
proxelar -i tui
```

An interactive terminal interface built with [ratatui](https://github.com/ratatui/ratatui). Shows a table of all captured requests with method, status, host, path, and response size.

### Key bindings

| Key | Action |
|-----|--------|
| `j` / `k` / `↑` / `↓` | Navigate requests |
| `Enter` | Toggle detail panel |
| `Tab` | Switch between Request and Response tabs |
| `/` | Enter filter mode (search by method or URL) |
| `Esc` | Close detail panel or clear filter |
| `g` / `G` | Jump to first / last request |
| `c` | Clear all captured requests |
| `q` / `Ctrl+C` | Quit |

The detail panel shows the full request or response including headers and body.

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
- Filter by HTTP method or URL
- Click a row to view full request/response detail
- JSON pretty-printing in the detail view
- Light and dark mode (follows system preference)

To make the web GUI accessible from other machines:

```bash
proxelar -i gui -b 0.0.0.0
```
