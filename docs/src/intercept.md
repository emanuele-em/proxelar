# Intercept & Modify Traffic

Intercept mode pauses requests mid-flight so you can inspect, edit, and decide what to do before they reach the server.

## How it works

When intercept is **on**, every request is held until you act on it. Nothing is forwarded automatically. When intercept is **off**, traffic flows through normally (still captured and displayed).

## TUI

### Toggle intercept

Press **`i`** to turn intercept on or off. The status bar shows a red **`INTERCEPT`** badge when active.

### Act on a request

When a request arrives it appears as a `⏸` row. Navigate to it with `j`/`k`, then:

| Key | Action |
|-----|--------|
| `f` | Forward the request (as-is or with your edits) |
| `d` | Drop — returns a 504 to the client |
| `e` | Open the inline editor |

### Edit inline

Press **`e`** to open the editor. The full raw HTTP request is shown and fully editable — method, URI, headers, and body.

```
POST /api/login HTTP/1.1
host: example.com
content-type: application/json

{"user":"alice","pass":"secret"}
```

- **Arrow keys / Home / End** — move the cursor
- **Enter** — insert a new line
- **Backspace / Delete** — delete characters
- **Esc** — finish editing (request stays held, ready to forward)
- **`f`** — forward (with your edits applied)
- **`d`** — drop
- **Esc** (again, when not typing) — discard your edits

> **Binary bodies** — if the original body is not valid UTF-8 the editor shows a ⚠ warning. The content is displayed lossily; edits may corrupt binary data.

## Web GUI

Click the **`⏸ Intercept: OFF`** button in the toolbar to enable intercept. The button turns red and shows a pending-request count.

Pending requests appear in the table with an amber left border. Click a row to open the editor panel:

- Edit the **method**, **URI**, **headers**, and **body** directly
- Click **Forward** to send (with any edits you made)
- Click **Drop (504)** to block the request
- Press **Ctrl+Enter** as a keyboard shortcut for Forward
- Press **Esc** or **×** to close the panel without acting (request stays pending)

## Turning intercept off

Press **`i`** (TUI) or click the intercept button (web) again. All pending requests are forwarded immediately so clients do not hang.
