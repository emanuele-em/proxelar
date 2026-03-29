# Quick Start

## 1. Start the proxy

```bash
proxelar
```

This starts Proxelar in forward proxy mode with the interactive TUI on `127.0.0.1:8080`.

## 2. Install the CA certificate

To inspect HTTPS traffic, your system needs to trust Proxelar's CA certificate. The easiest way:

1. Configure your browser or system proxy to `127.0.0.1:8080`
2. Visit [http://proxel.ar](http://proxel.ar) through the proxy
3. Follow the platform-specific installation instructions on the page

Alternatively, manually install `~/.proxelar/proxelar-ca.pem`.

## 3. Browse through the proxy

Configure your system or browser proxy to `127.0.0.1:8080`. All HTTP and HTTPS traffic now flows through Proxelar and appears in the TUI.

Use the keyboard to navigate:

| Key | Action |
|-----|--------|
| `j` / `k` / arrows | Navigate requests |
| `Enter` | Toggle detail panel |
| `Tab` | Switch between Request / Response |
| `/` | Filter |
| `Esc` | Close panel / clear filter |
| `g` / `G` | Jump to top / bottom |
| `c` | Clear all requests |
| `q` / `Ctrl+C` | Quit |

## 4. Try a Lua script

Create a file called `script.lua`:

```lua
function on_request(request)
    request.headers["X-Proxied-By"] = "proxelar"
    return request
end
```

Run Proxelar with the script:

```bash
proxelar --script script.lua
```

Every request passing through the proxy now has the `X-Proxied-By` header injected.
