# Quick Start

## 1. Start the proxy

```bash
proxelar
```

This starts Proxelar in forward proxy mode with the interactive TUI on `127.0.0.1:8080`.

## 2. Install the CA certificate

Configure your system or browser proxy to `127.0.0.1:8080`, then visit [http://proxel.ar](http://proxel.ar) through the proxy. The page provides direct certificate downloads and platform-specific installation instructions.

Alternatively, manually install `~/.proxelar/proxelar-ca.pem`. See [CA Certificate](./ca-certificate.md) for all platforms.

## 3. Browse through the proxy

All HTTP and HTTPS traffic now flows through Proxelar and appears in the TUI. Press `?` for the full keybinding reference, or see [Interfaces](./interfaces.md) for details on the TUI, terminal, and web GUI modes.

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
