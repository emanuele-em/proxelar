# Reverse Proxy

In reverse proxy mode, Proxelar sits in front of a backend service. Clients connect to Proxelar directly (without proxy configuration), and all requests are forwarded to the specified target.

This is useful for debugging local APIs, injecting headers, mocking endpoints, or testing how your frontend handles modified responses.

## Usage

```bash
proxelar -m reverse --target http://localhost:3000
```

Clients connect to `http://127.0.0.1:8080` and Proxelar forwards everything to `http://localhost:3000`.

The target scheme selects listeners and upstream transports deterministically:

- `http://` uses cleartext TCP.
- `https://` listens on TCP and, when the official HTTP/3 feature is enabled, UDP on the same port. TCP follows the client's negotiated H1/H2 protocol; UDP carries H3.
- `http3://` listens only on UDP and uses H3 upstream.

Client ALPN offers are propagated upstream in their original order. Proxelar does not probe QUIC heuristically or switch protocols after a timeout.

An `https://` target also makes the client-facing TCP listener use TLS. Proxelar
mints its listener certificate for the target hostname, so point that hostname
at the Proxelar listener and trust the Proxelar CA in the client. The negotiated
client ALPN selects H1 or H2 on TCP; clients offering H3 can use the UDP listener
on the same port.

## How it works

1. The client sends a request to `127.0.0.1:8080`
2. Proxelar rewrites the URI to the target (preserving path and query)
3. The `Host` header is updated to match the target
4. Lua `on_request` / `on_response` hooks run (if a script is loaded)
5. The response is returned to the client

## Examples

```bash
# Reverse proxy to a local service
proxelar -m reverse --target http://localhost:3000

# Custom port (clients connect to 4000, forwarded to 3000)
proxelar -m reverse --target http://localhost:3000 -p 4000

# With a Lua script that injects auth headers
proxelar -m reverse --target http://localhost:3000 --script auth_dev.lua

# With web GUI
proxelar -m reverse --target http://localhost:3000 -i gui

# HTTPS upstream with a private CA
proxelar -m reverse --target https://localhost:3000 --upstream-trust default+ca:/path/to/ca.pem

# HTTP/3 in both directions over UDP only
proxelar -m reverse --target http3://localhost:4433
```

For upstream HTTPS and H3, Proxelar uses bundled Mozilla/WebPKI roots by default. Use `--upstream-trust default+ca:/path/to/ca.pem` to add a private CA, `--upstream-trust ca-only:/path/to/ca.pem` to trust only that CA, or `--upstream-trust insecure` for temporary debugging without certificate or hostname verification. `insecure` makes upstream encrypted traffic vulnerable to MITM.

## Common use cases with scripting

### Inject authentication

```lua
function on_request(request)
    request.headers["Authorization"] = "Bearer dev-token-12345"
    return request
end
```

### Add security headers

```lua
function on_response(request, response)
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response
end
```

### Simulate errors

```lua
function on_request(request)
    if string.find(request.url, "/api/payments") then
        return {
            status = 500,
            headers = { ["Content-Type"] = "application/json" },
            body = '{"error": "Internal Server Error"}',
        }
    end
end
```
