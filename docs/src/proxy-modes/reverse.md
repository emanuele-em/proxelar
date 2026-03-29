# Reverse Proxy

In reverse proxy mode, Proxelar sits in front of a backend service. Clients connect to Proxelar directly (without proxy configuration), and all requests are forwarded to the specified target.

This is useful for debugging local APIs, injecting headers, mocking endpoints, or testing how your frontend handles modified responses.

## Usage

```bash
proxelar -m reverse --target http://localhost:3000
```

Clients connect to `http://127.0.0.1:8080` and Proxelar forwards everything to `http://localhost:3000`.

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
```

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
