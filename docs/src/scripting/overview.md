# Lua Scripting

Proxelar supports Lua scripts that hook into the request/response lifecycle. You can modify headers, rewrite URLs, block requests, mock API responses, transform bodies, and more — all without recompiling or changing your application.

## Running a script

```bash
proxelar --script my_script.lua
```

The script is loaded once at startup. It applies to all traffic flowing through the proxy, in both forward and reverse modes.

## Writing a script

A script defines one or both of these global functions:

```lua
function on_request(request)
    -- Called before forwarding the request to the upstream server.
    -- Modify and return the request, return a response to short-circuit,
    -- or return nil to pass through unchanged.
end

function on_response(request, response)
    -- Called before returning the response to the client.
    -- Modify and return the response, or return nil to pass through unchanged.
end
```

Both functions are optional. If a function is not defined, traffic passes through unchanged.

## Request hook

`on_request` receives a request table and can:

1. **Modify and forward** — change headers, URL, method, or body, then return the request table
2. **Short-circuit** — return a response table (with `status`, `headers`, `body`) to respond immediately without contacting the upstream server
3. **Pass through** — return `nil` (or nothing) to forward the request unchanged

```lua
-- Modify and forward
function on_request(request)
    request.headers["X-Custom"] = "value"
    return request
end

-- Short-circuit with a response
function on_request(request)
    if string.find(request.url, "blocked%.com") then
        return { status = 403, headers = {}, body = "Blocked" }
    end
end

-- Pass through (implicit nil return)
function on_request(request)
    print(request.method .. " " .. request.url)
end
```

## Response hook

`on_response` receives both the request (for context) and the response. It can modify and return the response, or return `nil` to pass through.

```lua
function on_response(request, response)
    response.headers["X-Proxy"] = "proxelar"
    return response
end
```

## Error handling

Script errors are caught, logged, and the request passes through unchanged. A buggy script can never crash the proxy. Check the log output (set `RUST_LOG=debug` for details) to see script errors.

## Feature flag

Lua scripting is behind the `scripting` feature flag, enabled by default. To build without it:

```bash
cargo install proxelar --no-default-features
```
