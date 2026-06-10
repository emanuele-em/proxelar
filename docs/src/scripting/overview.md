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

`on_request` receives a request table and can return one of three things:

- **The request table** — forward it (modified or not)
- **A response table** (with a `status` field) — short-circuit and return that response directly, without contacting the upstream server
- **`nil`** (or no return) — pass through unchanged

```lua
function on_request(request)
    -- Pass through logging only
    if string.find(request.url, "blocked%.com") then
        return { status = 403, headers = {}, body = "Blocked" }  -- short-circuit
    end

    request.headers["X-Custom"] = "value"
    return request  -- forward modified request
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

## Native C modules

By default the Lua VM runs in safe mode, which blocks native C modules — `require` of a C module fails with `can't load C modules in safe mode`. To use one (for example [`lua-protobuf`](https://github.com/starwing/lua-protobuf)), pass `--allow-c-modules`:

```bash
proxelar --script decode.lua --allow-c-modules
```

This runs the VM in unsafe mode: loaded modules execute unsandboxed native code in the proxy process, so only use it with scripts you trust. The module must target Lua 5.4 (the version proxelar embeds).

On **Windows**, the standard release binary statically links Lua and cannot load C modules. Use the `…-cmodules` release archive instead, which links a shared `lua54.dll` bundled alongside the executable.

## Feature flag

Lua scripting is behind the `scripting` feature flag, enabled by default. To build without it:

```bash
cargo install proxelar --no-default-features
```
