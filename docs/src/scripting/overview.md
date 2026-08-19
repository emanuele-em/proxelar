# Lua Scripting

Proxelar supports Lua scripts that hook into the request/response lifecycle. You can modify headers, rewrite URLs, block requests, mock API responses, transform bodies, and more — all without recompiling or changing your application.

## Running a script

```bash
proxelar --script my_script.lua
```

The script is loaded at startup and automatically reloaded after file changes. A valid edit becomes active on the next hook call. If a reload is invalid, Proxelar logs the error and keeps the last known-good script. Hooks apply across HTTP-capable proxy modes.

## Writing a script

A script can define any of these global functions:

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

function on_websocket_frame(frame)
    -- frame.direction is "client_to_server" or "server_to_client".
    -- Called only for text/binary data; frame.payload is binary-safe.
    -- Return a string to replace the payload, false to drop, or nil to pass.
end
```

Every function is optional. If a function is not defined, traffic passes through unchanged.
Ping, pong, and close frames remain visible in captures, but Rama owns their protocol handling and Lua cannot replace, drop, or synthesize them.

## Portable addon directories

`--script` also accepts a directory containing `init.lua`. Pure-Lua modules beside it are automatically available through `require`, including nested `module/init.lua` packages:

```text
my-addon/
├── init.lua
└── redact.lua
```

```lua
-- my-addon/init.lua
local redact = require("redact")

function on_request(request)
    return redact.request(request)
end
```

Run it with `proxelar --script ./my-addon`. This directory convention is the distributable unit for community addons. Addons must use pure Lua; native C modules are intentionally unavailable.

### Validated packages and the local catalog

Published addons should include `proxelar-addon.json`. Schema version 1 records
the package name, semantic version, description, entrypoint, hooks, whether it
requires native Lua modules, and a lowercase SHA-256 digest for every package
file. Files not declared by the manifest are rejected, as are missing files,
digest mismatches, symlinks, special files, absolute paths, and parent traversal.

```json
{
  "schema_version": 1,
  "name": "header-tagger",
  "version": "1.0.0",
  "description": "Adds a diagnostic request header.",
  "entrypoint": "init.lua",
  "hooks": ["request"],
  "requires_native_modules": false,
  "files": {
    "init.lua": "<lowercase SHA-256>"
  }
}
```

Use the same catalog from development, CI, and production:

```bash
proxelar addon verify ./my-addon
proxelar addon install ./my-addon
proxelar addon list
proxelar addon inspect my-addon
proxelar --addon my-addon
```

Installation validates the complete source package first, copies only regular
declared files with private permissions, and atomically renames the result into
`CA_DIR/addons`. It never overwrites an existing version. Use `--addons-dir` to
select another catalog. Manifest-free directories remain accepted through
`--script` for an edit-and-reload development loop; they are deliberately not
installable catalog packages.

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

The same fail-open policy applies to response and WebSocket hooks: runtime failures log and forward the original message.

## Native C modules

Native C modules are intentionally unavailable. Proxelar uses mlua's safe
standard-library subset and preserves `#![forbid(unsafe_code)]` in the core
crate. A validated package whose manifest sets
`requires_native_modules: true` fails closed before its entrypoint runs. Prefer
pure Lua modules or implement broadly useful functionality in the audited Rust
core.

## Feature flag

Lua scripting is behind the `scripting` feature flag, enabled by default. To build without it:

```bash
cargo install proxelar --no-default-features
```
