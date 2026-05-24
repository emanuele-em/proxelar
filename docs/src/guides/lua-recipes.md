# Lua recipes

Lua scripts define `on_request` and/or `on_response` hooks. Return a modified table to continue, return `nil` to pass through unchanged, or return a response table from `on_request` to short-circuit the upstream request.

## Add a request header

```lua
function on_request(request)
    request.headers["X-Proxied-By"] = "proxelar"
    return request
end
```

## Remove cookies

```lua
function on_request(request)
    request.headers["cookie"] = nil
    return request
end
```

## Add CORS response headers

```lua
function on_response(request, response)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response
end
```

## Block a domain

```lua
local blocked = { "ads%.example%.com", "tracker%.example%.com" }

function on_request(request)
    for _, pattern in ipairs(blocked) do
        if string.find(request.url, pattern) then
            return {
                status = 403,
                headers = { ["Content-Type"] = "text/plain" },
                body = "Blocked by Proxelar",
            }
        end
    end
end
```

## Modify a JSON response

```lua
function on_response(request, response)
    local ct = response.headers["content-type"] or ""
    if not string.find(ct, "application/json") then return end

    if string.sub(response.body, 1, 1) == "{" then
        response.body = '{"proxied":true,' .. string.sub(response.body, 2)
    end
    return response
end
```

## Use the checked-in examples

The repository includes complete scripts in [`examples/scripts/`](https://github.com/emanuele-em/proxelar/tree/main/examples/scripts):

- `add_header.lua`
- `auth_inject.lua`
- `block_domain.lua`
- `filter_by_method.lua`
- `inject_cors.lua`
- `log_traffic.lua`
- `mock_api.lua`
- `modify_json_response.lua`
- `redirect.lua`
- `request_body_modify.lua`
- `rewrite_html.lua`
- `strip_cookies.lua`

See the [Lua API reference](../scripting/api-reference.md) for all fields and return values.
