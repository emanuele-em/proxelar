# Script Examples

All examples below are complete, working scripts. They are also available in the [`examples/scripts/`](https://github.com/emanuele-em/proxelar/tree/main/examples/scripts) directory.

## Add headers to requests

```lua
function on_request(request)
    request.headers["X-Forwarded-By"] = "proxelar"
    request.headers["X-Request-Time"] = os.date("%Y-%m-%dT%H:%M:%S")
    return request
end
```

## Block domains

```lua
local blocked = {
    "ads%.example%.com",
    "tracker%.example%.com",
    "analytics%.bad%.com",
}

function on_request(request)
    for _, pattern in ipairs(blocked) do
        if string.find(request.url, pattern) then
            return {
                status = 403,
                headers = { ["Content-Type"] = "text/plain" },
                body = "Blocked by Proxelar: " .. request.url,
            }
        end
    end
end
```

## Mock API endpoints

```lua
function on_request(request)
    if request.method == "GET" and string.find(request.url, "/api/user/me") then
        return {
            status = 200,
            headers = { ["Content-Type"] = "application/json" },
            body = '{"id": 1, "name": "Test User", "email": "test@example.com"}',
        }
    end
end
```

## Redirect requests to a different host

```lua
function on_request(request)
    request.url = string.gsub(request.url, "old%-api%.example%.com", "new-api.example.com")
    return request
end
```

## Inject CORS headers

```lua
function on_response(request, response)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response
end
```

## Log traffic to stdout

```lua
function on_request(request)
    print(string.format("[REQ] %s %s", request.method, request.url))
end

function on_response(request, response)
    local ct = response.headers["content-type"] or "unknown"
    local size = #response.body
    print(string.format("[RES] %s %s -> %d (%s, %d bytes)",
        request.method, request.url, response.status, ct, size))
end
```

## Inject authentication

```lua
local TOKEN = "Bearer my-dev-token-12345"

function on_request(request)
    if string.find(request.url, "api%.example%.com") then
        request.headers["Authorization"] = TOKEN
    end
    return request
end
```

## Modify JSON response bodies

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

## Inject a banner into HTML pages

```lua
function on_response(request, response)
    local ct = response.headers["content-type"] or ""
    if not string.find(ct, "text/html") then return end

    local banner = '<div style="position:fixed;top:0;left:0;right:0;'
        .. 'background:#ff6b35;color:white;text-align:center;'
        .. 'padding:4px;z-index:99999;font-size:12px;">'
        .. 'Proxied by Proxelar</div>'

    response.body = string.gsub(response.body, "<body>", "<body>" .. banner, 1)
    return response
end
```

## Only allow GET and HEAD

```lua
function on_request(request)
    if request.method ~= "GET" and request.method ~= "HEAD" then
        return {
            status = 405,
            headers = {
                ["Content-Type"] = "text/plain",
                ["Allow"] = "GET, HEAD",
            },
            body = "Method " .. request.method .. " not allowed by proxy policy",
        }
    end
end
```

## Strip tracking cookies

```lua
local tracking_cookies = { "fbp", "_ga", "_gid", "fr", "datr" }

function on_request(request)
    local cookie = request.headers["cookie"]
    if not cookie then return end

    local parts = {}
    for pair in string.gmatch(cookie, "([^;]+)") do
        pair = string.match(pair, "^%s*(.-)%s*$")
        local name = string.match(pair, "^([^=]+)")
        local dominated = false
        for _, tc in ipairs(tracking_cookies) do
            if name == tc then dominated = true; break end
        end
        if not dominated then table.insert(parts, pair) end
    end

    if #parts > 0 then
        request.headers["cookie"] = table.concat(parts, "; ")
    else
        request.headers["cookie"] = nil
    end
    return request
end
```

## Modify POST request bodies

```lua
function on_request(request)
    if request.method ~= "POST" then return end
    local ct = request.headers["content-type"] or ""

    if string.find(ct, "application/json") and string.sub(request.body, 1, 1) == "{" then
        request.body = '{"injected_by":"proxelar",' .. string.sub(request.body, 2)
    end
    return request
end
```
