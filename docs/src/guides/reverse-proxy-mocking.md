# Mock or modify a local API

Reverse proxy mode puts Proxelar in front of a service without configuring the client as an explicit proxy. This is useful for local frontend development, API testing, and scripted response changes.

## Start a reverse proxy

If your app normally calls a backend on `http://localhost:3000`, run:

```bash
proxelar -m reverse --target http://localhost:3000
```

Clients connect to:

```text
http://127.0.0.1:8080
```

Proxelar forwards requests to `http://localhost:3000` while preserving the path and query string.

## Mock one endpoint

Create `mock_user.lua`:

```lua
function on_request(request)
    if request.method == "GET" and string.find(request.url, "/api/user/me") then
        return {
            status = 200,
            headers = { ["Content-Type"] = "application/json" },
            body = '{"id":1,"name":"Local Test User"}',
        }
    end
end
```

Run:

```bash
proxelar -m reverse --target http://localhost:3000 --script mock_user.lua
```

Requests to `/api/user/me` are answered by the script. Other requests pass through to the target.

## Inject development headers

```lua
function on_request(request)
    request.headers["Authorization"] = "Bearer local-dev-token"
    request.headers["X-Forwarded-By"] = "proxelar"
    return request
end
```

## Simulate a failure

```lua
function on_request(request)
    if string.find(request.url, "/api/payments") then
        return {
            status = 503,
            headers = { ["Content-Type"] = "application/json" },
            body = '{"error":"payments unavailable in local test"}',
        }
    end
end
```

## Notes

- Reverse proxy mode does not require browser or OS proxy configuration.
- Use `-i gui` if you prefer the web UI while developing.
- Use `--upstream-trust default+ca:/path/to/ca.pem` if the upstream service uses a private HTTPS CA.
- For HTTPS clients connecting to Proxelar itself, use forward proxy mode today; reverse proxy TLS termination for inbound clients is not the main supported workflow.
