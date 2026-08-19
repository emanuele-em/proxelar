-- Add custom headers to every request passing through the proxy.
--
-- Usage: proxelar --script examples/scripts/add_header.lua

function on_request(request)
    request.headers:set("X-Forwarded-By", "proxelar")
    request.headers:set("X-Request-Time", os.date("%Y-%m-%dT%H:%M:%S"))
    return request
end
