-- Log request/response summary to stdout.
-- Shows method, URL, status code, content type, and body size.
--
-- Usage: proxelar -i terminal --script examples/scripts/log_traffic.lua

function on_request(request)
    print(string.format("[REQ] %s %s", request.method, request.url))
end

function on_response(request, response)
    local ct = response.headers["content-type"] or "unknown"
    local size = #response.body
    print(string.format("[RES] %s %s -> %d (%s, %d bytes)",
        request.method, request.url, response.status, ct, size))
end
