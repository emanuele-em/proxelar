-- Only allow GET and HEAD requests through the proxy.
-- All other HTTP methods get a 405 Method Not Allowed response.
--
-- Usage: proxelar --script examples/scripts/filter_by_method.lua

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
