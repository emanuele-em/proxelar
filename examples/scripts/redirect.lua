-- Redirect requests from one host to another.
-- Useful for testing against a different backend without changing client config.
--
-- Usage: proxelar --script examples/scripts/redirect.lua

function on_request(request)
    request.url = string.gsub(request.url, "old%-api%.example%.com", "new-api.example.com")
    return request
end
