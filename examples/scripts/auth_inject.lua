-- Inject an Authorization header into requests to a specific API.
-- Useful for testing authenticated endpoints without modifying client code.
--
-- Usage: proxelar --script examples/scripts/auth_inject.lua

local TOKEN = "Bearer my-dev-token-12345"

function on_request(request)
    if string.find(request.url, "api%.example%.com") then
        request.headers["Authorization"] = TOKEN
    end
    return request
end
