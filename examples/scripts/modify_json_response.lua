-- Modify JSON response bodies by injecting a field.
-- Adds "proxied": true to all JSON object responses.
--
-- Usage: proxelar --script examples/scripts/modify_json_response.lua

function on_response(request, response)
    local ct = response.headers["content-type"] or ""
    if not string.find(ct, "application/json") then return end

    -- Inject a field into JSON object responses
    if string.sub(response.body, 1, 1) == "{" then
        response.body = '{"proxied":true,' .. string.sub(response.body, 2)
    end
    return response
end
