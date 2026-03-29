-- Modify POST request bodies by injecting a field into JSON payloads.
-- Adds an "injected_by" field to every JSON POST request.
--
-- Usage: proxelar --script examples/scripts/request_body_modify.lua

function on_request(request)
    if request.method ~= "POST" then return end
    local ct = request.headers["content-type"] or ""

    if string.find(ct, "application/json") and string.sub(request.body, 1, 1) == "{" then
        request.body = '{"injected_by":"proxelar",' .. string.sub(request.body, 2)
    end
    return request
end
