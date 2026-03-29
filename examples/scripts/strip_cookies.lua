-- Remove known tracking cookies from outgoing requests.
-- Keeps functional cookies intact while stripping analytics trackers.
--
-- Usage: proxelar --script examples/scripts/strip_cookies.lua

local tracking_cookies = { "fbp", "_ga", "_gid", "fr", "datr" }

function on_request(request)
    local cookie = request.headers["cookie"]
    if not cookie then return end

    local parts = {}
    for pair in string.gmatch(cookie, "([^;]+)") do
        pair = string.match(pair, "^%s*(.-)%s*$") -- trim whitespace
        local name = string.match(pair, "^([^=]+)")
        local dominated = false
        for _, tc in ipairs(tracking_cookies) do
            if name == tc then
                dominated = true
                break
            end
        end
        if not dominated then
            table.insert(parts, pair)
        end
    end

    if #parts > 0 then
        request.headers["cookie"] = table.concat(parts, "; ")
    else
        request.headers["cookie"] = nil
    end
    return request
end
