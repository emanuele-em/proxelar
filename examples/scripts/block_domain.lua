-- Block requests to specific domains.
-- Returns a 403 Forbidden response without contacting the upstream server.
--
-- Usage: proxelar --script examples/scripts/block_domain.lua

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
