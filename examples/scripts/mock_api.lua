-- Return mock responses for specific API endpoints.
-- The request never reaches the upstream server.
--
-- Usage: proxelar --script examples/scripts/mock_api.lua

function on_request(request)
    if request.method == "GET" and string.find(request.url, "/api/user/me") then
        return {
            status = 200,
            headers = { ["Content-Type"] = "application/json" },
            body = '{"id": 1, "name": "Test User", "email": "test@example.com"}',
        }
    end

    if request.method == "GET" and string.find(request.url, "/api/health") then
        return {
            status = 200,
            headers = { ["Content-Type"] = "application/json" },
            body = '{"status": "ok"}',
        }
    end
end
