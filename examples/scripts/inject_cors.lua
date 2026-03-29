-- Add CORS headers to all responses.
-- Useful for local development when the backend doesn't set CORS headers.
--
-- Usage: proxelar --script examples/scripts/inject_cors.lua

function on_response(request, response)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response
end
