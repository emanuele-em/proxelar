-- Inject a banner into HTML responses to indicate they are proxied.
-- Adds a fixed-position notification bar at the top of every HTML page.
--
-- Usage: proxelar --script examples/scripts/rewrite_html.lua

function on_response(request, response)
    local ct = response.headers["content-type"] or ""
    if not string.find(ct, "text/html") then return end

    local banner = '<div style="position:fixed;top:0;left:0;right:0;background:#ff6b35;'
        .. 'color:white;text-align:center;padding:4px;z-index:99999;font-size:12px;">'
        .. 'Proxied by Proxelar</div>'

    response.body = string.gsub(response.body, "<body>", "<body>" .. banner, 1)
    return response
end
