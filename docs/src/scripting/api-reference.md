# API Reference

## Request table

The `on_request` function receives a table with these fields:

| Field | Type | Description |
|-------|------|-------------|
| `method` | string | HTTP method (`"GET"`, `"POST"`, `"PUT"`, `"DELETE"`, etc.) |
| `url` | string | Full request URL (`"https://example.com/path?q=1"`) |
| `headers` | header object | Ordered, byte-safe request headers (see [Headers](#headers) below) |
| `body` | string | Request body (may contain binary data, empty string for GET/HEAD) |

All fields are readable and writable. Modify them in place and return the table to forward the modified request.

`body` is always plaintext: if the message uses a supported `Content-Encoding`
(`gzip`, `deflate`, or `br`), the proxy decompresses it before calling the hook
and re-compresses your result to the same encoding on the way out, refreshing
`Content-Length`. Remove the `Content-Encoding` header to forward the body
uncompressed instead. Any other encoding is passed through untouched. See
[Content encoding](#content-encoding) below.

## Response table

The `on_response` function receives two arguments:

1. **request** — a table with `method` and `url` fields (for context)
2. **response** — a table with these fields:

| Field | Type | Description |
|-------|------|-------------|
| `status` | number | HTTP status code (`200`, `404`, `500`, etc.) |
| `headers` | header object | Ordered, byte-safe response headers |
| `body` | string | Response body (plaintext — see [Content encoding](#content-encoding)) |

## Short-circuit response

To respond immediately without contacting the upstream server, return a table with a `status` field from `on_request`:

```lua
return {
    status = 403,
    headers = { ["Content-Type"] = "text/plain" },
    body = "Forbidden",
}
```

The presence of the `status` field is what distinguishes a response from a modified request.

## Headers

Headers are ordered objects. HTTP/1 names keep their original casing; native
HTTP/2 and HTTP/3 names arrive lowercase as required by those protocols.
Duplicate fields stay distinct, values are Lua strings so non-UTF-8 bytes
round-trip safely, and name lookup is ASCII case-insensitive. A name supplied by
a script retains that spelling in the Lua object and is lowercased by the H2/H3
wire adapter when necessary.

Read the first value or every duplicate value with `get` and `get_all`:

```lua
request.headers:get("content-type")       -- "application/json" or nil
response.headers:get_all("set-cookie")   -- {"session=abc", "lang=en"}
```

Modify headers without collapsing unrelated fields:

```lua
request.headers:set("x-custom", "value") -- replace all values at the first position
response.headers:add("set-cookie", "a=1") -- append one duplicate
response.headers:add("set-cookie", "b=2")
request.headers:remove("cookie")            -- remove all values, return count
```

Iterate in exact field order, including duplicate names:

```lua
for name, value in request.headers:iter() do
    print(name, value)
end

-- `pairs(request.headers)` has the same ordered behavior.
```

For compatibility, bracket reads return the first value, string assignments
behave like `set`, and assigning `nil` behaves like `remove`. New scripts should
prefer the explicit methods, especially for duplicate headers. Plain Lua header
tables remain accepted when constructing a short-circuit response.

## Content encoding

Scripts work on decompressed bodies. When a request or response carries a
`Content-Encoding` the proxy understands, the body is decoded before your hook
runs and re-encoded to the same scheme afterward, with `Content-Length` updated
to match.

| `Content-Encoding` | Behavior |
|--------------------|----------|
| `gzip` / `deflate` / `br` | Decoded for the hook, re-encoded on output |
| absent / `identity` | Passed through as-is |
| anything else (e.g. `zstd`) | Passed through compressed, untouched |

To change the wire encoding, edit the `Content-Encoding` header in your hook:

```lua
-- Forward the response uncompressed
response.headers:remove("content-encoding")
response.body = "now plaintext on the wire"
```

If re-encoding fails, the proxy strips `Content-Encoding` and sends the body
uncompressed rather than corrupting it. Bodies larger than
`--body-capture-limit` stream through unchanged and are never decoded.

## Return values

### on_request

| Return | Effect |
|--------|--------|
| Request table | Forward the (modified) request to upstream |
| Response table (has `status`) | Short-circuit — return this response directly |
| `nil` (or no return) | Pass through unchanged |

### on_response

| Return | Effect |
|--------|--------|
| Response table | Return the (modified) response to the client |
| `nil` (or no return) | Pass through unchanged |

## Available Lua standard libraries

Scripts run in a standard Lua 5.4 environment with access to:

- `string` — pattern matching, formatting, manipulation
- `table` — array/table operations
- `math` — mathematical functions
- `os.date()`, `os.time()`, `os.clock()` — time functions
- `print()` — output to proxy stdout
- `tostring()`, `tonumber()`, `type()` — type conversion
