# API Reference

## Request table

The `on_request` function receives a table with these fields:

| Field | Type | Description |
|-------|------|-------------|
| `method` | string | HTTP method (`"GET"`, `"POST"`, `"PUT"`, `"DELETE"`, etc.) |
| `url` | string | Full request URL (`"https://example.com/path?q=1"`) |
| `headers` | table | Request headers (see [Headers](#headers) below) |
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
| `headers` | table | Response headers |
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

Headers are Lua tables mapping lowercase header names to values.

**Single-value headers** are plain strings:

```lua
request.headers["content-type"]     -- "application/json"
request.headers["authorization"]    -- "Bearer token123"
```

**Multi-value headers** (like `Set-Cookie`) are arrays:

```lua
response.headers["set-cookie"]      -- {"session=abc", "lang=en"}
```

When setting headers, both forms are accepted:

```lua
-- Single value (most common)
request.headers["x-custom"] = "value"

-- Multiple values
response.headers["set-cookie"] = {"a=1", "b=2"}

-- Remove a header
request.headers["cookie"] = nil
```

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
response.headers["content-encoding"] = nil
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
