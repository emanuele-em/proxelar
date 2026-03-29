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

## Response table

The `on_response` function receives two arguments:

1. **request** — a table with `method` and `url` fields (for context)
2. **response** — a table with these fields:

| Field | Type | Description |
|-------|------|-------------|
| `status` | number | HTTP status code (`200`, `404`, `500`, etc.) |
| `headers` | table | Response headers |
| `body` | string | Response body |

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
