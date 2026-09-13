# Rules and headless API

## Declarative routing rules

Use repeatable command-line mappings for common cases:

```bash
proxelar \
  --map-local 'https://app.test/assets/=./fixtures/assets' \
  --map-remote 'https://api.test/v1/=http://127.0.0.1:3000/'
```

For mocks, redirects, and header changes, pass a JSON file with `--rules rules.json`:

```json
{
  "rules": [
    {
      "action": "set_request_header",
      "url_prefix": "https://api.test/",
      "name": "x-debug-client",
      "value": "proxelar"
    },
    {
      "action": "mock",
      "url_prefix": "https://api.test/health",
      "method": "GET",
      "status": 200,
      "headers": [{ "name": "content-type", "value": "application/json" }],
      "body": "{\"ok\":true}"
    },
    {
      "action": "redirect",
      "url_prefix": "https://old.test/",
      "location": "https://new.test/",
      "status": 302
    }
  ]
}
```

Rules run in file order. Header changes can accumulate; the first matching response-producing rule wins. Map-local paths are constrained to the configured directory and reject traversal.

Supported `action` values are `map_local`, `map_remote`, `redirect`, `mock`, `set_request_header`, and `remove_request_header`.

## Headless REST API

Start the API without opening the GUI:

```bash
proxelar -i api --api-token "$PROXELAR_TOKEN"
```

The server listens on `--gui-port` (8081 by default). Send `Authorization: Bearer <token>` on every request:

```bash
curl -H "Authorization: Bearer $PROXELAR_TOKEN" \
  'http://127.0.0.1:8081/api/v1/flows?filter=method:POST%20%26%20status:500'
```

| Method and path | Purpose |
|---|---|
| `GET /api/v1/status` | Version, capture counts, and intercept state |
| `GET /api/v1/session` | Complete native session snapshot |
| `GET /api/v1/flows?filter=...` | HTTP flows using the shared filter language |
| `GET /api/v1/filter?filter=...` | Matching HTTP, WebSocket, TCP, DNS, and UDP IDs |
| `GET /api/v1/flows/{id}` | One HTTP flow |
| `DELETE /api/v1/flows` | Clear recorded traffic |
| `GET /api/v1/flows/{id}/content/request` | Decoded request content view |
| `GET /api/v1/flows/{id}/content/response` | Decoded response content view |
| `POST /api/v1/flows/{id}/replay` | Queue a request replay |
| `PUT /api/v1/intercept` | Set intercept with `{ "enabled": true }` |
| `POST /api/v1/intercept/{id}` | Resolve with `forward`, `drop`, or `modify` |

For a `modify` decision, `body` can be a UTF-8 string or `{ "bytes": [0, 255, ...] }` for lossless binary editing. Header input accepts either a JSON object (string or string-array values) or an ordered list when duplicate order matters. Each ordered entry contains `name` and exactly one of `value` (UTF-8 text) or `value_base64` (arbitrary bytes):

```json
[
  { "name": "X-Trace", "value": "first" },
  { "name": "X-Binary", "value_base64": "gP8=" },
  { "name": "X-Trace", "value": "last" }
]
```

Flow and session responses use this same ordered representation, preserving
duplicates and using `value_base64` whenever a value is not valid UTF-8.

Filter terms include `host:`, `method:`, `status:`, `type:`, `body:`, `header:`, `request_body:`, and `response_body:`. Combine terms with `&`, `|`, `!`, parentheses, or adjacent implicit AND. The aliases `~d`, `~m`, `~s`, `~t`, `~b`, and `~h` are also accepted.

The API is intended for one trusted local operator. A token is authentication, not transport security; keep the listener on loopback or put remote access behind an authenticated TLS tunnel.
