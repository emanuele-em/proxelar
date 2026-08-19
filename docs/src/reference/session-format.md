# Session format

The native Proxelar session is JSON with a mandatory numeric `version`. Version 2 has this top-level shape:

```json
{
  "version": 2,
  "created_at": 1784450000000,
  "flows": [],
  "websockets": [],
  "tcp_streams": [],
  "dns_exchanges": [],
  "udp_exchanges": []
}
```

- `created_at` and message/frame timestamps are Unix epoch milliseconds.
- `flows` contain stable IDs and complete request/response snapshots.
- request and response bodies include `body_metadata.truncated` and `body_metadata.total_seen` so a captured prefix is never presented as complete.
- `websockets` contain handshake snapshots, ordered frames, direction/opcode, and closure state.
- `tcp_streams` contain target, opening time, ordered directional chunks, and closure state.
- `dns_exchanges` contain the query name/type, parsed IP answers, override state, and completion state.
- `udp_exchanges` contain the client and fixed target addresses, lossless request/response bytes, response-received state, and capture-limit flags.
- HTTP headers are ordered lists, so global field order, duplicate values, and
  HTTP/1 field-name casing are preserved. UTF-8 values use `value`; other bytes
  use base64:

  ```json
  [
    { "name": "X-Trace", "value": "first" },
    { "name": "X-Binary", "value_base64": "gP8=" },
    { "name": "X-Trace", "value": "last" }
  ]
  ```

Readers accept only the current format version. Version 1 used a map-shaped
header representation that could not preserve global field order or arbitrary
bytes, so v1 files are rejected explicitly rather than decoded ambiguously.
Future incompatible schema changes must increment the version and provide an
explicit migration or a clear rejection.

The format prioritizes fidelity and debuggability over compactness. It is not encrypted and native saves are not redacted. Use filesystem permissions appropriate for secrets-bearing traffic.
