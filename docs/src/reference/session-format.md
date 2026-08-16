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
- HTTP headers are ordered `[name, value]` tuples, preserving duplicate fields
  and HTTP/1 field order. Readers also accept the name-keyed header objects
  written by version 1 sessions.

Readers migrate version 1 sessions and reject versions newer than the implementation supports. Additive collection fields use empty defaults so readers remain tolerant of data written before those collections existed. Any incompatible schema change must increment the version and provide an explicit migration or a clear rejection.

The format prioritizes fidelity and debuggability over compactness. It is not encrypted and native saves are not redacted. Use filesystem permissions appropriate for secrets-bearing traffic.
