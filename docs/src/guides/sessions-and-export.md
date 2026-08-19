# Sessions and export

Proxelar records completed HTTP flows, WebSocket connections and frames, observed raw TCP chunks, DNS exchanges, and raw UDP datagrams in one versioned session. Load prior traffic before starting and save the combined history when Proxelar shuts down cleanly:

```bash
proxelar --load-session previous.proxelar.json \
  --save-session combined.proxelar.json
```

Press Ctrl+C to finalize outputs. `--load-session` and `--import-har` are mutually exclusive.

## Interoperable formats

```bash
proxelar --import-har input.har \
  --export-har output.har \
  --export-curl requests.sh \
  --export-raw raw-flows/
```

- HAR import carries HTTP request and response data.
- HAR export also carries WebSocket messages in Chromium's
  `_webSocketMessages` format.
- curl export writes one reproducible command per HTTP request.
- raw export writes request/response pairs without collapsing duplicate headers.
- the native format also preserves WebSocket frames, raw TCP chunks, DNS and UDP exchanges, body truncation metadata, and stable flow IDs.

HAR cannot represent all native session data, including WebSocket connection
lifecycle. Keep the native file when capture fidelity matters.

## Secret handling

HAR, curl, and raw exports redact `Authorization`, `Proxy-Authorization`,
`Cookie`, `Set-Cookie`, and common secret query parameters by default.
Application data in HTTP bodies and WebSocket messages is not inspected for
secrets. Use `--export-secrets` only when the output will remain in a trusted
location.

Native `--save-session` files are lossless and are **not redacted**. Treat them as credentials-bearing debugging artifacts: restrict permissions, do not commit them, and delete them when no longer needed.

See [Session format](../reference/session-format.md) for compatibility details.
