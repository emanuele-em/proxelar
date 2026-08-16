# Known limitations

Proxelar is usable today for local traffic inspection, scripting, intercept, replay, and WebSocket inspection. These are the main gaps to understand before choosing it for a workflow.

## Sessions and export fidelity

Proxelar can save/reload its versioned native session format, import/export HAR, emit curl commands, and write raw HTTP pairs. HAR cannot represent every Proxelar concept: raw TCP chunks, live intercept state, and some WebSocket metadata remain available only in the native session. Exports redact common credentials by default; native session saves preserve captured data exactly.

## Body decoding and editing

Bodies can be capped with `--body-capture-limit`; the UI records captured and total byte counts and marks truncation. Views decode gzip, br, zstd, deflate, declared charsets, formatted JSON/XML/HTML/forms/multipart, highlighted CSS/JavaScript, safe raster images, and bounded binary formats. Protobuf wire fields and MessagePack values are rendered as structured JSON when valid. Multipart parts are separated for inspection, not presented as a structured part editor.

When an intercepted body changes, Proxelar removes stale transfer/content encodings and recalculates `Content-Length`. Invalid UTF-8 request bodies use a lossless hex editor in the TUI and web GUI. The Protobuf editor preserves and edits field numbers, wire types, integer values, UTF-8 values, and base64 byte values without a schema. Semantic field names and uncommon deprecated group wire types still require an external Lua decoder/schema.

## Capture modes

Proxelar supports forward, reverse, WireGuard, SOCKS5, DNS, and fixed-target UDP modes plus upstream HTTP CONNECT/SOCKS5 chaining. WireGuard capture uses a userspace TCP/IP stack and currently generates one client identity per CA directory. Proxelar does not install firewall rules or modify system proxy settings.

Unknown TCP streams can be observed as directional chunks, but there is no protocol-aware binary editor.

## HTTP versions

HTTP/1.1 and HTTP/2 are intercepted and preserved end to end. With `--upstream-http-version auto`, the default, the incoming request version determines the upstream version (h1→h1, h2→h2); for HTTPS, upstream ALPN is constrained to that version. Use `http1` or `http2` to force a version instead. HTTP/3 and QUIC interception are not available today and are planned for later this year.

## HTTPS and mobile apps

HTTPS interception requires trusting the Proxelar CA. Certificate-pinned clients will reject the generated certificates. Android 7+ apps trust user-installed CAs only if the app explicitly opts in.

## Remote web GUI

The web GUI and REST API are designed for one trusted local operator. Both require a runtime bearer token, but they do not provide user accounts, TLS termination, rate limits, or multi-tenant isolation. Bind to loopback by default. If remote access is necessary, put it behind an authenticated TLS tunnel and protect the token as a credential.

## Security-suite features

Proxelar is not a scanner, crawler, collaborative testing platform, or vulnerability management tool. For those workflows, tools such as Burp Suite, Caido, or mitmproxy may be a better fit.
