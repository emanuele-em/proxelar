# Proxelar Roadmap

This roadmap describes the main gaps between Proxelar's current implementation and the long-term goal: a dependable Rust-native traffic workbench for local debugging, scripting, and automation.

It is not a promise of delivery order. It is the public source of truth for larger feature work so old one-off issues do not become stale tracking tickets.

## Current stable surface

- Forward proxy with CONNECT tunneling and HTTPS MITM interception.
- Reverse proxy mode for putting Proxelar in front of a local or remote service.
- Terminal, TUI, and web GUI interfaces.
- Request intercept/edit/drop/forward flow in TUI and web GUI.
- Request replay from captured flows.
- Lua `on_request` and `on_response` hooks, including short-circuit responses.
- WebSocket connection and frame inspection.
- Body capture limits for large traffic, with passthrough streaming after the configured limit.
- Upstream TLS trust policies for default roots, extra CA files, CA-only trust, and insecure debugging.
- HTTP/2 client connection acceptance while preserving HTTP/1.1 upstream forwarding invariants.

## Priority gaps

### Persistence and interop

- Save and load captured sessions.
- Export selected or all flows as HAR, curl commands, and raw HTTP request/response files.
- Add redaction controls for secrets before export.
- Define a versioned on-disk flow format.

### Body handling and content views

- Expose body truncation metadata clearly in flow models and both UIs.
- Decode common content encodings such as gzip, br, zstd, and deflate.
- Reconcile `Content-Length`, `Transfer-Encoding`, and compression headers after body edits.
- Add safer binary-body editing behavior and richer text/binary previews.
- Add content-aware views for JSON, XML, HTML, forms, multipart bodies, images, protobuf, and msgpack.

### Capture modes and proxy topology

- Add transparent/local capture for traffic that cannot easily be configured with an explicit proxy.
- Add SOCKS5 proxy mode.
- Add upstream proxy chaining for corporate proxies, Tor, and tool-to-tool workflows.
- Investigate HTTP/3 and document the fallback story.
- Add DNS inspection or rewriting only if it fits the local debugging model cleanly.

### Automation and extension

- Stabilize `proxyapi` as an embeddable library with complete examples.
- Add a headless API for flows, replay, intercept decisions, scripts, and configuration.
- Add script hot reload.
- Add first-class rules for redirects, map-local/map-remote, mocks, and header rewrites.

### Security and trust

- Publish a threat model for the local CA, web GUI, scripts, and exported traffic.
- Document CA uninstall, rotation, key storage, Android user-CA behavior, and certificate-pinning limits.
- Add checksums or signatures for release artifacts.
- Harden and document remote web GUI access before presenting it as a supported deployment mode.

### Onboarding and reliability

- Add a `doctor` or equivalent diagnostics flow for proxy reachability, HTTPS interception, CA trust, and WebSocket capture.
- Add one-command browser-profile launch or clear browser setup recipes.
- Add UI smoke tests for web GUI states.
- Add performance and long-running reliability tests for high-concurrency traffic and large streaming bodies.
