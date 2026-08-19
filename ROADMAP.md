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
- Native end-to-end HTTP/1 and HTTP/2 with transport-neutral messages and ordered byte-safe headers.
- HTTP/3 reverse and WireGuard interception, including RFC 9220 WebSockets.
- Versioned native sessions plus HAR import/export, curl export, and raw HTTP export with default secret redaction.
- Shared expression filters across the TUI and REST API, including body/header terms and boolean operators.
- Content-aware views with gzip, br, zstd, deflate, charsets, formatted JSON/XML/HTML/forms/multipart, CSS/JavaScript highlighting, safe raster-image rendering, Protobuf/MessagePack JSON, and bounded binary previews.
- WireGuard, SOCKS5, DNS, and fixed-target UDP modes, raw TCP observation, and HTTP CONNECT/SOCKS5 upstream chaining.
- Declarative map-local, map-remote, redirect, mock, and request-header rules.
- Bearer-token headless API for sessions, flows, replay, content views, and intercept decisions.
- Lua hot reload and optional WebSocket frame transformation hooks.
- Versioned Lua addon manifests, full-package SHA-256 verification, safe atomic local installation, catalog discovery, and runtime selection by addon name.
- Distinct per-leaf TLS private keys, release checksums, SPDX SBOMs, and provenance attestations.
- Isolated Chromium-family browser-profile launch with proxy settings preconfigured.

## Priority gaps

### Protocol depth

- Expand HTTP/3 beyond reverse and WireGuard modes while keeping protocol selection explicit and deterministic.
- Add optional descriptors that give Protobuf wire fields semantic names and define raw-TCP schemas; descriptorless Protobuf and MessagePack editing is already available.
- Expand WireGuard identity management beyond the generated single-client configuration.

### Automation and extension

- Stabilize `proxyapi` as an embeddable library with complete end-to-end examples and semver policy.
- Add API endpoints for live rule/script replacement and event streaming designed for non-browser clients.
- Add hosted registry discovery and publisher signatures on top of the validated local addon catalog; package manifests and full-file integrity verification are already stable.

### Security and trust

- Add optional TLS/mTLS authentication for deliberately remote API deployments.
- Evaluate OS key stores for protecting the local CA private key at rest.
- Add signed packages where each distribution channel supports them in addition to checksums and provenance.

### Onboarding and reliability

- Add a `doctor` diagnostics flow for proxy reachability, HTTPS interception, CA trust, and WebSocket capture.
- Add opt-in, transactional system-proxy setup with guaranteed restoration after crashes.
- Add UI smoke tests for web GUI states.
- Add performance and long-running reliability tests for high-concurrency traffic and large streaming bodies.
