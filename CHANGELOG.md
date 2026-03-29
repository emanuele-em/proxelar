# Changelog

<!--
  Contributors: add a bullet point describing your change under [Unreleased].
  You don't need to add a PR reference or your name — CI does that automatically.
-->

## [Unreleased]

## [0.3.0] - 2026-03-29

- Lua scripting system with `on_request` and `on_response` hooks via `--script` flag
- Embedded Lua 5.4 via mlua (vendored, zero system dependencies)
- Short-circuit responses from scripts (block requests, mock API endpoints)
- Script errors never crash the proxy — logged and passed through
- `scripting` feature flag (enabled by default, opt out with `--no-default-features`)
- 13 example scripts covering header injection, domain blocking, API mocking, CORS, traffic logging, HTML rewriting, cookie stripping, and more
- mdBook documentation at proxelar.micheletti.io

## [0.2.0] - 2026-02-21

- Complete rewrite from Tauri desktop app to CLI tool
- Three-crate workspace: `proxelar-cli`, `proxyapi`, `proxyapi_models`
- Three interface modes: terminal, TUI (ratatui), web GUI (axum + WebSocket)
- Forward proxy with CONNECT tunneling and HTTPS MITM interception
- Reverse proxy mode with URI rewriting
- hyper 1.x migration with rustls 0.23 and tokio-rustls 0.26
- `HttpHandler` trait for extensible request/response interception
- Per-host leaf certificate caching with moka
- Built-in certificate download server at `http://proxel.ar`
- Unified event pipeline with bounded mpsc channel
- Integration tests for CA, cert server, forward proxy, reverse proxy, and serialization
- Cross-platform CI (Ubuntu, macOS, Windows) with MSRV verification
- cargo-deny license and vulnerability auditing
- Cross-platform release workflow with binary artifacts
- License changed to MIT-only

## [0.1.6] - 2023-04-14

- Migration from eframe to Tauri + Yew frontend
- Filter option for requests
- Row selection in Tauri UI
- Delete request functionality
- Tauri events instead of polling
- Pause proxy functionality
- Hover text for table rows
- CI/CD checks for lint and format

## [0.1.5] - 2023-02-26

- Delete single request button
- GUI and bug fixes
- Check before rendering right panel

## [0.1.4] - 2023-02-24

- Listening interface and port selection

## [0.1.3] - 2023-02-22

- Consistent request/response types
- Fix crash on clear
- Layout improvements for top table

## [0.1.2] - 2023-02-21

- Filter by HTTP request method (combobox)
- Expose raw HTTP method for efficient comparison

## [0.1.1] - 2023-02-20

- Initial public release
- MITM proxy with eframe GUI
- HTTPS interception with self-signed certificates
- Request/response inspection
- Custom certificate generation guide
