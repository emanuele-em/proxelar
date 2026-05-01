# Changelog

<!--
  Contributors: add a bullet point describing your change under [Unreleased].
  You don't need to add a PR reference or your name — CI does that automatically.
-->

## [Unreleased]

## [0.4.4] - 2026-05-01

- Add an optional body capture limit so large uploads/downloads can stream safely while preserving the default unlimited capture behavior.
- Fix the Homebrew formula bump step in the release workflow.
- Dependency updates: rand 0.10.1, actions/upload-pages-artifact 5, softprops/action-gh-release 3
- Replace CLAUDE.md with compact AGENTS.md contributor instructions

## [0.4.3] - 2026-04-12

- Request table now shows nine columns — Time, Proto, Method, Host, Path, Status, Type (content-type), Size, Duration — in both TUI and web GUI
- Filter expanded to all nine columns: `time:14:`, `proto:https`, `method:GET`, `host:github`, `path:/api`, `status:200`, `type:json`, `size:1KB`, `duration:slow`
- Web GUI: replaced the method dropdown with a unified `column:value` search bar matching TUI behaviour
- Semantic per-column color coding — each protocol, method, status range, content-type category, size tier, and duration tier has its own distinct color in both interfaces
- Dependency update: tokio 1.51.1

## [0.4.2] - 2026-04-11

- WebSocket inspection — connections appear as `WS⇄` / `WS✓` rows in the TUI and web GUI; click or select to browse individual frames with direction, opcode, size, and payload preview
- Column-scoped filter in TUI — use `method:GET`, `status:404`, `host:example`, `path:/api`, `size:1.5KB` to narrow the table to a single column; plain text falls back to the existing all-fields search
- TUI filter status bar no longer shows intercept-only shortcuts (`f`, `e`) when a filter is active but intercept is off

Full release notes: [micheletti.io/proxelar-042](https://micheletti.io/proxelar-042/)

## [0.4.1] - 2026-04-05

- Docker/Podman support — official `Dockerfile` and `compose.yml` for containerized deployments
- `?` help menu in TUI and web GUI listing all keyboard shortcuts
- Request replay from TUI (`r` key) and web GUI button — resend any captured request instantly
- Dependency updates: tokio 1.51, mlua 0.11.6, hyper 1.9

## [0.4.0] - 2026-04-04

### Intercept mode

- Pause any HTTP/HTTPS request mid-flight and decide what to do before it reaches the server
- **TUI**: press `i` to toggle intercept; pending requests appear as `⏸` rows; `f` to forward, `d` to drop (504), `e` to edit inline
- **Web GUI**: intercept toggle button in the toolbar; click a pending row to open the editor panel with method, URI, headers, and body fields; Forward / Drop buttons
- Inline request editor in TUI — no external `$EDITOR` required; full cursor navigation, line editing, binary body warning
- Two-step edit flow: edit freely → `Esc` to stage → `f` to forward (with or without changes)
- Parse error feedback: editor stays open with a red border when the request line is malformed
- Toggling intercept off automatically forwards all pending requests so clients never hang
- `InterceptConfig` and `InterceptDecision` types exported from `proxyapi` for programmatic use
- Stable ID correlation between `RequestIntercepted` and `RequestComplete` events
- XSS fix in web GUI header editor (DOM construction instead of `innerHTML`)
- Multi-value header preservation (`append` instead of `insert`) in both TUI and web editors
- Documentation page: [Intercept & Modify Traffic](https://proxelar.micheletti.io/intercept.html)

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
