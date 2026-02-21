# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
cargo build --workspace                # build all crates
cargo run                              # run CLI (default member is proxelar-cli)
cargo test --workspace                 # all tests
cargo test -p proxyapi                 # test only core library
cargo test -p proxyapi_models          # test only data models
cargo test -p proxyapi -- cert_authority  # single test module
cargo clippy --workspace -- -D warnings   # lint (CI treats warnings as errors)
cargo fmt --all --check                # format check
cargo audit                            # security vulnerability scan
```

MSRV: 1.88. CI runs on ubuntu, macos, and windows.

## Workspace Structure

Three crates with a strict dependency direction: `proxelar-cli` → `proxyapi` → `proxyapi_models`.

- **`proxyapi_models`** — Pure data types (`ProxiedRequest`, `ProxiedResponse`). Serializable via serde + http-serde. No async, no network. `#![forbid(unsafe_code)]`.
- **`proxyapi`** — Core proxy engine. Forward proxy (CONNECT tunneling, HTTPS MITM), reverse proxy, CA cert generation/caching, `HttpHandler` trait. Uses hyper 1.6, rustls 0.23, tokio-rustls 0.26, openssl (vendored). `#![forbid(unsafe_code)]`.
- **`proxelar-cli`** — Binary. CLI (clap), three interface modes: terminal (colored stdout), TUI (ratatui), web GUI (axum + WebSocket).

## Architecture

### Request Flow

**Forward proxy** (`proxyapi/src/proxy/forward.rs`):
1. Accept TCP → spawn `handle_connection` → hyper http1 `serve_connection`
2. CONNECT requests → HTTP upgrade → peek 4 bytes to detect protocol:
   - TLS ClientHello → generate leaf cert signed by CA → `TlsAcceptor` → `serve_stream`
   - `"GET "` → plain HTTP `serve_stream`
   - Other → raw TCP tunnel via `copy_bidirectional`
3. Non-CONNECT → direct forwarding via `Client`
4. In `serve_stream`: `handler.handle_request()` → `normalize_request()` → `client.request()` → `collect_and_emit()`

**Reverse proxy** (`proxyapi/src/proxy/reverse.rs`):
1. Accept TCP → `handle_connection` → `handler.handle_request()` → `rewrite_uri()` → forward to target

### Event Pipeline

```
CapturingHandler → mpsc::Sender<ProxyEvent> (bounded 10,000) → Interface
```

Events are `ProxyEvent::RequestComplete { id, request, response }` or `ProxyEvent::Error { message }`. Boxed fields to keep enum size small.

- **Terminal**: prints colored lines
- **TUI**: merged with key events and render ticks via `spawn_event_loop()` into `AppEvent` stream
- **Web GUI**: JSON-serialized → `broadcast::Sender` → WebSocket to browser

### CA / TLS MITM (`proxyapi/src/ca/`)

`Ssl::load_or_generate(dir)` runs in `spawn_blocking` (heavy OpenSSL). Loads or generates 4096-bit RSA CA cert/key in `~/.proxelar/`. Per-host leaf certs cached with `moka` (capacity 1,000).

Cert download server intercepts requests to `proxel.ar` hostname, serving PEM/DER downloads and install instructions.

### Key Types

| Type | Location | Notes |
|------|----------|-------|
| `ProxyBody` | `proxyapi::body` | `BoxBody<Bytes, hyper::Error>` — universal body type. Create via `body::full()` / `body::empty()` |
| `Client` | `proxyapi::proxy` | `hyper_util::client::legacy::Client<HttpsConnector, ProxyBody>` |
| `HttpHandler` | `proxyapi::lib` | Async trait: `handle_request()` + `handle_response()`. Must be `Clone + Send + Sync + 'static` |
| `RequestOrResponse` | `proxyapi::lib` | Return from `handle_request`; allows short-circuiting with a response |
| `Rewind<T>` | `proxyapi::rewind` | AsyncRead+AsyncWrite wrapper that replays buffered bytes before inner stream |

## Important Patterns

- **rustls crypto provider**: Call `rustls::crypto::ring::default_provider().install_default()` at startup and in every test touching TLS. Use `let _ =` to ignore repeated install errors in tests.
- **RSA key DER export**: Use `PrivateKeyDer::Pkcs1` (not Pkcs8) when exporting via `pkey.rsa()?.private_key_to_der()`.
- **Timestamps**: Use `timestamp_millis()` (not nanos) to avoid i64 overflow.
- **Body size limit**: `MAX_BODY_SIZE = 100 MB`. Oversized bodies are replaced with empty bytes in captured events; proxied traffic is unaffected.
- **`normalize_request()`**: Strips Host header, joins duplicate Cookie headers with `"; "`, pins HTTP/1.1.
- **Bounded event channel**: On full, events are dropped with `warn!` log. Never panics.

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-i, --interface` | `tui` | `terminal` / `tui` / `gui` |
| `-m, --mode` | `forward` | `forward` / `reverse` |
| `-p, --port` | `8080` | Proxy listen port |
| `-b, --addr` | `127.0.0.1` | Bind address |
| `-t, --target` | (required for reverse) | Upstream URI for reverse mode |
| `--gui-port` | `8081` | Web GUI port |
| `--ca-dir` | `~/.proxelar` | CA cert/key directory |

Environment: `RUST_LOG` controls tracing output (e.g. `RUST_LOG=debug`, `RUST_LOG=proxyapi=trace`).
