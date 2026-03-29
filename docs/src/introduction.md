# Introduction

Proxelar is a man-in-the-middle proxy written in Rust. It intercepts, inspects, and optionally modifies HTTP and HTTPS traffic flowing between a client and a server.

## What can it do?

- **Inspect traffic** — see every request and response in real time, including headers and bodies
- **Intercept HTTPS** — automatic CA certificate generation and per-host certificate minting
- **Modify traffic with Lua scripts** — write `on_request` and `on_response` hooks to transform, block, or mock traffic at runtime
- **Forward and reverse proxy** — use as a system proxy (forward) or put it in front of your service (reverse)
- **Three interfaces** — interactive TUI, plain terminal output, or web GUI

## Architecture

Proxelar is built as a three-crate Rust workspace:

- **`proxelar-cli`** — the CLI binary with three interface modes
- **`proxyapi`** — the core proxy engine, usable as a standalone library
- **`proxyapi_models`** — shared request/response data types

The proxy engine is built on [hyper](https://hyper.rs) 1.x, [rustls](https://github.com/rustls/rustls) 0.23, and [tokio](https://tokio.rs). HTTPS interception uses OpenSSL for certificate generation and rustls for TLS termination. Lua scripting is powered by [mlua](https://github.com/khvzak/mlua) with a vendored Lua 5.4.
