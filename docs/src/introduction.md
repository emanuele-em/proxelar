# Introduction

Proxelar is a scriptable local traffic workbench written in Rust. It sits between a client and an upstream service so you can inspect, intercept, replay, and modify HTTP, HTTPS, and WebSocket traffic.

It is aimed at development and debugging workflows: API inspection, local service mocking, request/response rewriting, WebSocket debugging, and repeatable traffic transforms without changing the application under test.

## What can it do?

- **Inspect traffic** — see every request and response in real time, including headers and bodies
- **Intercept HTTPS** — automatic CA certificate generation and per-host certificate minting
- **Modify traffic with scripts and rules** — hot-reload Lua hooks or declare maps, redirects, mocks, and header changes
- **Package repeatable extensions** — verify, install, discover, and run versioned integrity-checked Lua addons
- **Six capture modes** — forward, reverse, WireGuard, SOCKS5, DNS, and fixed-target UDP
- **Four interfaces** — interactive TUI, plain terminal output, web GUI, or headless REST API
- **Inspect WebSockets** — capture WebSocket connections and browse individual frames
- **Keep portable sessions** — reload native captures or exchange HAR, curl, and raw HTTP artifacts with default secret redaction

## What is it not?

Proxelar is not trying to replace a mature security suite. If you need scanning, collaborative testing, or a large pre-existing addon inventory, use a tool built for that workflow. If you need HTTP/3 and QUIC interception today, use a tool that already provides it; Proxelar plans to add both later this year. Proxelar is deliberately smaller: a local, scriptable proxy that is easy to install, run, and automate.

## Architecture

Proxelar is built as a three-crate Rust workspace:

- **`proxelar-cli`** — the CLI binary with terminal, TUI, web, and API interfaces
- **`proxyapi`** — the core proxy engine, usable as a standalone library
- **`proxyapi_models`** — shared request/response data types

The proxy engine is built on [rama](https://ramaproxy.org) and [tokio](https://tokio.rs). Rama provides the HTTP/1.1 and HTTP/2 stacks, typed protocol layers, SOCKS5, WebSocket relaying, BoringSSL TLS, and dynamic MITM certificate issuance. Lua scripting is powered by [mlua](https://github.com/mlua-rs/mlua) with a vendored Lua 5.4.
