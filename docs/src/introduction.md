# Introduction

Proxelar is a scriptable local traffic workbench written in Rust. It sits between a client and an upstream service so you can inspect, intercept, replay, and modify HTTP, HTTPS, and WebSocket traffic.

It is aimed at development and debugging workflows: API inspection, local service mocking, request/response rewriting, WebSocket debugging, and repeatable traffic transforms without changing the application under test.

## What can it do?

- **Inspect traffic** — see every request and response in real time, including headers and bodies
- **Intercept HTTPS** — automatic CA certificate generation and per-host certificate minting
- **Modify traffic with Lua scripts** — write `on_request` and `on_response` hooks to transform, block, or mock traffic at runtime
- **Forward and reverse proxy** — use as a system proxy (forward) or put it in front of your service (reverse)
- **Three interfaces** — interactive TUI, plain terminal output, or web GUI
- **Inspect WebSockets** — capture WebSocket connections and browse individual frames

## What is it not?

Proxelar is not trying to replace a mature security suite. If you need scanning, collaborative testing, a large addon ecosystem, or advanced transparent capture today, use a tool built for that workflow. Proxelar is deliberately smaller: a local, scriptable proxy that is easy to install, run, and automate.

## Architecture

Proxelar is built as a three-crate Rust workspace:

- **`proxelar-cli`** — the CLI binary with three interface modes
- **`proxyapi`** — the core proxy engine, usable as a standalone library
- **`proxyapi_models`** — shared request/response data types

The proxy engine is built on [hyper](https://hyper.rs) 1.x, [rustls](https://github.com/rustls/rustls) 0.23, and [tokio](https://tokio.rs). HTTPS interception uses OpenSSL for certificate generation and rustls for TLS termination. Lua scripting is powered by [mlua](https://github.com/khvzak/mlua) with a vendored Lua 5.4.
