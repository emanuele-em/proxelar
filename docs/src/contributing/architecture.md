# Architecture

Proxelar is a Rust workspace with a strict dependency direction:

```text
proxelar-cli  →  proxyapi  →  proxyapi_models
interfaces      engine       pure data
```

`proxyapi_models` owns serializable request, response, WebSocket, TCP, DNS, UDP, and session types. It must stay free of async and network behavior. `proxyapi` owns listeners, TLS, handlers, capture, filtering, content views, sessions/export, rules, and Lua hooks. `proxelar-cli` owns argument parsing and the terminal, TUI, web, API, and browser-launch experiences.

## Runtime flow

1. A mode-specific listener accepts TCP or UDP traffic.
2. HTTP/TLS/SOCKS/DNS/UDP routing sends traffic to the relevant handler; unknown TCP can use observed tunneling.
3. Requests pass through rules, Lua hooks, optional interactive intercept, normalization, and the shared outbound client.
4. Responses pass through Lua/intercept processing and capture.
5. `ProxyEvent` values fan out once to the selected interface and `SessionRecorder`.
6. The recorder backs the REST API and clean-shutdown exporters.

Forward, reverse, replay, and chaining use the same outbound connector policy, but direct proxy requests are not pooled across transactions. Preserve the normalization invariants: remove `Host`, join duplicate `Cookie` fields with `; `, strip hop-by-hop metadata, and preserve the incoming HTTP version unless the user explicitly forces one.

## Extension points

- `ProxyConfig` and `ProxyMode` provide the library-level embedding surface.
- `InterceptConfig` and `InterceptDecision` provide interactive request interception.
- `RouteRules` provides deterministic configuration without code.
- Lua provides hot-reloaded request, response, and WebSocket frame hooks.
- `ProxyEvent` is the stable internal observation stream used by interfaces and persistence.

## Change checklist

Keep `#![forbid(unsafe_code)]`/the narrowly audited Lua exception intact, preserve the crate dependency direction, and make script errors log and pass through. Add socket-level integration tests for proxy behavior and serialization tests for model changes. Run the full commands in the repository's `AGENTS.md` and `CONTRIBUTING.md` before submitting.
