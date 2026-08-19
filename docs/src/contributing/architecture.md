# Architecture

Proxelar is a Rust workspace with a strict dependency direction:

```text
proxelar-cli  →  proxyapi  →  proxelar-proto  →  proxyapi_models
interfaces      engine       protocol core       pure data
```

`proxyapi_models` owns serializable request, response, WebSocket, TCP, DNS, UDP, and session types. It must stay free of async and network behavior. `proxelar-proto` owns transport-neutral heads and bodies plus the native H1 and H2 codecs/drivers. `proxyapi` owns listeners, TLS, H3, handlers, capture, filtering, content views, sessions/export, rules, and Lua hooks. `proxelar-cli` owns argument parsing and the terminal, TUI, web, API, and browser-launch experiences.

## Runtime flow

1. A mode-specific listener accepts TCP or UDP traffic.
2. HTTP/TLS/SOCKS/DNS/UDP routing sends traffic to the relevant handler; unknown TCP can use observed tunneling.
3. Requests pass through rules, Lua hooks, optional interactive intercept, normalization, and the shared outbound client.
4. Responses pass through Lua/intercept processing and capture.
5. `ProxyEvent` values fan out once to the selected interface and `SessionRecorder`.
6. The recorder backs the REST API and clean-shutdown exporters.

Protocol drivers share one transport-neutral message model. Preserve `normalize_request()` invariants at H1 boundaries: remove `Host`, join duplicate `Cookie` fields with `; `, strip hop-by-hop metadata, and pin HTTP/1.1. H2/H3 adapters must use native lowercase and pseudo-header forms while retaining duplicate order.

## Extension points

- `HttpHandler` provides library-level request/response interception.
- `RouteRules` provides deterministic configuration without code.
- Lua provides hot-reloaded request, response, and WebSocket frame hooks.
- `ProxyEvent` is the stable internal observation stream used by interfaces and persistence.

## Change checklist

Keep `#![forbid(unsafe_code)]`/the narrowly audited Lua exception intact, preserve the crate dependency direction, and make script errors log and pass through. Add socket-level integration tests for proxy behavior and serialization tests for model changes. Run the full commands in the repository's `AGENTS.md` and `CONTRIBUTING.md` before submitting.
