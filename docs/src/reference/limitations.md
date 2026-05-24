# Known limitations

Proxelar is usable today for local traffic inspection, scripting, intercept, replay, and WebSocket inspection. These are the main gaps to understand before choosing it for a workflow.

## Persistence and export

Captured flows currently live in memory. Proxelar does not yet save sessions, reload sessions, export HAR files, export curl commands, or write raw request/response pairs.

Use Proxelar when you need live inspection and local transformation. Use a tool with mature export support if saved artifacts are central to your workflow.

## Body decoding and editing

Bodies are captured as bytes, and large bodies can be capped with `--body-capture-limit`. Rich content decoding is limited today:

- gzip, br, zstd, and deflate decoding are not yet first-class content views
- binary body editing is intentionally cautious
- content-aware editors for JSON, forms, protobuf, multipart, and images are roadmap items

## Capture modes

Proxelar supports explicit forward proxy mode and reverse proxy mode. It does not yet support transparent/local capture, WireGuard-style capture, SOCKS5 mode, DNS inspection, or upstream proxy chaining.

## HTTPS and mobile apps

HTTPS interception requires trusting the Proxelar CA. Certificate-pinned clients will reject the generated certificates. Android 7+ apps trust user-installed CAs only if the app explicitly opts in.

## Remote web GUI

The web GUI is designed for local use. It uses a runtime token and currently accepts localhost origins for its WebSocket connection. Use SSH port forwarding or another local tunnel if you need to view it from another machine.

## Security-suite features

Proxelar is not a scanner, crawler, collaborative testing platform, or vulnerability management tool. For those workflows, tools such as Burp Suite, Caido, or mitmproxy may be a better fit.
