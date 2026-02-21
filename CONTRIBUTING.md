# Contributing to Proxelar

Thanks for your interest in contributing! Whether it's a bug fix, new feature, or documentation improvement — all contributions are welcome.

## Getting Started

```bash
# Clone and build
git clone https://github.com/emanuele-em/proxelar.git
cd proxelar
cargo build --workspace

# Run tests
cargo test --workspace

# Lint and format
cargo clippy --workspace -- -D warnings
cargo fmt --all --check
```

## Making Changes

1. Fork the repo and create a branch from `master`
2. Make your changes
3. Add or update tests as needed
4. Ensure `cargo test --workspace` and `cargo clippy --workspace -- -D warnings` pass
5. Submit a pull request

## Project Structure

The workspace has three crates with a strict dependency direction: `proxelar-cli` → `proxyapi` → `proxyapi_models`.

| Crate | Purpose |
|-------|---------|
| `proxyapi_models` | Pure data types — no async, no network |
| `proxyapi` | Core proxy engine — forward/reverse proxy, TLS MITM, CA management |
| `proxelar-cli` | Binary — CLI, terminal, TUI, and web GUI interfaces |

## Testing with a Local Server

```bash
# Install an echo server and HTTP client
cargo install echo-server xh

# In one terminal, start the echo server
echo-server

# In another, start proxelar
cargo run

# Send requests through the proxy
xh --proxy http:http://127.0.0.1:8080 GET http://127.0.0.1:8080
```

## Reporting Issues

If you're unsure about a change, feel free to [open an issue](https://github.com/emanuele-em/proxelar/issues) first to discuss it.
