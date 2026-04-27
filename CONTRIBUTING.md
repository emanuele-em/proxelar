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

# Check feature gates
cargo build --workspace --no-default-features
cargo test --workspace --no-default-features

# Lint, format, and package
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo package --workspace --list
```

## Making Changes

1. Fork the repo and create a branch from `master`
2. Make your changes
3. Add or update tests for behavior changes
4. Run the relevant checks from the testing section below
5. Submit a pull request

## Testing

Every patch should have a test story. For bug fixes, add a regression test that fails before the fix. For new proxy behavior, prefer an integration test that starts local client/server sockets and asserts what the client receives and what `ProxyEvent`s are emitted.

Run the full local gate before large changes:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build --workspace
cargo build --workspace --no-default-features
cargo test --workspace
cargo test --workspace --no-default-features
cargo package --workspace --list
```

For narrower iterations:

```bash
cargo test -p proxyapi
cargo test -p proxyapi --features scripting -- scripting
cargo test -p proxyapi_models
cargo test -p proxelar
```

To check test coverage locally, install `cargo-llvm-cov` and run the same workspace report CI uses:

```bash
cargo install cargo-llvm-cov --locked
cargo llvm-cov --workspace --all-features --locked \
  --ignore-filename-regex '(^|/)(tests|target)/' \
  --fail-under-lines 80
```

For a browsable report:

```bash
cargo llvm-cov --workspace --all-features --locked --html \
  --ignore-filename-regex '(^|/)(tests|target)/'
```

CI currently enforces the production coverage gates: `80%+` workspace line coverage and `90%+` `proxyapi` core crate line coverage. Treat coverage as a regression guard and trend metric; behavior-focused tests are still required for proxy changes even when the percentage is unchanged.

The production coverage target is:

| Scope | Target |
|-------|--------|
| Workspace | `80%+` line coverage |
| `proxyapi` core crate | `90%+` line coverage |
| `proxyapi_models` data crate | `95-100%` line coverage |

The workspace and `proxyapi` targets are hard CI gates in `.github/workflows/autofix.yml`. Raise these thresholds only after adding durable tests that keep the new gate stable across platforms and feature combinations.

To check the target gates locally:

```bash
cargo llvm-cov --workspace --all-features --locked \
  --ignore-filename-regex '(^|/)(tests|target)/' \
  --fail-under-lines 80

cargo llvm-cov -p proxyapi --all-features --locked \
  --ignore-filename-regex '(^|/)(tests|target)/' \
  --fail-under-lines 90
```

CI additionally verifies package tarball construction with `cargo package --workspace --locked --no-verify`, Rust documentation with warnings denied, dependency audits, coverage, and the matrix on Linux, macOS, and Windows.

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
