# Installation

## From crates.io

```bash
cargo install proxelar
```

This builds and installs the `proxelar` binary. Lua 5.4 and OpenSSL are vendored and compiled from source, so no system dependencies are required beyond a Rust toolchain.

## From source

```bash
git clone https://github.com/emanuele-em/proxelar.git
cd proxelar
cargo build --release
```

The binary is at `target/release/proxelar`.

## Without Lua scripting

If you don't need scripting and want a smaller build:

```bash
cargo install proxelar --no-default-features
```

## Requirements

- Rust 1.94 or later
- Works on Linux, macOS, and Windows
