# Installation

## Homebrew (macOS / Linux)

```bash
brew install proxelar
```

## winget (Windows)

```bash
winget install --id EmanueleMicheletti.Proxelar --exact
```

## Docker / Podman

```bash
# Web GUI
docker run --rm -it -v ~/.proxelar:/root/.proxelar -p 8080:8080 -p 127.0.0.1:8081:8081 ghcr.io/emanuele-em/proxelar --interface gui --addr 0.0.0.0

# Terminal
docker run --rm -it -v ~/.proxelar:/root/.proxelar -p 8080:8080 ghcr.io/emanuele-em/proxelar --interface terminal --addr 0.0.0.0
```

The `-v ~/.proxelar:/root/.proxelar` mount reuses your existing trusted CA certificate, so you do not get browser warnings after trusting the CA once.

The published image is `linux/amd64`. To build it yourself, or to run on another architecture, use the `Dockerfile` in the repository:

```bash
docker build -t proxelar .
```

## From crates.io

```bash
cargo install proxelar
```

This builds and installs the `proxelar` binary with Lua and HTTP/3 enabled. Lua 5.4 and BoringSSL are compiled from source; source installations therefore need CMake, Clang/libclang, and a C/C++ toolchain in addition to Rust.

## From source

```bash
git clone https://github.com/emanuele-em/proxelar.git
cd proxelar
cargo build --release
```

The binary is at `target/release/proxelar`.

## Feature-minimal builds

The published binary and Cargo defaults include Lua scripting and HTTP/3. To keep H3 but omit Lua:

```bash
cargo install proxelar --no-default-features --features http3
```

For a smaller H1/H2-only binary without Lua or H3:

```bash
cargo install proxelar --no-default-features
```

## Requirements

- Rust 1.97.1 or later
- Works on Linux, macOS, and Windows
