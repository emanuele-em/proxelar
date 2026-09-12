# proxelar task runner

coverage_min_lines := "80"
core_coverage_target_lines := "90"

# Run the full workspace test suite
test:
    cargo test --workspace --locked

# Run tests for a single crate, e.g. `just test-crate proxyapi`
test-crate crate:
    cargo test -p {{ crate }} --locked

# Run proxyapi's scripting-gated tests, self-contained via vendored Lua
test-scripting:
    cargo test -p proxyapi --locked --features scripting,vendored-lua -- scripting

# Run the workspace test suite with default features disabled
test-no-default-features:
    cargo test --workspace --locked --no-default-features

# Run fast local lint checks
lint:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets --all-features

# Build the workspace
build:
    cargo build --workspace --locked

# Build the workspace in release mode
build-release:
    cargo build --workspace --locked --release

# Build the workspace with default features disabled (Lua scripting off)
build-no-default-features:
    cargo build --workspace --locked --no-default-features

# Verify package tarball construction
package:
    cargo package --workspace --locked --no-verify

# Build workspace docs, matching CI's warnings-as-errors gate
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked

# Install cargo-deny (one-time setup for the deny recipe below)
deny-setup:
    cargo install cargo-deny --locked

# Check dependency licenses, bans and advisories (matches CI's deny.yml)
deny:
    cargo deny check

# Install cargo-audit (one-time setup for the audit recipe below)
audit-setup:
    cargo install cargo-audit --locked

# Scan dependencies for RustSec advisories (matches CI's audit job)
audit:
    cargo audit

# Full local gate before large changes (lint, build, test, package, doc, audit)
check: lint build build-no-default-features test test-no-default-features package doc audit

# Install cargo-llvm-cov (one-time setup for the coverage recipes below)
coverage-setup:
    cargo install cargo-llvm-cov --locked

# Workspace coverage gate matching CI (80%+ line coverage)
coverage:
    cargo llvm-cov --workspace --all-features --locked \
        --ignore-filename-regex '(^|/)(tests|target)/' \
        --fail-under-lines {{ coverage_min_lines }}

# Full CI coverage gate: workspace 80%+, then proxyapi core crate 90%+
coverage-check: coverage
    cargo llvm-cov report -p proxyapi \
        --ignore-filename-regex '(^|/)(tests|target)/' \
        --fail-under-lines {{ core_coverage_target_lines }}

# Browsable HTML coverage report
coverage-html:
    cargo llvm-cov --workspace --all-features --locked --html \
        --ignore-filename-regex '(^|/)(tests|target)/'

# Run the built binary against the current build (TUI by default; pass args to select another mode)
[positional-arguments]
run *args:
    cargo run -- "$@"
