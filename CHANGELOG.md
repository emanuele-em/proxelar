# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- Replaced unbounded event channel with bounded channel (capacity 10,000) to prevent memory exhaustion
- Body collection now enforces a 100 MB size limit to prevent OOM on large responses
- CA certificate loading now validates that the key matches the certificate
- Reverse proxy target URI is validated at startup (must include scheme and authority)
- HTTPS MITM errors are now logged at `warn` level instead of `debug`
- Host header injection in reverse proxy now logs a warning on parse failure
- Response builder errors in cert server are now logged instead of silently swallowed
- Protocol detection uses named constants instead of magic bytes
- Shutdown error detection is shared between forward and reverse proxy
- Web GUI caps stored requests at 10,000 to prevent browser memory leaks
- Browser open failures are now logged
- Startup detection uses cancellation token propagation instead of fragile oneshot+sleep
- Tokio features narrowed from `full` to only required features in CLI crate
- `tokio::task::JoinError` now has a dedicated error variant instead of string conversion

### Added
- `#![forbid(unsafe_code)]` on all library crates
- `cargo audit` security scanning in CI pipeline
- Documentation for all public API items
- Additional model tests (accessor coverage, multi-header, large body)
- CHANGELOG.md

### Fixed
- `const fn` incorrectly applied to `&mut self` methods in TUI state
- Redundant `filtered_count()` reimplementation (now delegates to `filtered_requests()`)

### Removed
- Outdated `install_cer.sh` references from README
- Outdated Tauri UI section from CONTRIBUTING.md
