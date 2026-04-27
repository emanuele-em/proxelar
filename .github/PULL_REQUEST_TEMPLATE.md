## What
Brief description of changes.

## Why
Motivation and context.

## Changelog
Add a bullet point to `CHANGELOG.md` under `[Unreleased]` describing your change.
You don't need to add a PR reference or your name — CI does that automatically.

- [ ] I have added an entry to the CHANGELOG
- [ ] I have added or updated tests for user-visible behavior changes

## Local Checks

- [ ] I ran `cargo fmt --all --check` and it passed
- [ ] I ran `cargo clippy --workspace --all-targets --all-features -- -D warnings` and it passed
- [ ] I ran `cargo build --workspace` and it passed
- [ ] I ran `cargo test --workspace` and it passed
- [ ] I ran `cargo build --workspace --no-default-features` and it passed, or this PR does not affect feature gates
- [ ] I ran `cargo test --workspace --no-default-features` and it passed, or this PR does not affect feature gates
- [ ] I ran `cargo llvm-cov --workspace --all-features --locked --ignore-filename-regex '(^|/)(tests|target)/' --fail-under-lines 80` and it passed, or this PR does not affect Rust code
- [ ] I ran `cargo llvm-cov -p proxyapi --all-features --locked --ignore-filename-regex '(^|/)(tests|target)/' --fail-under-lines 90` and it passed, or this PR does not affect `proxyapi`
