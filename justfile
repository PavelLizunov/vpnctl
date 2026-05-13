default := 'help'

# Show this help
help:
    @just --list

# Quick syntax/type check across the whole workspace
check:
    cargo check --workspace --all-targets

# Run all tests
test:
    cargo test --workspace --all-targets

# Lint with clippy treating warnings as errors
clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# Format every Rust file
fmt:
    cargo fmt --all

# Verify formatting (CI-mode)
fmt-check:
    cargo fmt --all -- --check

# Security advisories
audit:
    cargo audit

# License/banned-crates/advisory policy
deny:
    cargo deny check

# Run vpnctl with arguments, e.g. `just run uuid`, `just run registry`
run *ARGS:
    cargo run --bin vpnctl -- {{ARGS}}

# Build release binary (musl static)
build-release:
    cargo build --release --target x86_64-unknown-linux-musl

# Full local CI sweep — run before pushing
ci: fmt-check clippy test deny
    @echo "✔ all CI gates passed"
