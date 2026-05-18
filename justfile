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

# ─── Tools from 2026-05-18 security audit ──────────────────────────

# Secret scanner — catches accidental commits of inventory/*.env or
# pasted bot tokens. Same tool the CI's `gitleaks` job uses. Run
# locally before committing if you're paranoid.
#
# Requires `gitleaks` binary (Debian/Ubuntu: `sudo apt install gitleaks`,
# macOS: `brew install gitleaks`).
scan-secrets:
    gitleaks detect --source . --config .gitleaks.toml --verbose

# Mutation tester — injects bugs into the protocols crate's
# share_link/server_inbound paths and checks whether the byte-
# equality regression tests catch them. Surfaces «tests pass even
# when impl is inverted» bug class (the db3998c-style mistake).
#
# Requires `cargo install --locked cargo-mutants` (~30s).
mutants-protocols:
    cargo mutants -p vpnctl-protocols --in-diff origin/main

# Source-based coverage (LLVM). Reports per-region branch coverage
# across the workspace. Surfaces error-path branches that have no
# test exercising them — frequent regression source.
#
# Requires `cargo install cargo-llvm-cov` (~1 min).
coverage:
    cargo llvm-cov --workspace --html
    @echo "→ HTML report: target/llvm-cov/html/index.html"
