# vpnctl — agent contract

Linux-only Rust control plane for self-hosted VPN infrastructure. The canonical
repository is `https://github.com/PavelLizunov/vpnctl`; default branch is `main`.
`README.md` describes the product and `CLAUDE.md` is the long operational history.

## Work safely

- Use one task branch and worktree per task. Never switch, clean, reset, stash, or
  stage another session's files. Stage explicit paths, not `git add -A`.
- Default delivery is branch -> PR -> required CI. Never push directly to `main`,
  deploy production, publish a release, or rotate credentials without owner approval.
- Repository work runs on build-1. Host mutations and SSH integration tests run only
  on an explicitly assigned disposable/lab target; a build-1 unit-test PASS is not a
  production or target-smoke PASS.

## Build and test

Rust stable with `rustfmt` and `clippy` is pinned by `rust-toolchain.toml`.
`just` is only a convenience wrapper; the commands below are canonical and work when
`just` is unavailable.

```sh
cargo check --workspace --all-targets
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo deny check
```

Before a code PR, run all five commands. CI additionally runs gitleaks and the two
Docker-backed ignored SSH suites:

```sh
docker pull lscr.io/linuxserver/openssh-server:latest
cargo test -p vpnctl-ssh --test e2e_sshd -- --ignored --nocapture
cargo test -p vpnctl-ssh --test spec_password_auth -- --ignored --nocapture
```

Release build: `cargo build --release --target x86_64-unknown-linux-musl`.
Changes to protocol rendering should also run `just mutants-protocols` when the
mutation tooling is installed; its current CI job is advisory, not a blocking PASS.

## Project and test map

- `crates/core`, `protocols`, `kernels`, `crypto`, `inventory`, `ssh`,
  `host-fingerprint`, `boosty-bridge`: reusable logic.
- `cli/`: `vpnctl` command-line binary.
- `daemon/`: `vpnctld` API and admin UI.
- `tests/` and crate-local `tests/`: regression/integration coverage.
- `justfile` and `.github/workflows/ci.yml`: canonical local and remote gates.

Add or adjust a deterministic test for behavior changes. A claimed fix is not proven
until the relevant test fails under a planted regression or equivalent mutation and
then passes with the implementation.

## Secrets, generated state, and deployment

- Never read, print, copy into prompts, or commit live inventory/env files, database
  contents, subscription URLs/tokens, SSH keys, admin passwords, or deploy credentials.
- Real state lives outside this repository (for example `/var/lib/vpnctl/inv.db`,
  `/etc/vpnctl/vpnctld.env`, and the legacy private inventory described in `CLAUDE.md`).
  Use placeholders in tests and examples; run gitleaks on the diff before push.
- Do not hand-edit `target/`, generated artifacts, caches, or vendored binaries.
- Production deploy/restore is owner-gated and must follow the current `CLAUDE.md`
  live-deploy/restore procedure from green `main`, including backup before replacement.
  Code rollback is a new revert PR; do not force-push or rewrite published history.

## Done

A task is done only when its diff is scoped, the required commands above pass with
recorded exit codes, target-specific checks are either proven or explicitly marked
not run, secret scan is clean, and the PR reports pre-existing failures separately.
