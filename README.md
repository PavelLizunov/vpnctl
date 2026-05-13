# vpnctl

[![CI](https://github.com/PavelLizunov/vpnctl/actions/workflows/ci.yml/badge.svg)](https://github.com/PavelLizunov/vpnctl/actions/workflows/ci.yml)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)

Lightweight, fail-safe, Linux-only control plane for self-hosted VPN
infrastructure. Single static binary, no daemon required, **architecturally
ready for new server kernels and wire protocols** without touching CLI,
inventory, SSH or crypto layers.

Successor to bash-based `vpn-control`. Same domain (sing-box +
VLESS+REALITY + TUIC v5), but with type-safe state, transactional inventory,
and a plug-in architecture.

> **Canonical home: [github.com/PavelLizunov/vpnctl](https://github.com/PavelLizunov/vpnctl)**
> A mirror is published to a private Forgejo at `192.168.0.207:18300/slovn/vpnctl`
> for LAN-only development. Issues and PRs go on GitHub.

## Status

**v0.2 in progress.**

- ✅ Scaffold — workspace, traits, registry, smoke binary
- ✅ CI — clippy/fmt/test/deny/audit gates green
- ✅ SSH transport — `russh` 0.60, key auth, host-key TOFU, exec/upload/read,
      4 integration tests against live SSH
- ⏳ SQLite inventory with migrations
- ⏳ CLI commands `server add/list/deploy`, `user add/grant/sub`, `status`
- ⏳ End-to-end deploy smoke test via testcontainers

See [`CLAUDE.md`](CLAUDE.md) for the operational handbook.

## Architecture

Two orthogonal abstractions:

| Trait | Meaning | Examples |
|---|---|---|
| `Kernel` | The daemon that runs on the node | `sing-box`, `wgturn`, `xray` |
| `Protocol` | The wire protocol presented to the client | `vless+reality`, `tuic-v5`, `wireguard` |

A `Kernel` declares which `Protocol`s it can host. Adding a new kernel = one
new file in `crates/kernels/src/`. Adding a new protocol = one new file in
`crates/protocols/src/`. The CLI, inventory, SSH layer and crypto are
**unaffected**.

## Workspace layout

```
crates/
├── core/        traits Kernel & Protocol, Registry, domain types, errors
├── crypto/      UUID v4, x25519 keypair, REALITY short_id, password gen
├── ssh/         SshTransport trait, RusshTransport (russh 0.60), MockTransport
├── protocols/   impl Protocol — vless+reality, tuic-v5
├── kernels/     impl Kernel  — sing-box (full)
├── hosters/     DigitalOcean / Cloudzy / Generic (SSH port quirks)
└── inventory/   InMemoryInventory (sqlx+sqlite in v0.2)
cli/             clap-based binary `vpnctl`
```

## Quickstart

```bash
just check       # cargo check --workspace --all-targets
just test        # cargo test --workspace
just clippy      # cargo clippy --workspace --all-targets -- -D warnings
just fmt         # rustfmt all crates
just ci          # full local CI sweep before push

just run uuid          # generate a fresh UUID v4
just run registry      # list registered kernels & protocols
```

To run SSH integration tests against a live server:

```bash
VPNCTL_TEST_HOST=192.168.0.207 \
VPNCTL_TEST_USER=user \
VPNCTL_TEST_KEY=$HOME/.ssh/id_ed25519 \
  cargo test -p vpnctl-ssh --test integration -- --ignored
```

## Roadmap

- **v0.2** — `russh` transport ✅, SQLite inventory with migrations, `vpnctl deploy`, `vpnctl user add`, `vpnctl status` end-to-end against a real node.
- **v0.3** — `vpnctl sub <user>` subscription URL generator, `vpnctl rotate` for REALITY keypair re-issuance, ProxyJump in SSH transport.
- **v0.4** — daemon mode `vpnctld` (axum + REST API + `/sub/<token>` for clients).
- **v0.5** — optional node-side mTLS gRPC agent for live stats and push updates.

## License

AGPL-3.0-or-later.
