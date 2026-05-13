# vpnctl

Lightweight, fail-safe, Linux-only control plane for self-hosted VPN
infrastructure. Single static binary, no daemon required, **architecturally
ready for new server kernels and wire protocols** without touching CLI,
inventory, SSH or crypto layers.

Successor to the [`vpn-control`](https://github.com/slovn/vpn-control) bash
scripts. Same domain (sing-box + VLESS+REALITY + TUIC v5), but with type-safe
state, transactional inventory, and a plug-in architecture.

## Status

**v0.1 — scaffold.** Workspace, traits, registry, smoke commands. Real SSH
transport (`russh`) and SQLite inventory land in v0.2.

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
├── ssh/         SshTransport trait + MockTransport (russh impl in v0.2)
├── protocols/   impl Protocol — vless+reality, tuic-v5
├── kernels/     impl Kernel  — sing-box (full)
├── hosters/     DigitalOcean / Cloudzy / Generic (SSH port quirks)
└── inventory/   InMemoryInventory (sqlx+sqlite in v0.2)
cli/             clap-based binary `vpnctl`
```

## Smoke

```bash
cargo run --bin vpnctl -- uuid       # → fresh UUID v4
cargo run --bin vpnctl -- registry   # → enumerates registered kernels & protocols
cargo test --workspace               # → 3 crypto tests pass
cargo clippy --workspace --all-targets -- -D warnings   # → clean
```

## Roadmap

- **v0.2** — `russh` transport, SQLite inventory with migrations, `vpnctl deploy`, `vpnctl user add`, `vpnctl status` end-to-end against a real node.
- **v0.3** — `vpnctl sub <user>` subscription URL generator, `vpnctl rotate` for REALITY keypair re-issuance.
- **v0.4** — daemon mode `vpnctld` (axum + REST API + `/sub/<token>` for clients).
- **v0.5** — optional node-side mTLS gRPC agent for live stats and push updates.

## License

AGPL-3.0-or-later.
