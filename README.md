# vpnctl

[![CI](https://github.com/PavelLizunov/vpnctl/actions/workflows/ci.yml/badge.svg)](https://github.com/PavelLizunov/vpnctl/actions/workflows/ci.yml)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B%20(2024%20ed)-orange.svg)](rust-toolchain.toml)
[![Platform](https://img.shields.io/badge/platform-Linux%20x86__64-lightgrey.svg)](#project-size)
[![Version](https://img.shields.io/badge/version-0.8.0--dev-blue.svg)](#status--v08-in-flight)
[![Lines of code](https://img.shields.io/badge/Rust-~46k%20LOC-blue.svg)](#project-size)
[![Tests](https://img.shields.io/badge/tests-1096-brightgreen.svg)](#project-size)

Lightweight, fail-safe, Linux-only **control plane** for self-hosted VPN
infrastructure. CLI + daemon + admin UI from a single workspace; SSH-first,
no node-side agent, plug-in architecture for adding new wire protocols or
node daemons.

Built as a successor to a bash-based deployment toolkit, with type-safe
state, transactional inventory, audit-on-mutation, and an editorial-style
admin UI that's the operator's **only** required surface — every CLI
action also has a web button.

> **Canonical home:** [github.com/PavelLizunov/vpnctl](https://github.com/PavelLizunov/vpnctl).
> A mirror is published to a private, LAN-only Forgejo instance for
> development. Issues and PRs go on GitHub.

## Status — v0.8 in flight

Operating in production across multiple nodes, with a bilingual EN/RU
admin UI and per-node clash-api health probing.

### Project size

A quick sense of scale (mirrors the badges above):

| Metric | Value |
|---|---|
| Rust source | **~46k LOC** across **10 crates** (8 libs + `cli` + `daemon`) |
| Tests | **1096** functions (`#[test]` + `#[tokio::test]`), ~25k LOC of test code — **~72k LOC** all-in |
| Protocols × Kernels | **8 protocols** × **3 kernels**, fully orthogonal (see [Architecture](#architecture)) |
| Schema | **28** SQLite migrations (`sqlx`, audit-on-mutation) |
| Toolchain | Rust **1.85+**, edition **2024** · single static Linux x86_64 binary (glibc 2.36+) |

> LOC counted over `*.rs` excluding `target/`; tests counted as
> `#[test]` + `#[tokio::test]` attributes across the workspace. Both
> are easy to reproduce: `find crates cli daemon -name '*.rs' | xargs wc -l`.

### What ships today

| Area | State |
|---|---|
| Workspace + traits + CI | ✅ |
| SSH transport (subprocess `/usr/bin/ssh`, glibc 2.36 compatible) | ✅ |
| `vpnctl` CLI — server / user / grant / deploy / sub / status / migrate / bootstrap | ✅ |
| `vpnctld` daemon — REST API + `/sub/<token>` + Admin UI + per-IP rate-limit + persistent bans | ✅ |
| Inventory — sqlx + SQLite, migrations, audit_log, retention scheduler | ✅ |
| Kernels — `sing-box`, `amneziawg`, `wgturn` (VK-TURN-relayed WireGuard) | ✅ |
| Protocols — `vless+reality`, `tuic-v5`, `hysteria2`, `shadowsocks-2022`, `wireguard`, `anytls`, `trojan`, `wgturn` | ✅ (8 across 3 kernels) |
| Hosters — DigitalOcean / Cloudzy / Generic (SSH port quirks) | ✅ |
| Add-server **wizard** (Phase E) — paste IP+root password, SSE-streamed bootstrap | ✅ |
| Backups — VACUUM INTO snapshot + hourly retention + off-site copy + restore CLI/web self-test + CI-protected byte-equality (`restore_e2e`) + in-product Disaster Recovery section | ✅ |
| Subscription endpoint — byte-equivalent migration from legacy Python server | ✅ |
| Boosty subscription bridge — links subscribers to users, reconciles access (auto-enable active, disable-on-button for lapses) | ✅ |
| Protocol visibility — per-(server, protocol) hide + per-(user, server, protocol) deny with OR-semantics | ✅ |
| DPI-risk tiers — Strong / Moderate / Weak chip per protocol (REALITY/wgturn Strong; tuic/anytls Moderate; rest Weak) | ✅ |
| Monitoring — 24h sub-fetch sparkline + heavy-users heatmap + per-user UA fingerprint heuristic | ✅ |
| Audit timeline — paginated + filtered + CSV export | ✅ |
| Infra alerts — `admin_alerts` state-machine on Phase H node probe, Telegram bot transport, bulk-ack button | ✅ |
| **Uptime SLO** — per-server 24h/7d/30d chips on detail page + fleet-wide tile on dashboard | ✅ |
| Bilingual EN/RU shell + nav + body copy (wave 2 shipped; wave 3 in flight) | ✅ |
| 1096 workspace tests, GitHub Actions CI green | ✅ |

### Known gaps (carried into v0.9)

- **Per-user clash-api attribution** — depends on [SagerNet/sing-box#4159](https://github.com/SagerNet/sing-box/pull/4159)
  (1-line `TrackerMetadata.MarshalJSON` patch to emit `"user"`). Until
  accepted upstream, `vpn_connection_stats.user_id` is NULL on every
  row; server-wide totals on the dashboard still work.
- **Wave-3 EN/RU translation** — server-detail Kernels / Enabled-
  protocols / drift / deploy-key body (~600 lines) and user-detail
  sub-token / WG / traffic-limit / per-protocol grid body (~800 lines)
  remain English-only.
- **Stale-fingerprint detection** — TOFU host-key rotation today
  surfaces as a cryptic `server.unreachable` alert. A proactive
  `server.fingerprint.changed` alert with one-click «accept new» would
  close the gap.

See [`CLAUDE.md`](CLAUDE.md) for the full operational handbook,
roadmap, methodology rules, and post-incident notes.

## Architecture

Two orthogonal abstractions — adding either side does **not** touch
the other:

| Trait | Meaning | Examples |
|---|---|---|
| `Kernel` | Node-side daemon that holds the connections | `sing-box`, `amneziawg`, `wgturn` |
| `Protocol` | Wire format presented to the client | `vless+reality`, `tuic-v5`, `wireguard`, `hysteria2`, ... |

A `Kernel` declares which `Protocol`s it can host (`Kernel::supported_protocols()`).
`Registry::validate_server` catches incompatible combinations **before** an
SSH session opens.

Adding a new kernel (e.g. `xray`) = one new file in `crates/kernels/src/` +
one `register_kernel` line. Adding a new protocol = one new file in
`crates/protocols/src/` + one `register_protocol` line. CLI, inventory, SSH
layer, daemon, admin UI, and crypto stay **unaffected**.

Protocols are **stateless** — per-server secrets arrive via `RenderCtx`,
never live on the protocol struct.

## Workspace layout

```
vpnctl/
├── crates/
│   ├── core/             traits Kernel & Protocol, Registry, domain types
│   ├── crypto/           UUID v4, x25519, REALITY short_id, password gen
│   ├── host-fingerprint/ ssh-keyscan wrapper + SHA256 validate_shape
│   ├── ssh/              SshTransport trait + russh implementations
│   ├── protocols/        vless+reality, tuic-v5, hysteria2, ss-2022, wg,
│   │                     anytls, trojan, wgturn
│   ├── kernels/          sing-box (full), amneziawg, wgturn
│   └── inventory/        SqliteInventory, migrations, audit_log
├── cli/                  clap binary `vpnctl`
└── daemon/               axum binary `vpnctld` (admin UI + /sub + REST)
```

## Quickstart

```bash
just check       # cargo check --workspace --all-targets
just test        # cargo test --workspace (1096 tests)
just clippy      # cargo clippy --workspace --all-targets -- -D warnings
just fmt         # rustfmt all crates
just deny        # cargo deny check (no openssl-sys, no native-tls)
just ci          # full local CI sweep before push

just run uuid          # generate a fresh UUID v4
just run registry      # list registered kernels & protocols
```

## Operator flows (all web-driven)

Every action below has both a CLI subcommand and a web button. The web
form is the canonical operator surface; CLI is for automation /
scripting / disaster recovery.

| Goal | Web | CLI |
|---|---|---|
| Add a new server | `/admin/servers/quick-add` wizard, SSE-streamed bootstrap | `vpnctl bootstrap <ip> <password>` then `vpnctl deploy <id>` |
| Add a user | `/admin/users` + form | `vpnctl user add <name>` |
| Grant a user access to a server | `/admin/users/<id>` per-server toggle | `vpnctl grant <user> <server>` |
| Get subscription URL / QR / config | `/admin/users/<id>` (clipboard / QR / `.conf` download) | `vpnctl sub <user>` |
| Hide a Weak protocol from public render | `/admin/servers/<id>` chip click | `vpnctl server protocol hide <id> <pid>` |
| Pin host fingerprint | `/admin/servers/<id>` → «auto via ssh-keyscan» button | `vpnctl server set-fingerprint <id> --from-keyscan` |
| Inspect Boosty bridge state | `/admin/boosty` | `vpnctl boosty status` (add global `--output json` for automation) |
| Ack all infra alerts | `/admin/alerts` → «ack all (N)» button | (none; web-only) |
| Restore a snapshot | `/admin/settings` self-test, then CLI restore on a recovered host | `vpnctl restore <bundle>` |

### Boosty status JSON

`vpnctl boosty status` keeps its human-readable text output by default. For
automation, the global output flag emits a stable, single-line JSON object:

```bash
vpnctl --output json boosty status
```

```json
{"enabled":true,"blog":"creator","access_token":"••••cdef","refresh_token":"••••3456","device_id":"••••wxyz","poll_interval_secs":3600,"auto_disable_lapsed":false,"linked_users":12}
```

`access_token`, `refresh_token`, and `device_id` are always masked as
`••••<last4>`; unset credentials are reported as `(unset)`. The command reads
the configured bridge state from the inventory and does not contact Boosty.

### Binary provisioning

Kernels that ship a prebuilt engine binary (the `dns-tunnel` slipstream
relay, the `naive` Caddy build) install it from the control-node cache
under `/var/lib/vpnctl/cache/`, uploaded to the node and **SHA256-verified**
there before an atomic install. The install is **content-aware**: refresh
the cached binary with a patched build and the next `vpnctl deploy`
reinstalls it automatically when the cache binary's hash differs from the
on-node copy — no manual on-node deletion needed. An unchanged cache binary
is a no-op (idempotent).

## SSH integration tests

```bash
VPNCTL_TEST_HOST=<your-test-host> \
VPNCTL_TEST_USER=<ssh-user> \
VPNCTL_TEST_KEY=$HOME/.ssh/id_ed25519 \
  cargo test -p vpnctl-ssh --test integration -- --ignored
```

## Roadmap (high-level)

- **v0.1** scaffold + CI ✅
- **v0.2** SSH transport, SQLite inventory, CLI subcommands ✅
- **v0.3** bootstrap fresh-node, ProxyJump, subscription URLs ✅
- **v0.4** daemon + REST + `/sub/<token>` + admin UI shell + dashboard ✅
- **v0.5** admin UI feature delivery — users/grants/regen/abuse-signal ✅
- **v0.6** backups + bash-migration ✅
- **v0.7** add-server wizard + protocol breadth (8 protocols) + monitoring + audit + UA fingerprint + Phase H node probe ✅
- **v0.8** restore close-out · uptime SLO chips · bulk-ack alerts · subscription-server migration · DPI-risk tiers · bilingual EN/RU ✅ in flight
- **v1.0** _"everything in roadmap shipped + months of operating experience without rolling back"_

## License

AGPL-3.0-or-later.
