# vpnctl

[![CI](https://github.com/PavelLizunov/vpnctl/actions/workflows/ci.yml/badge.svg)](https://github.com/PavelLizunov/vpnctl/actions/workflows/ci.yml)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B%20(2024%20ed)-orange.svg)](rust-toolchain.toml)
[![Platform](https://img.shields.io/badge/platform-Linux%20x86__64-lightgrey.svg)](#project-size)
[![Version](https://img.shields.io/badge/version-0.9.0-blue.svg)](#production-health-check)

Lightweight, fail-safe, Linux-only **control plane** for self-hosted VPN
infrastructure. CLI + daemon + admin UI from a single workspace; SSH-first,
no node-side agent, plug-in architecture for adding new wire protocols or
node daemons.

Built as a successor to a bash-based deployment toolkit, with type-safe
state, transactional inventory, audit-on-mutation, and an editorial-style
admin UI that's the operator's **only** required surface — every CLI
action also has a web button.

> **Canonical home:** [github.com/PavelLizunov/vpnctl](https://github.com/PavelLizunov/vpnctl).
> Issues and PRs go on GitHub.

## Status — v0.9 in flight

Operating in production across multiple nodes, with a bilingual EN/RU
admin UI, cumulative per-user sing-box V2Ray Stats accounting, and per-node
clash-api health probing.

### Project size

A quick sense of scale (the authoritative protocol/kernel lists live in
[Architecture](#architecture) and the registry — `vpnctl registry`):

| Aspect | Value |
|---|---|
| Protocols × Kernels | **10 protocols** × **4 kernels**, fully orthogonal (see [Architecture](#architecture)) |
| Inventory | SQLite via `sqlx`, audit-on-mutation |
| Toolchain | Rust **1.85+**, edition **2024** · static musl Linux x86_64 binaries (`x86_64-unknown-linux-musl`) |

### What ships today

| Area | State |
|---|---|
| Workspace + traits + CI | ✅ |
| SSH transport (subprocess `/usr/bin/ssh`, glibc 2.36 compatible) | ✅ |
| `vpnctl` CLI — server / user / grant / deploy / sub / status / migrate / bootstrap | ✅ |
| `vpnctld` daemon — REST API + `/sub/<token>` + Admin UI + per-IP rate-limit + persistent bans | ✅ |
| Inventory — sqlx + SQLite, migrations, audit_log, retention scheduler | ✅ |
| Kernels — `sing-box`, `amneziawg`, `caddy` (naive / vless-ws cover site), `xray` | ✅ |
| Protocols — `vless+reality`, `tuic-v5`, `hysteria2`, `shadowsocks-2022`, `wireguard`, `anytls`, `trojan`, `naive`, `vless-ws`, `vless+xhttp` | ✅ (10 across 4 kernels) |
| Hosters — DigitalOcean / Cloudzy / Generic (SSH port quirks) | ✅ |
| Add-server **wizard** (Phase E) — paste IP+root password, SSE-streamed bootstrap | ✅ |
| Backups — VACUUM INTO snapshot + hourly retention + off-site copy + restore CLI/web self-test + CI-protected byte-equality (`restore_e2e`) + in-product Disaster Recovery section | ✅ |
| Subscription endpoint — byte-equivalent migration from legacy Python server | ✅ |
| Chain-capable subscriptions — stock sing-box JSON plus capability-gated VPNRouter app-config metadata, both with fail-closed entry filtering | ✅ |
| Boosty subscription bridge — auto-creates complete users for new paid subscribers, grants every server, and supports a configurable disable grace period | ✅ |
| Protocol visibility — per-(server, protocol) hide + per-(user, server, protocol) deny with OR-semantics | ✅ |
| DPI-risk tiers — Strong / Moderate / Weak chip per protocol (REALITY Strong; tuic/anytls Moderate; rest Weak) | ✅ |
| Monitoring — 24h sub-fetch sparkline + heavy-users heatmap + filtered `/admin/sharing` risk page + per-user UA fingerprint heuristic | ✅ |
| Traffic accounting — cumulative per-user sing-box V2Ray Stats (Clash for live metadata; AmneziaWG independent) | ✅ |
| Audit timeline — paginated + filtered + CSV export | ✅ |
| Infra alerts — `admin_alerts` state-machine on Phase H node probe, Telegram bot transport, bulk-ack button | ✅ |
| **Uptime SLO** — per-server 24h/7d/30d chips on detail page + fleet-wide tile on dashboard | ✅ |
| Bilingual EN/RU shell + nav + body copy (wave 2 shipped; wave 3 in flight) | ✅ |
| Workspace test suite, GitHub Actions CI green | ✅ |

### AmneziaWG 2.0 / 3.1 integration

The `amneziawg2` and `amneziawg3` protocols use separate sing-box endpoints,
UDP ports 51821/51822 and address pools 10.72.0.0/16 / 10.73.0.0/16,
with IPv6 pools fd72:72::/64 / fd73:73::/64. Client files route both IP families.
AWG server deployment requires a literal server IP so private destinations and
the configured node address can be rejected for VPN peers.
They do not change the legacy `wireguard` protocol or `amneziawg` kernel.
The operator enables each version on the server page and downloads its native
`.conf` from the user's **Delivery** tab. These files require a client supporting
the specified AmneziaWG version; they are deliberately excluded from generic
sing-box subscriptions and share links.

Downloads require an enabled, granted user, a visible protocol and complete
key material. GET requests never generate or rotate keys. User WireGuard keys
are shared across these protocols: an explicit Generate/Rotate action also
changes existing WireGuard client identity. Server keys and profile seeds remain
stable across deploys; a partially stored server keypair is rejected rather than
silently replaced. Client addresses are derived from the user public key;
unrelated grant changes do not renumber them, and collisions fail closed.

**Kernel requirement:** use the pinned `1.14.0-vpnctl.4` release, verified against
official AmneziaWG 3.1 with real TCP/UDP transfers. `1.14.0-vpnctl.3` accepts
configuration but fails AWG3 data transfer and must not be used for this integration.
Protocol changes schedule a targeted automatic deployment using current inventory.
If a deployment is busy or the inventory changes during preparation, the server
page provides a manual retry; keys and profiles are preserved. See the
[AWG specification](docs/specs/amneziawg2-3.md).

### Known gaps (carried into v0.9)

- **Wave-3 EN/RU translation** — server-detail Kernels / Enabled-
  protocols / drift / deploy-key body (~600 lines) and user-detail
  sub-token / WG / traffic-limit / per-protocol grid body (~800 lines)
  remain English-only.
- **Stale-fingerprint detection** — TOFU host-key rotation today
  surfaces as a cryptic `server.unreachable` alert. A proactive
  `server.fingerprint.changed` alert with one-click «accept new» would
  close the gap.

See [`AGENTS.md`](AGENTS.md) for the agent contract and
[`docs/specs/`](docs/specs/) for the standing contracts (architecture,
workflow, deployment, compatibility, backups). Deferred work lives in
[`BACKLOG.md`](BACKLOG.md); operational history lives in git.

## Architecture

Two orthogonal abstractions — adding either side does **not** touch
the other:

| Trait | Meaning | Examples |
|---|---|---|
| `Kernel` | Node-side daemon that holds the connections | `sing-box`, `amneziawg`, `caddy`, `xray` |
| `Protocol` | Wire format presented to the client | `vless+reality`, `tuic-v5`, `hysteria2`, `shadowsocks-2022`, `wireguard`, `anytls`, `trojan`, `naive`, `vless-ws`, `vless+xhttp` |

A `Kernel` declares which `Protocol`s it can host (`Kernel::supported_protocols()`).
`Registry::validate_server` catches incompatible combinations **before** an
SSH session opens.

Adding a new kernel (e.g. `xray`) = one new file in `crates/kernels/src/` +
one `register_kernel` line. Adding a new protocol = one new file in
`crates/protocols/src/` + one `register_protocol` line. CLI, inventory, SSH
layer, daemon, admin UI, and crypto stay **unaffected**.

Protocols are **stateless** — per-server secrets arrive via `RenderCtx`,
never live on the protocol struct.

### Subscription formats

The canonical public route (`https://ninitux.com/api/v1/sub/<token>`) defaults to the Mihomo / Omarchy YAML format without requiring a query parameter. The legacy `GET /sub/<token>` route is unchanged: without a selector it keeps its existing sing-box/UA behavior, while `?format=mihomo` and `?format=sing-box` remain explicit options.

- **Mihomo / Omarchy format** (default for public `https://ninitux.com/api/v1/sub/<token>`, legacy query `?format=mihomo`): Renders a ready YAML configuration for
  Mihomo, Omarchy, and Clash Meta. The initial scope is `vless+reality` and `hysteria2`;
  unsupported protocols are omitted. Chained routes use Mihomo `dialer-proxy`, failing closed
  (omitting target nodes) when their direct entry node is unavailable or unusable.
- **Stock sing-box format** (`?format=sing-box`): Delivers stock sing-box JSON where chained targets
  carry native `detour` fields and disappear fail-closed when their entry has no usable outbound.
  Fork-only protocols such as `vless+xhttp` remain available to VPNRouter/sing-box-lx but are omitted from stock format exports.

## Workspace layout

```
vpnctl/
├── crates/
│   ├── core/             traits Kernel & Protocol, Registry, domain types,
│   │                     build provenance (build_version)
│   ├── crypto/           UUID v4, x25519, REALITY short_id, password gen
│   ├── host-fingerprint/ ssh-keyscan wrapper + SHA256 validate_shape
│   ├── ssh/              SshTransport trait + russh implementations
│   ├── protocols/        vless+reality, tuic-v5, hysteria2, ss-2022, wg,
│   │                     anytls, trojan, naive, vless-ws,
│   │                     vless+xhttp
│   ├── kernels/          sing-box (full), amneziawg, caddy, xray
│   ├── inventory/        SqliteInventory, migrations, audit_log
│   └── boosty-bridge/    Boosty subscription → user reconcile/sync
├── cli/                  clap binary `vpnctl`
└── daemon/               axum binary `vpnctld` (admin UI + /sub + REST)
```

## Quickstart

```bash
just check       # cargo check --workspace --all-targets
just test        # cargo test --workspace
just clippy      # cargo clippy --workspace --all-targets -- -D warnings
just fmt         # rustfmt all crates
just deny        # cargo deny check (no openssl-sys, no native-tls)
just ci          # full local CI sweep before push

just run uuid          # generate a fresh UUID v4
just run registry      # list registered kernels & protocols
```

### Production health check

`vpnctld` exposes an unauthenticated, read-only liveness endpoint. Check the
daemon directly on its default listen address with:

```bash
curl --fail --silent --show-error http://127.0.0.1:18402/api/v1/health
```

The response is HTTP `200 OK` with a minimal JSON body. `version` is the
stable SemVer — machine-readable and safe to grep/parse. `build` adds
provenance: the same SemVer plus the short Git SHA the binary was built from
(`+unknown` when built outside a Git checkout, e.g. a release tarball):

```json
{"status":"ok","version":"0.9.0","build":"0.9.0+a1b2c3d"}
```

**Release rule.** SemVer (`version`) changes only intentionally, when a
release is cut — it is the operator-facing contract. The build SHA (`build`)
changes on **every** build from a checkout, so two daemons that both report
`version: 0.9.0` are still distinguishable by `build`. The same
`<semver>+<sha>` stamp is shown in the admin UI footer/masthead and by
`vpnctl --version`, giving one provenance string across the deployed daemon
and CLI. The SHA is baked in at compile time: `scripts/deploy.sh` exports
`VPNCTL_BUILD_SHA` before `cargo build`, and `vpnctl_core::build_version()`
reads it via `option_env!` — no build script and no `git` at runtime
(outside a checkout the stamp falls back to `+unknown`).

Use the deployment's public base URL instead of `127.0.0.1:18402` to verify
the reverse-proxy path as well. This endpoint reports `vpnctld` process
liveness only: it does not read or mutate inventory and does not probe VPN
nodes.

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
| Set client 2-hop detour | `/admin/servers/<id>` («Client entry / Входной сервер») | `vpnctl server set-client-detour-via <target> <upstream>` (or `--clear`) |
| Hide a Weak protocol from public render | `/admin/servers/<id>` chip click | `vpnctl server protocol hide <id> <pid>` |
| Pin host fingerprint | `/admin/servers/<id>` → «auto via ssh-keyscan» button | `vpnctl server set-fingerprint <id> --from-keyscan` |
| Inspect Boosty bridge state | `/admin/boosty` | `vpnctl boosty status` (global `--output json` for automation) |
| Ack all infra alerts | `/admin/alerts` → «ack all (N)» button | (none; web-only) |
| Restore a snapshot | `/admin/settings` self-test, then CLI restore on a recovered host | `vpnctl restore <bundle>` |

### Client detour vs SSH jump_via

- **Client detour** (`client_detour_via`): configures a 2-hop VPN client outbound chain where a target server dials out through an entry server in generated subscriptions. Set via `/admin/servers/<id>` («Client entry / Входной сервер») or `vpnctl server set-client-detour-via <target> <upstream>` (`--clear` to remove).
- **SSH `jump_via`**: configures an SSH ProxyJump bastion host used exclusively by the control plane for node administration over SSH.

Client detour chaining is independent of SSH `jump_via`. It supports up to one hop across granted `vpn-exit` servers; self-reference, cycles, and nested chains are rejected. The VPNRouter app-config endpoint publishes a chained VLESS target only when the client advertises `detour-v1`; legacy and generic URI clients continue to receive the unchanged target-omitting response.

### Boosty status JSON

`vpnctl boosty status` keeps its human-readable text output by default. For
automation, the global output flag emits a stable, single-line JSON object:

```bash
vpnctl --output json boosty status
```

```json
{"enabled":true,"blog":"creator","access_token":"••••cdef","refresh_token":"••••3456","device_id":"••••wxyz","poll_interval_secs":3600,"auto_disable_lapsed":false,"grace_days":14,"auto_create_users":true,"linked_users":12}
```

`access_token`, `refresh_token`, and `device_id` are always masked as
`••••<last4>`; unset credentials are reported as `(unset)`. The command reads
the configured bridge state from the inventory and does not contact Boosty.

### Binary provisioning

Kernels that ship a prebuilt engine binary (such as the `naive` Caddy build)
install it from the control-node cache under `/var/lib/vpnctl/cache/`,
uploaded to the node and **SHA256-verified** there before an atomic install.
The install is **content-aware**: refresh the cached binary with a patched build
and the next `vpnctl deploy` reinstalls it automatically when the cache
binary's hash differs from the on-node copy — no manual on-node deletion needed.
An unchanged cache binary is a no-op (idempotent).

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
- **v0.8** restore close-out · uptime SLO chips · bulk-ack alerts · subscription-server migration · DPI-risk tiers · bilingual EN/RU ✅
- **v0.9** Xray/XHTTP · Boosty automation · fleet kernel versions and quality ranking 🚧 in flight
- **v1.0** _"everything in roadmap shipped + months of operating experience without rolling back"_

## License

AGPL-3.0-or-later.
