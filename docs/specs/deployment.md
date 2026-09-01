# Contract: deployment

## 1. Intent & Invariants

- What: how vpnctld is built, shipped, and kept alive on the homelab prod host,
  and the runtime constraints that once broke production.
- Invariants:
  - Deploy daemon, CLI, managed sing-box, and its stats helper from the SAME
    revision; partial revision rollouts break migrations or traffic accounting.
  - A failed copy must never leave a partial executable (atomic temp + rename).
  - Never ship an SSH library that pulls glibc newer than the prod host.

## 2. Production facts

| | |
|---|---|
| Host | VM 119 `vpnctld`, LAN `192.168.0.236`, Tailscale `vpnctld` |
| Admin UI | `http://vpnctld/admin/` (tailscale serve 80 → 127.0.0.1:18402, tailnet-only, no Funnel) |
| Health | `/api/v1/health` → `{"status":"ok","version":"<semver>","build":"<semver>+<sha>"}` |
| Binary | `/opt/vpnctl/vpnctld` (root:root 0755) |
| CLI | `/usr/local/bin/vpnctl` |
| Node artifacts | `/opt/vpnctl/node-artifacts/{sing-box,singbox-stats-helper}` |
| Assets | `/opt/vpnctl/assets/` |
| Inventory DB | `/var/lib/vpnctl/inv.db` |
| EnvFile | `/etc/vpnctl/vpnctld.env` (creds live here, never in `Environment=`) |
| Deploy key | `/var/lib/vpnctl/.ssh/id_ed25519{,.pub}` |
| Firewall | hand-rolled iptables, INPUT policy DROP; new ports must be opened + persisted to `/etc/iptables/rules.v4` |

Build: static musl — `just build-release`
(`cargo build --release --target x86_64-unknown-linux-musl`). The historical
`cargo zigbuild …gnu.2.36` path is retired. Musl verified 2026-08-23 on a
bookworm build host with `musl-tools` + `cmake` installed and
`rustup target add x86_64-unknown-linux-musl` (output: `static-pie`); those
build-host prerequisites are NOT yet covered by CI (see BACKLOG.md).

Deploy: `scripts/deploy.sh` on the prod host — builds (or accepts prebuilt)
daemon + CLI + managed sing-box + node-side stats helper, exports
`VPNCTL_BUILD_SHA` before the Rust build so binaries report `<semver>+<sha>`
(`vpnctl_core::build_version`, `option_env!`, no git at runtime), validates all
four sources before installing any, stages all four, installs node artifacts
first and daemon last, and rolls every prior path back on an interrupted swap.
The Go artifacts are static linux/amd64 builds; managed sing-box must report the
`with_v2ray_api` tag. For the accounting migration, install artifacts first,
deploy every sing-box node while the old daemon still polls Clash, verify the
loopback Stats API, and only then restart vpnctld; this avoids a collection gap
during rollout. Then `sudo systemctl restart vpnctld` and verify the changed code path
with a curl. Before replacing: `sudo cp -a /opt/vpnctl/vpnctld
/opt/vpnctl/vpnctld.bak-<tag>`.

Managed node artifacts use unique `/tmp/vpnctl-*.{pid}.{seq}` upload paths,
then move to executable staging under `/usr/local/libexec/vpnctl` before
validation because hardened nodes may mount `/tmp` `noexec`. Exit and signal
traps remove both uploads and stages. A node-local
`/run/lock/vpnctl-singbox-install.lock` (`flock -w 300`) serializes every shared
backup, install, health-check, and rollback path.

## 3. Runtime constraints (learned from incidents)

- **glibc hazard.** Prod is Debian bookworm (glibc 2.36). Any dependency that
  pulls glibc ≥ 2.38 sysroots, or `tokio::process` (`pidfd_spawnp` = 2.39),
  crash-loops the daemon. Deliberate architectural compromise: SSH runs through
  the system `/usr/bin/ssh` via subprocess (`daemon/src/ssh_subprocess.rs`,
  `std::process::Command` + `spawn_blocking`) — no russh, no `tokio::process`.
  Do not reintroduce an in-process SSH library without resolving the target
  glibc first.
- **Trusted proxies.** Behind any reverse proxy set `VPNCTLD_TRUSTED_PROXIES`
  in `/etc/vpnctl/vpnctld.env`; otherwise client IPs log as the proxy and the
  suspicious-local-ip detector fires on every legit request. Security
  invariant: once a proxy is trusted, `resolve_peer_real_ip` trusts its
  `X-Real-IP` — so every proxy block targeting vpnctld must authoritatively
  `header_up X-Real-IP {client_addr}`, and the site config must strip any
  client-supplied `X-Real-IP` before routing.
- **WgTurn and DNS Tunnel decommission and node cleanup gate.** The WgTurn and
  DNS Tunnel removal release must **NOT** be deployed to production until legacy
  `wgturn.service`, `wg-quick@wgturn-be`, `dns-tunnel.service`, and
  `dns-tunnel-singbox.service` units are stopped, disabled, and removed on every
  affected server via the hoster's console (never via SSH instructions,
  strictly adhering to the web-only / hoster console policy).
- **Migration backup and rollback.** Before the daemon version containing
  migrations `0049_remove_wgturn.sql` and `0050_remove_dns_tunnel.sql` starts,
  create and verify an inventory snapshot using the standard backup procedure
  (pre-0049 / pre-0050 verified snapshots). Migration 0050 removes active
  bindings (`server_protocols`, `server_kernels`, `grant_protocol_overrides`)
  while intentionally retaining `dns-tunnel:*` secrets (alongside retained
  `wgturn:*` secrets from 0049) for one transition release. A rollback
  requires restoring the verified pre-0050/pre-0049 inventory snapshot and
  restoring the previous node units/configuration through the hoster's console;
  retained secrets alone are not a complete rollback. Purging them requires a
  separate verified cleanup release after the transition settles.

## 4. Verification Checklist

- [ ] `objdump`/provenance: build stamp `<semver>+<sha>` matches the deployed
      commit.
- [ ] `systemctl is-active vpnctld`; health endpoint 200 with expected version.
- [ ] Changed behavior exercised by a live request after restart.
- [ ] Binary backup created before replacement.
- [ ] Pre-0050 (and pre-0049) inventory snapshot created and `verify_snapshot`
      passed; restore path and snapshot location recorded before daemon
      startup.
- [ ] Pre-deploy cleanup verified: legacy `wgturn.service`, `wg-quick@wgturn-be`,
      `dns-tunnel.service`, and `dns-tunnel-singbox.service` stopped/disabled/removed
      on every affected server via hoster console prior to daemon restart.
- [ ] Inventory migration verified: active WgTurn and DNS Tunnel bindings
      unbound, `wgturn:*` and `dns-tunnel:*` secrets retained for rollback
      window, audit rows generated only on mutation (`protocol.remove_wgturn`,
      `protocol.remove_dns_tunnel`).
- [ ] Follow-up `wgturn:*` and `dns-tunnel:*` secret purge tracked for
      subsequent verified cleanup.
