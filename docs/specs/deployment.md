# Contract: deployment

## 1. Intent & Invariants

- What: how vpnctld is built, shipped, and kept alive on the homelab prod host,
  and the runtime constraints that once broke production.
- Invariants:
  - Deploy daemon + CLI from the SAME revision; installing only the daemon used
    to leave `/usr/local/bin/vpnctl` stale and broke the weekly kernel updater.
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
| Assets | `/opt/vpnctl/assets/` |
| Inventory DB | `/var/lib/vpnctl/inv.db` |
| EnvFile | `/etc/vpnctl/vpnctld.env` (creds live here, never in `Environment=`) |
| Deploy key | `/var/lib/vpnctl/.ssh/id_ed25519{,.pub}` |
| Firewall | hand-rolled iptables, INPUT policy DROP; new ports must be opened + persisted to `/etc/iptables/rules.v4` |

Build: static musl — `just build-release`
(`cargo build --release --target x86_64-unknown-linux-musl`). The historical
`cargo zigbuild …gnu.2.36` path is retired.

Deploy: `scripts/deploy.sh` on the prod host — builds (or accepts prebuilt)
daemon + CLI, exports `VPNCTL_BUILD_SHA` before build so binaries report
`<semver>+<sha>` (`vpnctl_core::build_version`, `option_env!`, no git at
runtime), validates BOTH sources before installing either, atomic rename into
place. Then `sudo systemctl restart vpnctld` and verify the changed code path
with a curl. Before replacing: `sudo cp -a /opt/vpnctl/vpnctld
/opt/vpnctl/vpnctld.bak-<tag>`.

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

## 4. Verification Checklist

- [ ] `objdump`/provenance: build stamp `<semver>+<sha>` matches the deployed
      commit.
- [ ] `systemctl is-active vpnctld`; health endpoint 200 with expected version.
- [ ] Changed behavior exercised by a live request after restart.
- [ ] Binary backup created before replacement.
