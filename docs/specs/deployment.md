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

The [Boosty author dashboard](boosty-author-dashboard.md) is available on the
HTTPS admin at `https://vpnctld.tail9fd337.ts.net/admin/boosty`. Set
`VPNCTLD_BOOSTY_DASHBOARD_URL` to enable the native views and provide the
standalone URL on port 9443. vpnctl reads the service on loopback port 3001.
Keep the credential-stripping ingress on port 9443 for standalone access.

For the [manual DNSTT check](dnstt-on-demand-assurance.md), install
`scripts/dnstt-assurance-on-demand.py` as a root-owned executable and point
`VPNCTLD_DNSTT_CHECK_RUNNER` to it. The adapter uses the separately provisioned
one-shot probe and its private template.

### VPNRouter source-diagnosis catalog

`POST /api/v1/assistant/vpnrouter/source-diagnosis` uses the same
subscription/device credentials, gateway settings and `Cache-Control: no-store`
transport as `/plan` and `/step`. It additionally reads a trusted release
catalog from `VPNCTLD_VPNROUTER_SOURCE_CATALOG`. Set it in
`/etc/vpnctl/vpnctld.env`:

```sh
VPNCTLD_VPNROUTER_SOURCE_CATALOG=/etc/vpnctl/vpnrouter-source-catalog.json
```

The path must be absolute. The catalog must be a regular, non-symlink file
owned by root with no group or world write permission; every parent directory
is checked the same way. Install public source excerpts as `root:root 0644`
because vpnctld reads the file as an unprivileged service user. If the setting
is unset, the route treats every build as unmapped and returns
`unknown_build` without calling the provider. If the setting is present but the
file is missing, unsafe or malformed, the route returns 503 and never calls the
provider. Do not put credentials, private logs or account data in this file.

Match the tag commit and supported targets to the build provenance of the published
artifacts. Review each selected range for data suitable for external disclosure.
The assistant sends those public source lines to its provider on a matching request.
Build the catalog offline with Git and Gitleaks 8 installed. The manifest
names the version, the full 40-hex commit, the supported platform/architecture
pairs and the selected `path`/`first`/`last` ranges. Optional `areas`, `signals`
and `faults` selectors use the same values as the `/step` crash enums:

```json
{
  "schema": 1,
  "releases": [{
    "version": "2.51.0-r2",
    "commit": "<40 lowercase hex>",
    "targets": [{"platform": "windows", "arch": "x64"}],
    "excerpts": [{
      "path": "VPNRouter.Core/Services/Example.cs",
      "first": 15,
      "last": 23,
      "areas": ["routing", "startup"],
      "signals": ["tun_busy"],
      "faults": ["network"]
    }]
  }]
}
```

```sh
python3 scripts/vpnrouter-source-catalog.py \
  --repo /path/to/VPNRouter \
  --manifest /secure/vpnrouter-2.51.0-r2.manifest.json \
  --output /secure/vpnrouter-source-catalog.json
sudo install -o root -g root -m 0644 \
  /secure/vpnrouter-source-catalog.json \
  /etc/vpnctl/vpnrouter-source-catalog.json
sudo systemctl restart vpnctld
```

The generator reads committed blobs with Git repository-environment overrides,
network transports, lazy fetching and replacement objects disabled. It scans the
decoded excerpt text with Gitleaks before writing the catalog. A scanner error or
secret finding preserves the prior catalog. It accepts only regular committed files; a symlink entry is
rejected. If a mapping is missing, the generator fails instead of guessing. For
each build, the service ranks excerpts by the observed crash signal, area and
fault. It keeps up to 12 excerpts within 24 KiB of text and trims the lowest-ranked entries to fit 32 KiB of serialized JSON. Signal
matches rank above area matches and area above fault; an excerpt without
selectors is a fallback, and an excerpt whose selectors do not match is not
sent. Tag representative routing, startup, UI and settings sources so different
crash classes receive different evidence even when the catalog is larger than
the prompt budget. Connection evidence maps to selectors as follows:
`startup_timeout` uses `areas: ["startup"]`; `readiness_timeout` uses
`areas: ["startup"]` and `signals: ["proxy_unreachable"]`; `unexpected_stop`
uses `areas: ["routing"]` and `signals: ["stop_unconfirmed"]`; `tun_busy` uses
`areas: ["routing"]` and `signals: ["tun_busy"]`. The request carries exactly
one of `crash` or `connection`, never both or neither. If the crash reports only
`fault: unknown`, `area: unknown` and `signal: none`, or no excerpt matches, the
route returns
`{"schema":1,"result":{"operation":"insufficient_evidence"}}` without a
provider call and Desktop abstains locally. The service caps the catalog at
512 KiB, 1 to 64 releases, 8 target pairs
and 24 excerpts per release; each excerpt is at most 48 lines and 4096 UTF-8
bytes. Route the exact POST path through the existing reverse proxy, preserve
`Authorization` and `X-Vpnctl-Identity`, keep the 2048-byte body limit and set
`X-Real-IP` from the trusted proxy block. An authorized request for an
unregistered version/commit/platform/arch tuple returns HTTP 200 with
`{"schema":1,"result":{"operation":"unknown_build"}}` without a provider call.

An account can occupy one provider slot. Each daemon has two slots. When either limit is reached, the route returns HTTP 429 with `diagnosis_busy` and `Retry-After: 1`.

Build static musl binaries with `just build-release` on a
[HomeLab worker](agent-workflow.md#remote-builds-and-tests) or in GitHub Actions.
The CI job installs `musl-tools`, `cmake`, and the Rust
`x86_64-unknown-linux-musl` target. Set `VPNCTL_BUILD_SHA` at compile time
so the daemon and CLI report the source revision.

For production, select an accepted `main` commit with green CI. Use its
`vpnctl-daemon-<sha>` and `vpnctl-node-<sha>` artifacts. GitHub Actions
retains these artifacts for seven days. If they have expired, rebuild both
sets at the same SHA on the HomeLab worker using the `static-musl` and
`managed-node-artifacts` jobs in [CI](../../.github/workflows/ci.yml) as the
build recipe. Before installation, verify both `source-sha.txt` files against
the intended commit and run `sha256sum -c SHA256SUMS` in each artifact directory.

On the production host, use the four-argument form of `scripts/deploy.sh`
with the prebuilt daemon, CLI, managed sing-box, and stats helper. Set
`VPNCTL_ASSETS_SRC` to the matching assets directory from the daemon artifact.
The script validates the sources before staging them, installs node artifacts
first and daemon last, and rolls every prior path back on an interrupted swap.
An inter-run `flock` on `${VPNCTL_DAEMON_DST}.deploy.lock` (override with
`VPNCTL_DEPLOY_LOCK`) covers builds, staging, swaps and rollback; the lock file
is kept in place. Swap bookkeeping precedes each rename so a signal on either side
restores the previous set.
Admin UI assets are served from `/opt/vpnctl/assets/`, so they are replaced as
one set in the same transaction: a checkout build ships its `daemon/assets`,
prebuilt artifacts must pass theirs in `VPNCTL_ASSETS_SRC`, or set
`VPNCTL_SKIP_ASSETS=1` to keep the live set deliberately; otherwise the script
refuses before touching anything (new markup with an old `admin.js` breaks the
deploy buttons).
The Go artifacts are static linux/amd64 builds. Managed sing-box deployment
rejects non-amd64 nodes before changing them because its stats helper is amd64;
managed sing-box must report the `with_v2ray_api` tag. For the accounting
migration, install artifacts first, deploy every sing-box node while the old
daemon still polls Clash, verify the
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

Every deploy path (admin POST, SSE/autodeploy, and CLI) stops and disables
managed service units for retired kernels and enabled kernels with no enabled
protocols. Such kernels are not installed or rendered during that deploy, so an
old listener cannot retain revoked users. Shutdown errors fail the deploy;
a successful shutdown-only deploy may establish the applied revision with zero
configs uploaded. Kernels with enabled protocols and unrelated node services
remain untouched by shutdown reconciliation.

Secret-bearing node configs are uploaded only after their directory is verified
not to be a symlink, made root-owned, and stripped of group/other write access.
Stale staging entries are unlinked before creating root:root `0600` files, so
uploads cannot follow a service-planted symlink or truncate a hard-link target.
The directory stays protected across SSH calls. Xray's directory is root:xray
`0750`, its live config is root:xray `0640`, and its service has no writable
config-directory exception. Upload/apply errors attempt staging cleanup; apply
scripts also clean stages on exit and handled signals, including unpacked
Caddy bundle members and AWG validation copies. Atomic installation keeps the
existing live ownership/modes except for Xray's read-only ownership: sing-box
`0640` with its service owner, Caddyfile root:caddy `0640`, Caddy's sing-box
backend root:root `0600`, and AWG root:root `0600`. AWG failure diagnostics must not print stripped
configs containing private or preshared keys.

## 3. Runtime constraints (learned from incidents)

- **HTTP connections.** The HTTP/1 server uses a Tokio timer and a 15-second
  deadline for reading request headers, before routing or middleware. At most
  256 connections are active; excess accepted sockets are closed immediately.
  This is separate from the existing 15-second handler timeout. Peer socket
  addresses remain available through `ConnectInfo<SocketAddr>`. Shutdown stops
  accepting sockets, drains active HTTP requests, then drains the access-log
  writer.
- **glibc hazard.** Prod is Debian bookworm (glibc 2.36). Any dependency that
  pulls glibc ≥ 2.38 sysroots, or `tokio::process` (`pidfd_spawnp` = 2.39),
  crash-loops the daemon. Deliberate architectural compromise: SSH runs through
  the system `/usr/bin/ssh` via subprocess (`daemon/src/ssh_subprocess.rs`,
  `std::process::Command` + `spawn_blocking`) — no russh, no `tokio::process`.
  Do not reintroduce an in-process SSH library without resolving the target
  glibc first.
- **Trusted proxies.** Behind any reverse proxy set `VPNCTLD_TRUSTED_PROXIES`
  in `/etc/vpnctl/vpnctld.env` as a comma-separated list of exact IPv4/IPv6
  addresses or CIDR ranges, for example `127.0.0.1/32,10.0.0.0/8,::1/128`.
  Surrounding whitespace is ignored; unset or whitespace-only values trust
  no proxies. Invalid entries (including empty entries between commas) stop
  startup with an error naming the bad entry. Without this setting, client
  IPs log as the proxy and the suspicious-local-ip detector fires on every
  legit request. Security and access logging (including GeoIP and sharing
  signals) use the same resolver: trusted peers supply a single valid
  `X-Real-IP`; missing or invalid values fall back to the peer address.
  Untrusted peers always use the peer address. `X-Forwarded-For` is ignored.
  Every proxy block targeting vpnctld must authoritatively
  `header_up X-Real-IP {client_addr}`, and the site config must strip any
  client-supplied `X-Real-IP` before routing. For HTTPS admin access the proxy
  must also overwrite `X-Forwarded-Proto` with the actual external scheme;
  trusted `X-Forwarded-Proto: https` makes admin session cookies `Secure`.
- **Admin assets.** Startup requires readable regular files `admin.js`,
  `admin.css`, `icons.svg`, and `favicon.svg` in the selected assets directory.
  Selection uses the first existing path: `assets` relative to the working
  directory, the build-time daemon crate's `assets`, then `daemon/assets`
  relative to the working directory. An incomplete selected directory stops
  startup with the missing file's path; it does not fall back to another
  directory. Ship the full assets tree, including fonts (font loading retains
  the stylesheet's fallback fonts).
- **Deploy key readiness.** Startup reports the daemon deploy key ready only
  after deriving its public key from the private key and checking that the
  `.pub` file matches (comments may differ). A missing `.pub` is regenerated
  without replacing the private key. An unreadable, invalid, or mismatched
  pair produces a startup warning instead of a ready message; mismatched
  files are not overwritten.
- **Inventory snapshot directory.** The CLI backup commands, daemon hourly
  scheduler and Web snapshot creation, listing, download and self-test use
  `vpnctl_inventory::backup_dir_from_env()`: `VPNCTLD_BACKUP_DIR` overrides
  `vpnctl_inventory::DEFAULT_BACKUP_DIR` (`/var/lib/vpnctl/backups`). Set the
  override in `/etc/vpnctl/vpnctld.env` and in the CLI environment to use the
  same directory; the daemon user needs write access. The separate encrypted
  bundle script uses `BACKUP_DIR`; set it too if those archives should share
  the custom directory.
- **Inventory file permissions.** The shared inventory open path creates a
  new database with mode 0600 before SQLite connects. Newly created inventory
  parent directories use mode 0700, including CLI/daemon path resolution.
  SQLite creates new WAL/SHM sidecars with the database's private permissions.
  Existing database/sidecar permissions are preserved; group/world access
  produces a warning at open rather than silently changing ownership policy.
- **Node-proxied GeoIP refresh.** Each compressed download is capped at
  128 MiB and each decompressed MMDB at 512 MiB on the controller. Oversized
  responses fail without replacing the installed database. Local SSH attempts
  share `VPNCTLD_GEOIP_DEADLINE_SECS` (default 480 seconds); exit and handled
  HUP/INT/TERM signals remove that updater's partial files.
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

- [ ] Incomplete HTTP/1 headers expire without invoking a handler; excess
      connections close, completed connections release their slots, and
      graceful shutdown preserves in-flight responses and peer metadata.
- [ ] Both artifact sets report the intended SHA in `source-sha.txt` and pass
      `sha256sum -c SHA256SUMS`.
- [ ] `objdump`/provenance: build stamp `<semver>+<sha>` matches the deployed
      commit.
- [ ] `systemctl is-active vpnctld`; health endpoint 200 with expected version.
- [ ] Changed behavior exercised by a live request after restart.
- [ ] VPNRouter source catalog is present at the configured path, `root:root`
      with no group/world write access, and a registered build returns a
      diagnosis while an unregistered build returns `unknown_build`.
- [ ] Routing and startup crash requests select different tagged excerpts when
      the catalog exceeds the prompt budget; a crash with only unknown
      fault/area/signal, or one with no matching excerpt, returns
      `insufficient_evidence` without a provider call.
- [ ] A connection request with exactly one of `startup_timeout`,
      `readiness_timeout`, `unexpected_stop` or `tun_busy` forwards that code
      without a crash object; null, both or neither evidence form is rejected.
      The same known/unknown/missing-source results apply.
- [ ] With the catalog setting unset, the source-diagnosis route returns
      `unknown_build` without a provider call. With the setting present but the
      file missing or malformed, it returns 503.
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
