# vpnctl backlog

Deferred work items with enough context to pick up cold. Newest first.

## Deploy All lock retry on concurrent user auto-deploy

**Status:** closed in code. `daemon/src/wizard_bootstrap/redeploy.rs` routes
Deploy All through `run_redeploy_when_idle`, waiting up to 300 s for each
server's `DeployGuard` (polling every 500 ms). A busy server reports a wait
step; a timeout still reports an error and requires a web Deploy retry.

## Purge retained WgTurn and DNS Tunnel secrets (post-transition release)

**Status:** scheduled post-transition.

Following the approved removal of WgTurn (`0049_remove_wgturn.sql`) and DNS Tunnel
(`0050_remove_dns_tunnel.sql`), active bindings (`server_protocols`, `server_kernels`,
`grant_protocol_overrides`) were removed while `wgturn:*` and `dns-tunnel:*` server secrets
were intentionally retained in SQLite (`server_secrets` table) as rollback material for
one transition release window.

Once the transition release has settled in production across all nodes with legacy units
(`wgturn.service`, `wg-quick@wgturn-be`, `dns-tunnel.service`, `dns-tunnel-singbox.service`)
decommissioned via hoster console, schedule a separate verified migration to purge all
`wgturn:%` and `dns-tunnel:%` rows from `server_secrets`.

## Release path (musl) has no CI coverage

The canonical release build (`just build-release`, static musl) was verified
by hand for the FIRST time on 2026-08-23 (linux-worker: `musl-tools` +
`cmake` + `rustup target add x86_64-unknown-linux-musl` → `static-pie`
binary, ~3 min). CI never exercises it, so a dependency bump could silently
break the only documented release path. Fix: add a (possibly advisory) CI job
that installs musl-tools + cmake and runs
`cargo build --release --target x86_64-unknown-linux-musl -p vpnctld -p vpnctl`
so breakage surfaces at PR time. Note: the 2026-08-23 prod deploy shipped a
same-distro `x86_64-unknown-linux-gnu` build (bookworm worker → bookworm
host) — proven, but not the canonical static target.

## Documentation migration debt (post-CLAUDE.md audit, 2026-08-22)

Items surfaced by the audit that moved the project from `CLAUDE.md` to
`AGENTS.md` + `docs/specs/`:

1. **Stale "web-deploy has no SSH" comments.** `daemon/src/handlers/admin/server_actions.rs:~334`
   and `daemon/src/app.rs:~1129` still say the Deploy button waits for "a
   working SSH path on bookworm-2.36", but SSH deploy shipped via
   `SubprocessSshTransport` + `wizard_bootstrap::run_redeploy`
   (`ensure_installed` + `apply_config`). Rewrite the comments to describe the
   current pipeline.
2. **`probeable()` ignores AmneziaWG.** `daemon/src/node_probe_poller.rs:55`
   `TODO(amneziawg)`: the AmneziaWg kernel is registered, but node probing
   only understands sing-box. Wire a per-kernel probe variant (`wg show`) or a
   sibling `probeable_amneziawg`.
3. **Subscription base URL — closed in code.** `/admin/settings` exposes the
   public base URL; `daemon/src/handlers/admin/legacy/settings/system.rs`
   validates and saves it through `update_public_base_url_audited`. Staging
   overrides no longer require changing a hard-coded URL.
4. **Verify before declaring gaps closed.** (a) Fingerprint drift:
   `check_fingerprint_drift` exists and fires `server.fingerprint.drift`, but
   the README gap (TOFU host-key rotation surfacing as cryptic
   `server.unreachable` + one-click «accept new») needs a full-path check.
   (b) TLS cert provisioning: `sing_box::ensure_installed` generates
   `cert.pem`/`key.pem`, but parity across ALL deploy paths (wizard, CLI,
   redeploy) is unverified.
5. **~50 historical references to `CLAUDE.md`** remain in code comments,
   tests, scripts, and docs. They are provenance pointers; the content now
   lives in `AGENTS.md` / `docs/specs/` and in git history. Optional cleanup:
   retarget them, or leave as historical markers.

## Cumulative per-user traffic attribution (Go helper)

**Status:** closed in code. `tools/singbox-stats-helper/` queries sing-box's
loopback V2Ray Stats API. `daemon/src/clash_poller.rs` uses
`SshStatsClient::cumulative_snapshot` and `record_vpn_cumulative_stats` for
per-user byte deltas with persisted baselines; Clash remains live connection
metadata, and AmneziaWG retains its independent poller. This removes the
active-connection sampling gap; it does not turn payload totals into hoster
wire-traffic billing or prove every production node has the required build.

See [the traffic accounting contract](docs/specs/traffic-accounting-v2.md) for
restart handling, failure behavior, retention and verification requirements.
