# vpnctl backlog

Deferred work items with enough context to pick up cold. Newest first.

## Boosty: independent authorization and stale lapse decisions

Quick Connect copies a browser session. The bridge can preserve and reuse its
tokens, but a browser logout, revocation or competing refresh can invalidate
that session. For the current import flow, use a separate private window and
close it after confirmation so ordinary browsing does not rotate the same grant. Investigate a supported independent authorization before
promising unattended operation across browser-session revocation. Recovery
must remain a web action; never ask operators to extract credentials manually.

Remaining reconcile debt: `observe_boosty_lapse` needs an expected-subscriber
guard and transactional mutation auditing, like `set_boosty_user_disabled`.
Protected absences in an anomalous roster must not start the lapse clock.
Manual lapse-confirmation forms also need to reject decisions after unlink,
relink or subscription recovery instead of using unrestricted user disable.
Cover these interleavings with deterministic tests and preserve existing
subscription identities and grants.

## Remove the SQLx SQLite security backport

`vendor/sqlx-sqlite` preserves official SQLx 0.8.6 Rust sources and changes only
the SQLite dependency requirement to the fixed `libsqlite3-sys =0.39.1`.
Remove the root Cargo patch and vendor package when a reviewed published SQLx
release supports fixed bundled SQLite. Preserve inventory/migration compatibility
and re-run the gates in `docs/specs/dependency-security-remediation.md`.

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

**Status:** closed in code. The blocking `static musl release` CI job installs
musl-tools and cmake, runs `just build-release`, and verifies that both daemon
and CLI have no ELF interpreter. Dependency changes exercise the canonical
release path before acceptance.

## Unverified gap closures

Verify these end to end before declaring them closed:

1. **Fingerprint drift.** `check_fingerprint_drift` exists and fires
   `server.fingerprint.drift`, but the README gap (TOFU host-key rotation
   surfacing as cryptic `server.unreachable` + one-click «accept new») needs a
   full-path check.
2. **TLS cert provisioning.** `sing_box::ensure_installed` generates
   `cert.pem`/`key.pem`, but parity across ALL deploy paths (wizard, CLI,
   redeploy) is unverified.

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
