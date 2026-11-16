# vpnctl backlog

Deferred work items with enough context to pick up cold. Newest first.

## Readable Corp diagnostics and action hierarchy

P3 confirmed owner-requested gap, recorded before correction at f4575087:
the detail view displays evidence/provenance inline and suggested steps near
the bottom. Prioritize the plain owner answer and supported action, preserve
technical detail behind native disclosures and tighten analyzer instructions.
See `docs/specs/corp-diagnostics-readable.md`. No result schema change is needed.

## Corp route distinction in the rules editor

P3 confirmed owner-reported usability gap, recorded before correction: at
c9835eb0, direct/proxy selects share the same presentation and no per-row
explanation links "Без VPN" to ordinary internet. The owner requests clearer
distinction in the rule list, preserving the palette. Scope and verification:
`docs/specs/corp-route-clarity.md`. Implementation and acceptance pending.

Additional owner steering confirmed the isolated Corp green theme and missing
vpnctl identity obscure its relationship with the server UI. Reuse the shared
theme and masthead identity; record this before replacing the standalone style.

Source-confirmed CI duplication, recorded before correction: the check job runs
the aggregate just ci recipe after cargo check, repeating fmt/clippy/test/deny
already assigned separate jobs. Keep all five Cargo gates and both generated
file checks, but execute each in its existing dedicated job. Local just ci stays.

## Protocol-aware availability from multiple client networks

Current path detection uses existing aggregated TCP quality rounds and preserves
incident evidence; it does not establish successful VPN authentication, UDP
availability or a filtering cause. Extend Protocol Assurance with separate
network/endpoint identities, independent tests when SSH telemetry is stale,
probe-identity validity checks and control-target health. Replace duplicate
probes within a bounded handshake budget rather than increasing load. Add a
rate-limited web check action when full-path checks share that budget. Invalid
probe profiles must become Unknown without granting access to extra users.
See `docs/specs/current-path-availability.md`.

## Boosty: independent authorization and stale lapse decisions

Quick Connect copies a browser session. The bridge can preserve and reuse its
tokens, but a browser logout, revocation or competing refresh can invalidate
that session. For the current import flow, use a separate private window and
close it after confirmation so ordinary browsing does not rotate the same grant.
Investigate a supported independent authorization before
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
The live-base backport also documents inventory/backup and static musl checks in
`docs/specs/dependency-security-backports.md`; retain those gates and the reviewed
`russh 0.65.1` dependency without advisory suppressions. The declared workspace
Rust version still needs reconciliation with dependency requirements: even the
previously selected russh required Rust 1.89.

## VexVPN single-server import compatibility

**Status:** next task requested by the owner, after full node/monthly traffic accounting.

The owner-provided VexVPN screenshot rejects the provider's HTTPS subscription
and explicitly requests vless/vmess/trojan/ss server links. Verify the client's
actual import capabilities, then expose direct per-server VLESS links and QR
codes in the existing web delivery flow, with a one-artifact default. Encoding
the same unsupported subscription URL in another QR is not a compatibility fix.
App reference: https://apps.apple.com/ru/app/vexvpn/id6815689581 . Do not copy the
owner's screenshot subscription/device URL or token into Git or reports.

## Forced password change on first SSH login

**Status:** confirmed unsupported by the password-based setup transport.

A hoster can require a root password change before allowing any remote command.
The wizard/deploy-key push currently uses non-interactive sshpass and fails with
`Password change required but no TTY available`. After the password is changed
through the hoster's console, the existing web deploy-key form can install and
verify the key, and deployment can proceed. This is an onboarding gap, separate
from protocol defaults; it must not be described as an incorrect password.
A follow-up needs a web flow that completes the host-required password change,
keeps host-key verification, never logs or persists either password, and verifies
a fresh key-only session before declaring setup complete.

## Client recovery when a node's public IP is filtered

**Status:** design recorded; automatic client failover is not implemented.
Manual Cheburcheck diagnostics are separate from availability and routing.

Prefer Netherlands (`transip`) as a reachable entry, with Sweden as reserve.
`jump_via` restores SSH management only; compatible clients need
`client_detour_via`, an updated subscription and validated transfer through the
entry to the intended exit. URI-only/static WireGuard or AmneziaWG profiles need
their own recovery path. For direct access, investigate a new address from a
different prefix or a provider move; changing SNI/DNS cannot repair IP-level drop.

Next implementation should require repeated real transfer failures plus a
working reserve, respect format/grant compatibility and capacity, audit route
changes and use a stable recovery interval. Cheburcheck failures, 429 and
`uncertain` alone must not trigger changes for every subscriber.
See [recovery options](docs/operations/blocked-node-recovery.md) and the
[incident handoff](https://github.com/PavelLizunov/vpnctl/blob/9ecef81ac491e70f0e435a585b2df01755ba9b58/docs/incidents/2026-11-05-route-failover.md).

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
