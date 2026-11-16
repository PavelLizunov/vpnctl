# vpnctl backlog

Deferred work items with enough context to pick up cold. Newest first.

## Editable Corp telephony

P2 runtime limitation confirmed before portal guard: Corp currently forces
IPv4 and has no IPv6 TUN address, so publishing IPv6 phone routes would falsely
suggest usable routing. Keep canonical IPv6 in the signed wire contract, but
reject IPv6 browser publications/restores and proxy IPv4 ranges intersecting
mandatory physical local-network exclusions with an actionable explanation.


P2 confirmed owner-requested gap, recorded before correction at c17cdcd1:
the portal displays five embedded phone exceptions but cannot edit or publish
telephony independently. Add a separately signed feed, durable revision/CAS/history,
and browser editor without changing site-policy bytes, provisioning or credentials.
Scope and verification: `docs/specs/corp-telephony.md`. Implementation in progress;
local compilation and full tests prohibited; exact-SHA GitHub CI required.

Source-confirmed signer retirement gap: operator removal inspected only site
history, so a retained phone envelope could lose its trust key; a concurrent
phone publication could race an earlier inspection. The correction adds phone
history verification and an inventory transaction guard. This specific finding
was recorded immediately after the correction; the feature intent above was
recorded before implementation.

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

# Corp portal findings (2026-11-16)

- P2 live desktop discovery: the existing bottom-sticky save toolbar covers the newly visible page picker in the initial1280x800 view. Remove sticky positioning on desktop as well; save actions remain after the bounded list. Recorded before correction.

- P2 owner-reported annotation noise: every row exposes a comment input populated with inherited Direct sites/Proxy sites labels, duplicating route choice and clipping the route control. Hide the optional note column by default without changing stored comments, and give route controls enough width.
- P2 owner-reported navigation gap: the only page controls appear below the table, so the owner cannot tell that more rules exist. Show remaining-row counts and direct page selection above and below results; preserve the full editable draft.
- P2 confirmed missing rule scope: the site excludes protected UIS/CoMagic/callbackhunter domains and the fixed SIP IP from the editable API seed but offers no explanation or VoIP view. Show their source-verified built-in rules separately, read-only; do not imply live client acknowledgement or call health. Explain the normal find/change/save workflow and show the rule list before the add form.
- P2 confirmed edge import gap: Caddy's parent-file import consumes one brace-escape layer before request_body replacement, so the standalone-tested JSON became an empty authorization body and live DELETE returned422 without deletion. An imported-template regression reproduces all five positive body lengths failing. Recorded before correction. RESOLVED in source: both JSON literals retain protection through one parent import and runtime replacement; all seven imported-template integration tests pass with authorization/storage guards unchanged.
- P2 mobile acceptance: at320px the two-column route/delete row clips the explicit direct label (155px control), and the261px sticky save bar overlaps the list. Record before correction: use full-width route controls, five-row mobile pages and a nonsticky mobile save section. RESOLVED at12a66414: live320px controls254px wide, five rows, static save section and no overflow.
- P2: Corp editor renders all 33 rules, creating a 4711px page at 1280px; no route filter or pagination. Preserve full-draft semantics while bounding the visible list.
- P2: Add preview aligns fields at their bottoms; the route hint offsets labels/controls relative to the comment and submit button. Align control rows, with hints outside them.
- P2: Diagnostics has list/detail/retry but no delete capability, so the owner cannot remove a report and reclaim its live archive storage. Add scoped authenticated deletion with explicit confirmation and late-worker protection.
- P2 historical exposure: docs/MIGRATION_PLAN_NINITUX_AND_NK01.md:47 at 28bade9f contains a real-looking SQLCipher key for a historical parallel Python subscription manager. It is absent current main but remains in 145 PR heads. Full value/source archived privately and verified; current validity against that manager is unverified. No key rotation or history rewrite performed by the 2026-11-16 audit. This is not evidence of current vpnctld database credentials being exposed.

- P1 editable-telephony diff review: history/restore decoded a stored phone payload and checked its digest/metadata, but did not verify its retained signed envelope. An altered envelope could be restored and re-signed despite the state reader rejecting it. Source confirmed in handlers/telephony.rs::stored before correction; share full signature verification across phone state/history/restore.

- P2 PR337/e7b5ca0 exact-head Clippy gate: new phone inventory fixture unnecessarily takes ownership of a JSON value, and the phone runtime validation uses a collapsible nested condition. Both warnings are fatal under the existing -D warnings contract. Recorded before behavior-preserving fixes; do not suppress lints or weaken validation.

- P1 PR337/e7b5ca0 migration compatibility fixture creates today's schema, then removes post71 metadata to reconstruct schema71 but leaves the newly added phone tables. Reopening consequently tries migration74 against already-present tables. Product migration74 itself is additive; remove its tables only inside this isolated historical fixture before removing markers. Recorded before correction.
- P2 PR337/e7b5ca0 browser acceptance cannot find the phone address-type control by its exact label. The dynamic wrapping label includes an embedded select's option text in the computed label. Give generated phone controls an explicit accessible label so assistive technology and the exact user-flow locator identify the intended field. Recorded before correction.
