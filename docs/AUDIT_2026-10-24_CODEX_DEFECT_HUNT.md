# Codex defect hunt — 2026-10-24

Baseline: `origin/main` @ `c399603`. Method: parallel read-only `codex exec`
agents (one per area) produced candidates; every candidate below was then
re-read against the source by the lead session. "Verdict" is the lead's
verification result and the lead's severity, which may differ from the
agent's. No fixes are included in this document's commit.

Verdicts: **confirmed** (code path read end to end, failure reproducible from
the code), **confirmed-narrow** (real, but reachable only via CLI, an unusual
configuration, or a short race window).

## Round 1

| ID | Sev | Verdict | Area | Defect |
|----|-----|---------|------|--------|
| CDX-01 | important | confirmed | inventory/boosty | `add_boosty_user` grants every server; the `trg_grant_rejects_workload_role` trigger aborts the whole transaction as soon as one `workload-only` server exists, so Boosty auto-create never creates users. |
| CDX-02 | important | confirmed | inventory/stats | Raw-stats retention is 30 days, but monthly usage and limit alerts read only raw stats. On day 31 the first hours of day 1 are purged, usage drops and the limit alert is auto-acked. |
| CDX-03 | important | confirmed | inventory/stats | `remove_user` leaves `vpn_connection_stats` rows (no FK). `rollup_vpn_user_daily` inserts them into `vpn_user_daily` (FK to users), the insert fails and the whole day's rollup transaction rolls back for every user. |
| CDX-04 | minor | confirmed | migrations | `0043_vpn_server_hourly.sql` seeds midnight buckets with full daily totals, then adds raw hourly data for the same days; only the midnight bucket is replaced, so already-migrated history double-counts the overlap window. One-time, historical. |
| CDX-05 | important | confirmed | inventory/detour | `client_detour_via ... ON DELETE SET NULL`: deleting an entry server silently turns chained targets into direct ones, violating `client-detour.md` ("no direct fallback"); no audit row for the cleared policy. |
| CDX-06 | minor | confirmed-narrow | backup | `restore_from` only checks that `sqlite_master` is non-empty; any foreign SQLite file migrates to an empty vpnctl schema and replaces the live DB. CLI-only. |
| CDX-07 | important | confirmed | vpn_router app-config | Extra protocols (vless-ws, xhttp, naive, hy2) render with global `users.uuid`; servers use `COALESCE(grants.client_uuid, users.uuid)`. Users with a per-server UUID get links that fail auth. `/sub` already uses `user_with_per_server_uuid`. |
| CDX-08 | important | confirmed | sub/sing-box | When no outbound is rendered (all grants revoked / all hidden) the envelope still sets `route.final = "proxy"` without a `proxy` outbound; clients reject the config. `empty_singbox_config()` exists but is used only for disabled users. |
| CDX-09 | important | confirmed | sub/sing-box, mihomo | Outbound tags are `"{display} {proto} ~{user}"`; two servers with the same display name (allowed by the form) produce duplicate sing-box tags / Mihomo names; Mihomo's `candidate_map` silently overwrites. |
| CDX-10 | important | confirmed | protocols/ss2022 | Shadowsocks-2022 uses one server-wide PSK and ignores the user list; disabling/deleting a user never revokes their `ss://` link. Design-level; needs per-user keys or rotation on revoke. |
| CDX-11 | important | confirmed | protocols/wireguard | Legacy `wireguard` peer addresses are the index in the sorted granted-user list; any grant change re-numbers other users' `AllowedIPs`, breaking their already-imported configs. (AmneziaWG 2/3 use key-derived addresses and are not affected.) |
| CDX-12 | important | confirmed | protocols/xhttp | `VlessXhttp::server_secret_specs` declares only `vlessxhttp.path` but render requires `vless.private_key`/`vless.short_id`; an xray-only `vless+xhttp` server never gets them minted and deploy fails with `MissingSecret`. |
| CDX-13 | minor | confirmed-narrow | protocols/vless-ws | Port validation ignores the fixed loopback backend `127.0.0.1:11443`; choosing front port 11443 passes validation and the deploy fails with a bind conflict. |
| CDX-14 | important | confirmed | kernels/caddy | `Caddyfile` (Naive `basic_auth` passwords) and `vlessws-singbox.json` (user UUIDs) are installed `0644` in a world-readable `/etc/caddy`. |
| CDX-15 | important | confirmed | kernels apply scripts | AmneziaWG / sing-box / xray apply scripts run `systemctl reload-or-restart` under `set -eu` without `|| …`; a non-zero exit (typical for the oneshot `awg-quick@awg0`) exits before the `.bak` rollback, leaving the bad config live. |
| CDX-16 | minor | confirmed | kernels/sing-box | The managed sing-box installer replaces `/usr/bin/sing-box` and restarts only `sing-box.service`; `caddy-vlessws` (same binary) keeps running the old version after a web kernel update. |
| CDX-17 | minor | confirmed-narrow | kernels/caddy | Without the local Caddy cache the installer accepts any installed Caddy with `forward_proxy`, ignoring the `CADDY_VERSION` pin; "update kernels" reports success without updating. |
| CDX-18 | minor | confirmed | kernels/amneziawg | `AmneziaWg` and `Caddy` inherit the no-op `open_firewall`; on nodes where UFW is active the WireGuard UDP port / Naive 443 stay closed (sing-box and xray open theirs). |
| CDX-19 | minor | confirmed-narrow | kernels/caddy | `caddy` + `vless-ws` without the `sing-box` kernel passes validation but the backend unit needs `/usr/bin/sing-box`, which nothing installs. Web paths always add sing-box; reachable via CLI. |
| CDX-20 | minor | confirmed-narrow | kernels/xray | Xray is installed with a direct `install` over the live binary (no staging + rename); a failed copy (disk full) leaves no executable. |
| CDX-21 | important | confirmed | ssh/password push | The sshpass path uses the shared `known_hosts` with `accept-new` and ignores the inventory `trusted_host_fingerprint`; with no `known_hosts` entry (restore, new daemon host) the password goes to whatever key answers. The reference-key failure also falls back to it. |
| CDX-22 | important | confirmed | deploy lock | The synchronous `POST /admin/servers/{id}/deploy` runs under the global 15 s `TimeoutLayer`; on timeout the handler future (and `DeployGuard`) drops while the `spawn_blocking` SSH work continues, so a second deploy can run concurrently on the same node. |
| CDX-23 | minor | confirmed | ssh/password run | `ssh_password_run` uses blocking `Command::output()` with no overall timeout or kill; a remote command that hangs while keepalives succeed blocks the wizard/push indefinitely. |
| CDX-24 | important | confirmed | ssh/authorized_keys | Deploy-key push appends with `echo >> ~/.ssh/authorized_keys` without ensuring a trailing newline; a file whose last key lacks LF gets the new key glued onto it, breaking both keys (wizard + push paths). |
| CDX-25 | important | confirmed | admin auth | Argon2 verification runs synchronously inside the async auth middleware, on every unauthenticated request with a Basic header, with no failed-auth throttling: CPU exhaustion and unlimited password guessing. |
| CDX-26 | important | confirmed | admin CSRF | Deploy / deploy-all / update-kernels(-all) / wizard step-2 / deploy-pending start on `GET …/sse`. The only guard is `Sec-Fetch-Site`, which browsers do not send to plain-HTTP origins (the documented `http://vpnctld/admin/`), so a cross-site navigation triggers them. |
| CDX-27 | minor | confirmed | admin auth | Logout only clears the session cookie; the browser's cached Basic credentials re-authenticate on the redirect, and the middleware appends a fresh session cookie to the logout response itself. |
| CDX-28 | minor | confirmed-narrow | real_ip | Access logging uses the leftmost `X-Forwarded-For` while security decisions use `X-Real-IP`; behind a proxy that appends XFF (nginx `$proxy_add_x_forwarded_for`) clients choose the logged IP/country, skewing sharing detection. Caddy replaces untrusted XFF, so the documented setup is safe. |
| CDX-29 | minor | confirmed | admin auth config | A syntactically valid but hash-less PHC (`$argon2id`) passes startup validation; the daemon starts and every login returns 401. |
| CDX-30 | minor | confirmed | wg_stats_poller | `compute_byte_deltas` advances the in-memory baseline before `record_vpn_stats`; on a write error the delta is lost although the log says "will retry next tick". |
| CDX-31 | important | confirmed | node_probe alerts | `server.unreachable` recovery depends on the in-memory `fired` flag; after a daemon restart an open alert is never recovered or auto-acked. |
| CDX-32 | minor | confirmed | health_monitor | The monitor diffs only the two newest samples; extra samples (manual probes from the monitoring page) between scans can hide a `true→false` transition, so `server.singbox.down` and its auto-restart never fire. |
| CDX-33 | minor | confirmed | health_monitor | One-shot `server.singbox.restarted` events go through `insert_alert_acked`, which ignores `_source_event`; while no new samples arrive (SSH down) every scan re-inserts the same restart. |
| CDX-34 | minor | confirmed | protocol_assurance | `recovers_open_alert` lets `Unknown` results (`tcp_path_only`, `udp_path_unverified`, `no_probe_identity`) recover any open assurance alert, including handshake failures found by the external runner; removing the runner reports a false "recovered". |
| CDX-35 | important | confirmed | admin grants | Bulk "revoke all" iterates `users_for_server`, which filters `u.disabled = 0`; disabled users keep their grants and regain access when re-enabled. |
| CDX-36 | minor | confirmed-narrow | boosty settings | Web/CLI settings save does read-modify-write of all columns including `refresh_token`; a sync rotating the token between the read and the write is overwritten with the stale token. |
| CDX-37 | important | confirmed | billing | Costs with a missing exchange rate are silently skipped from the fleet monthly total; profit and coverage are shown as if complete. |
| CDX-38 | minor | confirmed | user limits | `user.traffic_limit.set` audit is written unconditionally, including no-op saves (violates audit-on-actual-mutation). |

## Round 2

Round 2 agents received the round-1 titles to avoid repeats. Four candidates
duplicated round 1 (bulk revoke ×2 → CDX-35, password fallback → CDX-21) or
each other (pending deploy), and are merged below.

| ID | Sev | Verdict | Area | Defect |
|----|-----|---------|------|--------|
| CDX-39 | important | confirmed | scripts/deploy.sh | The daemon serves CSS/JS from `/opt/vpnctl/assets` (`WorkingDirectory=/opt/vpnctl`), but `deploy.sh` installs only binaries and `chmod`s the existing assets dir; a deploy ships new markup with the previous revision's `admin.js`/CSS. |
| CDX-40 | minor | confirmed-narrow | tools/stats helper | `singbox-stats-helper` is always built `GOARCH=amd64` and uploaded from one path, while sing-box is chosen per `uname -m`; on ARM nodes the Stats check fails with `Exec format error` and the deploy rolls back. |
| CDX-41 | minor | confirmed | scripts/import | `import_from_subscription_server.py` prints full client UUIDs and VPNRouter device IDs (device ID alone fetches `/api/v1/app/config`) in plan and apply output, including dry-run. |
| CDX-42 | minor | confirmed-narrow | scripts/deploy.sh | No inter-run lock: a run that rolls back after another run finished restores its own stale backups over the newer set. |
| CDX-43 | minor | confirmed-narrow | scripts/deploy.sh | `SWAPPED` is incremented after `mv`; a signal between the two leaves that swap un-rolled-back while its backup is deleted. |
| CDX-44 | minor | confirmed | scripts/geoip | `vpnctl-geoip-fetch-via-node.sh` opens the live WAL database with `immutable=1`, so committed-but-not-checkpointed servers/SSH settings are invisible. |
| CDX-45 | important | confirmed | admin server page | While `is_deploying`, the server page auto-opens `/deploy/sse`, and that handler (`run_redeploy_when_idle`) queues a *new* full redeploy after the running one; every open tab adds another. |
| CDX-46 | minor | confirmed | dashboard telemetry | Without a fresh snapshot, "active now" falls back to the bucket's `MAX(active_connections_peak)` — a historical peak shown as current. |
| CDX-47 | important | confirmed | protocols/naive | Naive `client_config` sets `tls.utls.enabled = true`; sing-box `protocol/naive/outbound.go` returns `uTLS is not supported on naive outbound`, so any sing-box subscription containing Naive is rejected as a whole. |
| CDX-48 | minor | confirmed-narrow | protocols/ss2022 | The PSK is always minted as 16 bytes, but `2022-blake3-aes-256-gcm` and `2022-blake3-chacha20-poly1305` (both accepted) need 32; changing the method renders unusable configs without an error. |
| CDX-49 | important | confirmed | admin user delivery | The chained sing-box subscription URL/QR is built from the request `Host` (`http://vpnctld/sub/...`) instead of the configured `public_base_url`, so it does not work outside the LAN. |
| CDX-50 | minor | confirmed | admin WG download | `/admin/users/{u}/wireguard/conf/{s}` checks only grant + protocol, not visibility overrides, suppression or `client_detour_via`; a chained target can still be downloaded as a direct config. |
| CDX-51 | important | confirmed | kernel disable | Disabling a kernel only removes the inventory row; deploys iterate the remaining kernels, so the old service (e.g. xray) keeps running with its last config and keeps accepting removed users. |
| CDX-52 | important | confirmed | wizard | The wizard accepts hostnames and enables every sing-box protocol including AWG2/3; the AWG isolation rule then fails with "requires a literal server IP" after the server is registered and installed. |
| CDX-53 | important | confirmed | pending deploy | `server_pending_deploy` ignores `server.reality.set`, `server.naive.set`, `server.vlessws.set`, secret and detour changes; subscriptions already publish the new values while the page shows "applied". |
| CDX-54 | minor | confirmed | fleet kernel update | `update-kernels-all` always ends with `BootstrapEvent::Ok` even when servers failed; the UI shows green and reloads. |
| CDX-55 | important | confirmed | stats ingest | Counter-reset detection uses `unixepoch()` at DB-write time vs node uptime with a 10 s tolerance; a controller clock step or >10 s extra write/collection latency is treated as a sing-box restart and full cumulative counters are re-counted. |
| CDX-56 | minor | confirmed | geoip update | CLI and the systemd job use the same `*.partial` temp names with no cross-process lock; one can rename the other's half-written file into place. |
| CDX-57 | minor | confirmed | /sub rate limit | A token ban writes the full subscription token into `audit_log.target`, which the audit page and CSV export show unredacted. |
| CDX-58 | minor | confirmed | clash poller | The server-wide live row is written only for non-empty snapshots and read without a freshness check; after all connections close, the server card keeps showing the last non-zero count. |
| CDX-59 | minor | confirmed | inventory servers | Duplicate-address detection compares strings; `2001:db8::1` and `2001:0db8:0:0:0:0:0:1` register as two servers for one node. |
| CDX-60 | minor | confirmed-narrow | billing renew | `advance_server_billing_cycle_guarded` reads the tariff before the transaction and guards only on `due_date`; a concurrent tariff edit with the same date mixes old amount/cycle with the new row. |
| CDX-61 | minor | confirmed | currency | `convert_minor` casts the `i128` result with `as i64`; large amounts wrap to negative spend. |
| CDX-62 | minor | confirmed | billing dates | `add_calendar_months` loops forever when the target year is outside chrono's range (e.g. `+262142-12-31`), hanging a runtime thread. |
| CDX-63 | important | confirmed | boosty sync | A rotated refresh token is persisted only after the whole sync finishes; the web "sync" runs inside the 15 s request timeout, so a timeout (or daemon restart) after OAuth rotation loses the new token and later syncs fail auth. |
| CDX-64 | minor | confirmed | alert sink | A failed Telegram send is only logged; the alert stays open, so later probes never re-send it. |
| CDX-65 | minor | confirmed | shutdown | The access-log writer handle is discarded; graceful shutdown does not drain its queue, so already-served `/sub` hits can be lost. |
| CDX-66 | minor | confirmed-narrow | cli migrate | `--overwrite-existing` does `remove_user` (own committed tx) then `add_user`; a failing insert (UUID conflict) leaves the user and grants deleted. |
| CDX-67 | minor | confirmed-narrow | cli migrate | Multi-plan import only checks plans against the existing DB; the second plan skips the just-created user and grants without its `client_uuid`. |
| CDX-68 | important | confirmed-narrow | cli migrate | Existing server secrets are overwritten unconditionally, even without `--overwrite-existing`; a wrong `--server-id` replaces a live node's REALITY keys. |
| CDX-69 | minor | confirmed | cli boosty | `boosty sync --apply` exits 0 when `report.errors` is non-empty. |
| CDX-70 | minor | confirmed | cli server add | `server add` stores IDs that the operation-lock filename check later rejects, so the server can never be deployed. |
| CDX-71 | minor | confirmed | cli registry | `vpnctl registry` prints hard-coded lists (one kernel, two protocols) instead of the built registry. |

Rejected in round 2: "Boosty poll interval change is not picked up" — the
settings form states the interval applies after a daemon restart.

## Summary

71 confirmed findings (30 important, 41 minor; 15 of them confirmed-narrow), 1
rejected, 4 duplicates merged. Suggested first fix wave (small, local, high
impact): CDX-01, 03, 08, 12, 15, 24, 35, 39, 47, 49, 53, plus CDX-26/45 (SSE
start-on-GET) as one design change.

## Fix status

Wave 1 (branch `fix/codex-wave1-20261024`): CDX-01, 03, 08, 12, 15, 24, 26,
35, 39, 45, 47, 49, 53 fixed with regression tests; SSE start tickets are
specified in `docs/specs/sse-start-tickets.md`. Not deployed.

Wave 2 (branch `fix/codex-wave2-20261025`): CDX-02, 05-07, 09, 13, 14, 16-23,
25, 27, 29-34, 36-38, 40-44, 46, 48, 50-52, 54-71 fixed
with regression tests by eight Codex implementers, re-reviewed and integrated
by the lead. Lead changes on top: CDX-51 stops only kernels the operator
disabled on that server (never unrelated node services); the CDX-25 login
throttle evicts the oldest bucket instead of refusing new clients; inventory
transactions use `BEGIN IMMEDIATE`. Not deployed.

Still open (need a design decision or are historical): CDX-04 (one-time
migration double count), CDX-10 (SS2022 server-wide PSK), CDX-11 (legacy
WireGuard index-based addresses), CDX-28 (XFF vs X-Real-IP for logging).

## Round 3 (2026-10-25): contradictions, drift and cleanup

Eight read-only Codex hunters (gpt-6.1-sol) at `ce96d46`, one area each (specs,
repo docs, admin copy, test quality, config surface, client/server protocol
parity, schema vs Rust, cleanup). Every row below was re-checked against the
source by the lead; duplicates across hunters are merged.

| ID | Severity | Area | Finding |
|---|---|---|---|
| R3-01 | important | client detour | sing-box `/sub` picks the entry server's first outbound as `detour` without checking transport; a Naive-only entry is used for Hysteria2/TUIC targets, which need UDP. |
| R3-02 | important | caddy validation | The web protocol toggle accepts `naive` + `vless-ws` on one server; the Caddy renderer rejects that pair, so every deploy fails while `/sub` keeps publishing both. |
| R3-03 | important | stats ingest | A counter for a user missing from `users` (deleted, node not yet redeployed) violates the baseline FK and rolls back the whole tick, so no traffic is recorded for the node. |
| R3-04 | important | backup self-test | `backup-restore.md` promises FK and `integrity_check` verification; `verify_snapshot` runs neither, yet the web self-test reports PASS. |
| R3-05 | important | restore docs | `backup-restore.md` and README say `vpnctl restore <bundle>`; the command takes a decrypted SQLite snapshot (`scripts/vpnctl-restore.sh` unpacks the `.tar.zst.age` bundle). |
| R3-06 | important | admin copy | Kernel and protocol toggles say "inventory only — the node sees it after Deploy"; the handlers queue an automatic redeploy immediately. |
| R3-07 | important | admin copy | The Delivery tip says rotating the sub-token invalidates the shown URL, but that URL is the app-config link keyed by `device_id`, which rotation does not change. |
| R3-08 | important | web-only rule | `vless.sni` and `hysteria2.obfs.password` can be set or rotated only with `vpnctl server secret`; there is no web control. |
| R3-09 | important | README | "Add a new server" row: `/admin/servers/quick-add` is POST-only (wizard is `/admin/servers/new`) and the CLI is `vpnctl bootstrap <id> --address <ip>`, not `<ip> <password>`. |
| R3-10 | important | currency | `currency-exchange.md` says historical Total Spend is never re-converted; `server_spend_and_count` re-converts payments at current rates when the stored snapshot is for another display currency or missing. |
| R3-11 | important | CI | `daemon/tests/subprocess_ssh_e2e.rs` (production SSH transport) is `#[ignore]` and the Docker CI job never runs it. |
| R3-12 | important | test quality | Caddy restart/apply tests use `MockTransport::expect`, which never fails on a missing call; removing the restart/apply exec keeps them green. |
| R3-13 | minor | registry | Daemon and CLI each hand-build the registry (`daemon/src/app/registry.rs`, `cli/src/registry.rs`); AGENTS.md and `architecture.md` promise one registration line. |
| R3-14 | minor | admin copy | Boosty form says the access token is used only when the refresh pair is incomplete; `build_client` prefers a non-empty access token (bearer-first, pinned by a test). |
| R3-15 | minor | admin copy | GeoIP settings say the update "then reloads the DB"; readers load once at start and the runner itself says new DBs load on the next restart. |
| R3-16 | minor | config | CLI honours `VPNCTLD_BACKUP_DIR`; the daemon scheduler, web download and self-test use the fixed default, so CLI and web see different backup sets. |
| R3-17 | minor | audit | `audit_for_server` matches only `target` and `$.server_id`; grant/revoke rows carry `$.server`, so server history misses them. |
| R3-18 | minor | AWG params | The AWG server fills missing obfuscation keys with defaults while clients drop the whole block when any key is missing; a partial legacy set yields mismatched server/client configs. |
| R3-19 | minor | currency docs | Migration 0058 and `currency-exchange.md` describe per-currency `minor_units`; no such column exists and every currency is stored in hundredths. |
| R3-20 | minor | BACKLOG | Stale items: Deploy-All lock retry (now waits up to 300 s), subscription base URL "hard-coded" (now a web setting), v2ray-stats helper "deferred" (wired in `clash_poller`). `abuse-detection.md` still says `user_id` stays NULL. |
| R3-21 | minor | README | Rust 1.85+ (manifest says 1.87, and the code already uses let-chains, which need 1.88); "10 protocols" (12 registered); DPI tiers list (Naive, VLESS-WS, VLESS-XHTTP are Strong); "build SHA changes on every checkout build" (only when `VPNCTL_BUILD_SHA` is set). |
| R3-22 | minor | docs | `PROTOCOL_TESTING.md` lists AnyTLS, Trojan and Naive as not shipped; `commercial-operations.md` describes the old backup script (optional key, best-effort off-site, `zstd -19`). |
| R3-23 | minor | test quality | `spec_privilege_semantics.rs` compares inputs to themselves; `cli admin hash-password` test never calls the command; `resolve_one_accepts_valid_ipv4_chars_only` discards every result. |
| R3-24 | minor | cleanup | Unused: `legacy/shell.rs` topbar/foot/root_class + nav, `set_server_jump_via` (stale `server.jump_via.set` audit), `clash_api::Snapshot::{bytes_per_user, connection_count_for_user}`. |

Found while testing wave 2 (not by a hunter): inventory write transactions
opened with a deferred `BEGIN` read and then write; in WAL mode a concurrent
commit between the two makes SQLite return `SQLITE_BUSY` at once, bypassing
`busy_timeout` (seen as a flaky "database is locked" in an admin smoke test).
Fixed in wave 2: every inventory transaction uses `BEGIN IMMEDIATE`, guarded by
`crates/inventory/tests/spec_write_transactions.rs`.

### Round 3 fix status

Wave 3 (branch `fix/codex-wave3-20261025`): R3-01..24 fixed by eight Codex
implementers, integrated and reviewed by the lead plus four diff-only
reviewers. Lead changes on top: VLESS on any transport (WS/XHTTP included)
counts as a UDP-capable detour entry, only Naive is TCP-only (R3-01); a
payment made in the display currency counts at its paid amount even without a
snapshot, so legacy rows stay exact (R3-10). The AWG fix (R3-18)
changes client output only where the server already applied default params
that the client omitted; complete parameter sets render byte-identically.
Not deployed.

Still open from round 3: the workspace declares `rust-version = "1.87"` but
the code already uses let-chains, which need Rust 1.88. Raising the MSRV
turns on clippy's MSRV-gated lints (`collapsible_if` into let-chains,
`as_chunks`) across untouched code, so it is left for a separate mechanical
change.

Wiring `subprocess_ssh_e2e` into CI (R3-11) showed that the never-run suite had
rotted: the host-key test assumed unhashed `known_hosts` lines (fixed with
`ssh-keygen -F`), and the root round trip cannot start because the
linuxserver image never finishes init for `USER_NAME=root`. CI skips that one
test until it gets an image that allows root login.

## Round 4 (2026-10-25): security, concurrency, scripts, UI flows

Eight read-only Codex hunters at `bd83916`, one area each. The lead
re-checked the high-impact rows against the source (R4-01, 02, 03, 07, 08);
the rest are hunter-verified and re-checked by the implementer before fixing.

| ID | Severity | Area | Finding |
|---|---|---|---|
| R4-01 | important | audit leak | Audit payloads store user UUIDs and VPNRouter device IDs (bearer credentials for `/api/v1/app/config`); `redact_audit_payload` masks only password/private/token/secret keys, so the audit page and CSV expose them. |
| R4-02 | important | AWG leak | On a failed start the AWG apply script runs `awg-quick strip awg0.conf >&2`, which prints `PrivateKey`; the error reaches SSE and the `server.deploy` audit row. |
| R4-03 | important | staging perms | `upload` writes via `base64 -d > path` under the session umask; a staged `config.json.new` with every user secret stays world-readable when `sing-box check` rejects it. |
| R4-04 | important | Boosty | Only `sync_from_inventory` runs in the spawned task; `deploy_flipped_users` is queued after `sync.await` inside the cancellable handler, so a timed-out request flips users without a redeploy. |
| R4-05 | important | Boosty race | The poller applies a precomputed disable after the operator unlinked the user, because `set_user_disabled` does not re-check the Boosty link. |
| R4-06 | important | registration race | Two concurrent quick-adds of one address both pass the pre-transaction duplicate check; two server rows then get separate deploy locks for one node. |
| R4-07 | important | remediation | Health auto-remediation runs `systemctl restart sing-box` without the node operation lock and without re-reading inventory, so it can restart a kernel a concurrent deploy just disabled. |
| R4-08 | important | apply scripts | A failed config snapshot (`cp -a`) does not stop the apply; AWG then deletes the live config on rollback, sing-box/xray restore a partial `.bak`. |
| R4-09 | important | firewall | `ufw allow … || true` hides firewall failures and `open_firewall` errors only warn, so a deploy reports success with the new port closed. |
| R4-10 | important | grants | Revoke commits the grant delete and its audit row separately; a failed audit write hides the pending revoke, and a failed autodeploy is not shown when `pending_deploy` is false. |
| R4-11 | important | wizard | After the first password login the wizard trusts a separate `ssh-keyscan` result for the next password login, instead of the key the first connection accepted. |
| R4-12 | important | wizard | An SSH port of 443 is accepted while the default REALITY inbound also binds 443, so the first deploy fails and the half-registered server blocks a wizard retry. |
| R4-13 | important | fail2ban | The jail port comes from `sshd -T`, not from the port the wizard actually connected on; a sshd started with `-p` gets a jail on the wrong port. |
| R4-14 | important | SSE UI | After a dropped SSE connection the JS re-enables the button; retry starts a second full deploy instead of watching the running one. |
| R4-15 | important | vpn:// | The AmneziaVPN `vpn://` export puts AWG params only in the nested text config; the Android client reads the structured `last_config` fields, so imports lose obfuscation. |
| R4-16 | important | Trojan links | Trojan share links rely on `allowInsecure=1` with a self-signed cert; current Xray clients reject `allowInsecure` (needs a pinned cert hash instead). Needs confirmation against the pinned client versions. |
| R4-17 | important | client docs | `docs/CLIENT_GUIDES.md` tells Linux users to save `/sub` output as a full sing-box/Mihomo config, but it has no inbounds/TUN, so nothing is proxied. |
| R4-18 | minor | SSE UI | `data-reload-after` keeps its timer when another SSE action starts, so the reload cuts the kernel-update log. |
| R4-19 | minor | wizard UI | The wizard marks deploy/apply/probe rows done as soon as the `probe` phase starts, before SSH succeeded. |
| R4-20 | minor | sing-box install | With matching binaries and a stopped service the installer fails `is-active` and rolls back instead of starting it. |
| R4-21 | minor | bulk grant | "Grant all" counts failures but returns a plain redirect, so per-user failures are invisible. |
| R4-22 | minor | traffic limit | A failed limit read renders as "no limit"; saving that form then deletes the real limit. |
| R4-23 | minor | cleanup | Unused inventory methods `upsert_currency_rates`, `delete_currency_rate`, `list_server_kernels` (spec names the unused batch method). |
| R4-24 | minor | cleanup | `scripts/hash-admin-password.sh` duplicates `vpnctl admin hash-password` and needs the `argon2` package. |
| R4-25 | minor | cleanup | `docs/specs/exchange-rate-ingestion.md` is a pre-implementation design (env vars, tables) that the code never implemented, filed among live specs. |
| R4-26 | minor | cleanup | Three copies of the `fresh_keypair` SSH test helper. |

26 findings; R4-04 was reported by two hunters and is merged.

### Round 4 fix status

Wave 4 (branch `fix/codex-wave4-20261025`): R4-01..15, 17..25 fixed by eight
Codex implementers, integrated and reviewed by the lead plus four diff-only
reviewers. Skipped with reasons: R4-16 (no pinned client versions and no
server cert fingerprint in the repo; the limitation is documented in
`docs/CLIENT_GUIDES.md`), R4-26 (no shared test-support location for the three
test crates). Lead changes on top: firewall scripts capture `ufw status` as
its own command so a failing status stops the deploy instead of reading as
"inactive" (review finding); with several accepted host keys the wizard pins
the key the node presents, only if the password login already trusted it.
Not deployed.

## Round 5 (2026-10-25): performance, retention, i18n, CLI, pollers, migrations, startup, specs

Eight read-only Codex hunters at `acb62b7`. The lead spot-checked the
important rows; implementers re-verify each row before fixing.

| ID | Severity | Area | Finding |
|---|---|---|---|
| R5-01 | important | backups | A self-test FAIL (e.g. zero users or servers) sets `prune_ok: false`, but hourly snapshots continue, so nothing is pruned and the disk fills. |
| R5-02 | important | rollups | The daily rollup recomputes only today and yesterday; after downtime longer than a day the missed days stay partial and raw rows are purged. |
| R5-03 | important | i18n | The server delete confirmation page is English-only (key loss, node untouched, Telegram relay warnings). |
| R5-04 | important | CLI | `vpnctl user disable` only flips the flag (help says it revokes node access); the web action also redeploys. |
| R5-05 | important | remediation | Auto-remediation runs only when the alert row is first inserted; if the node lock was busy then, it never retries while the condition persists. |
| R5-06 | important | assurance | The external runner timeout kills only the child; `reader.join()` can block forever on inherited stdout and stall the poller. |
| R5-07 | important | Boosty | The 600 s cross-process sync lease is never renewed; a long sync can overlap with another process's sync. |
| R5-08 | important | clock | Health samples are ordered by wall-clock `ts`; after a backwards clock step an old healthy sample stays "latest" and hides failures. |
| R5-09 | important | migrations | Migration 0013 creates a unique index over open alerts without removing pre-existing duplicates, so very old snapshots fail to open. |
| R5-10 | important | restore | `restore` run as root leaves the DB owned by root with 0600; the service user cannot open it. |
| R5-11 | important | restore UI | The in-app DR instructions say `vpnctl restore /path/to/inv.db` without `--db`, which restores into the CLI's XDG default, not `/var/lib/vpnctl/inv.db`. |
| R5-12 | important | config | `VPNCTLD_TRUSTED_PROXIES` silently drops unparsable entries (e.g. CIDR); all proxied clients then share the proxy IP and one rate-limit ban. |
| R5-13 | important | startup | An assets dir without `admin.js`/`admin.css` is accepted; every JS-driven action (wizard, deploy) silently does nothing. |
| R5-14 | important | specs | `backup-restore.md` merges the daemon's hourly SQLite snapshots with the daily encrypted DR bundle (different tool, schedule, retention). |
| R5-15 | minor | perf | `/api/v1/app/config` issues hundreds of sequential queries per refresh. |
| R5-16 | minor | perf | Every user-detail tab loads other users' credentials and prepares delivery data it does not show. |
| R5-17 | minor | perf | IP-to-server lookup scans the subscription access log, once inside a write transaction. |
| R5-18 | minor | perf | Latest fleet health is computed over the whole health history. |
| R5-19 | minor | retention | The traffic window "all" shows only the last 32 days. |
| R5-20 | minor | retention | Session cleanup deletes sessions that are still active. |
| R5-21 | minor | retention | After history purge a used account shows "never" as last activity. |
| R5-22 | minor | retention | Hourly cleanup scans several telemetry tables fully. |
| R5-23 | minor | i18n | Restore self-test warning reasons are not translated. |
| R5-24 | minor | i18n | A Telegram check error refers to a field label that does not exist in RU. |
| R5-25 | minor | CLI | `server secret` accepts an invalid port that renders as 443. |
| R5-26 | minor | CLI | `update-kernels --output json` prints text into stdout. |
| R5-27 | minor | CLI | Subscription generation errors exit 0. |
| R5-28 | minor | CLI | CLI accepts user IDs that break the AWG config. |
| R5-29 | minor | CLI | CLI TOFU fingerprint save writes no audit row. |
| R5-30 | minor | startup | The deploy key is reported ready without its public half. |
| R5-31 | minor | specs | S5 specs require incompatible server roles. |
| R5-32 | minor | specs | The wizard contract still forbids several accepted host keys, which wave 4 allows. |
| R5-33 | minor | specs | The running exchange-rate poller is still described as future work. |
| R5-34 | minor | specs | Finance specs give different rounding rules. |
| R5-35 | minor | README | README still promises the old Boosty grant behaviour. |

### Round 5 fix status

Wave 5 (branch `fix/codex-wave5-20261025`): R5-01..16, 18..35 fixed by eight
Codex implementers, integrated and reviewed by the lead plus four diff-only
reviewers. R5-17 skipped: the address lookups already read `servers`, not the
access log, and the duplicate check must stay inside the registration
transaction (a test now pins both). Lead changes on top: the node-health
sequence migration is 0064 (two groups both picked 0062); the hourly purge
rolls up only the days it is about to delete, and missed retained days are
caught up once at daemon start; a fresh restore takes the owner of the DB directory; the CLI TOFU
fingerprint save and its audit row share one transaction; the Boosty lease
renewal polls the sync before its timer so a slow renewal cannot starve it;
the "all" traffic window counts cells from the truncated oldest bucket.
Kept by design: `vpnctl user disable` tells the operator which servers still
need `vpnctl deploy` rather than deploying itself (the web action redeploys).
Not deployed. Before deploying, check that `VPNCTLD_TRUSTED_PROXIES` in
`/etc/vpnctl/vpnctld.env` parses (IPs or CIDRs): the daemon now refuses to
start on a bad entry instead of silently ignoring it.

## Round 6 (2026-10-25): security and disputed decisions

Eight read-only Codex hunters at `f7745e8`, focused on vulnerabilities by
attacker position and on the open or declined decisions above. The lead
confirmed R6-01, 02, 03, 05, 06, 08, 19 in the source; implementers re-verify
each row before fixing.

| ID | Severity | Area | Finding |
|---|---|---|---|
| R6-01 | important | node isolation | Proxy inbounds (VLESS etc.) route to `direct` with no private/loopback rule, so any VPN user can reach the node's unauthenticated Clash API (`127.0.0.1:9090`, all users' connections) and the stats API. Only AWG endpoints were isolated. |
| R6-02 | important | SSH | The subprocess transport buffers stdout/stderr with unbounded `read_to_end`; a compromised node can exhaust the daemon's memory through a routine poll. |
| R6-03 | important | migrate | `vpnctl migrate from-bash` connects without any host-key check and imports whatever users the peer returns. |
| R6-04 | minor | CLI bootstrap | CDX-24 was fixed only in the web wizard; CLI bootstrap still glues the deploy key onto a last line without LF. |
| R6-05 | important | auth | CDX-25 incomplete: the Argon2 permit is dropped when the request is cancelled while the blocking verification keeps running, so the cap of four can be exceeded. |
| R6-06 | important | auth | The session signing key is `SHA256(prefix ‖ PHC)`: whoever reads the password hash can mint admin sessions without the password. |
| R6-07 | minor | auth | The session cookie never carries `Secure`, even when the admin UI is served over HTTPS by a trusted proxy. |
| R6-08 | important | public API | `/api/v1/stats/sub-access` is public: anyone can trigger month-long aggregations over the access log and read service-wide activity. |
| R6-09 | minor | HTTP | No header read timeout: unfinished request headers hold connections indefinitely. |
| R6-10 | important | deploy | Disabling the last protocol of a non-sing-box kernel leaves its old listener (and revoked users) running; deploy skips the kernel. |
| R6-11 | important | node files | Root writes the Xray staging file in a directory the `xray` user can write, following a symlink planted between the SSH calls. |
| R6-12 | important | inventory | A DB first created by the CLI under umask 022 is world-readable. |
| R6-13 | important | restore | `vpnctl-restore.sh` reuses a predictable, possibly pre-created `/tmp` directory. |
| R6-14 | important | GeoIP | The fetch-via-node script writes and decompresses the node's response with no size cap and leaves partial files. |
| R6-15 | important | assurance | R5-06 incomplete: the runner starts the engine in a new session, so the daemon's process-group kill misses it and its credential-bearing temp dir stays. |
| R6-16 | minor | audit | Saving unchanged Naive / VLESS-WS settings writes an audit row and marks the server pending. |
| R6-17 | important | CLI | `user disable` commits the flag before its audit row; an interrupted run hides the pending deploy forever. |
| R6-18 | minor | WireGuard | CLI `user add` does not generate a WG key pair by default and the legacy download serves a template with a paste-your-key placeholder. |
| R6-19 | important | delivery | CDX-49 incomplete: the recommended Flow A URL is still `http://{Host}`, not the configured public base URL. |
| R6-20 | minor | Telegram | The bot token is interpolated into a curl config without an alphabet check (admin-only injection of curl directives). |
| R6-21 | minor | Telegram | A digest over 4096 characters is rejected whole and the manual button still reports success. |

Disputed decisions, evaluated and left as they are (owner decisions):

- Empty subscription falls back to `direct` / `DIRECT` (spec-pinned); a
  fail-closed `block`/`REJECT` would change the byte contract for existing clients.
- Boosty: a roster with zero paid members suppresses all disables (anomaly
  guard, test-pinned); a real "last payer downgraded" case stays enabled.
- CDX-10 (shared SS2022 PSK): per-user revocation needs multi-user SS2022 and
  re-issuing every profile. CDX-11 (WG addresses by index): needs persisted
  address assignment. CDX-04: the applied migration stays unchanged.
- CDX-28: logging keeps the leftmost XFF; security decisions use X-Real-IP.
- R4-16: Trojan keeps `allowInsecure` until certificate pinning is verified in
  the supported clients.
- MSRV: the manifest says 1.87 while the code uses let-chains (1.88); raising
  it is a separate mechanical clippy change.
- R1-2 counter-reset heuristic, CDX-64 three Telegram attempts, R5-04
  inventory-only CLI disable: kept; limits are documented in the specs.

### Round 6 fix status

Hygiene pass plus wave 6 (branch `hygiene/pass-20261025`): R6-01..21 fixed by
eight Codex implementers, integrated and reviewed by the lead plus four
diff-only reviewers. R6-01 was reproduced and verified with the pinned
binaries (sing-box 1.14.2, Xray 26.3.27): through a VLESS tunnel the old
configs reached `127.0.0.1:9090`, the new ones reject loopback, `localhost`
and CGNAT while public sites still work. Lead changes on top: hostname servers
keep range isolation instead of failing to render (only AWG still needs a
literal IP); an explicit deny list (`USER_TRAFFIC_DENIED_CIDRS`) covers ranges
sing-box's `ip_is_private` misses (CGNAT, used by Tailscale); Xray resolves
with `ForceIPv4v6` so nodes without IPv6 egress keep working; existing
world-readable inventory files are restricted to 0600 on open; a migrate pin
is saved only when the stored address and port match; the restore script
accepts relative paths; Flow A keeps the `/sub/<token>` path on the public
base. Upgrade note: existing admin session cookies are invalidated once
(R6-06); Xray configs become `root:xray 0640` in a root-owned directory.
Script and docs regression tests (`scripts/tests`) now run in CI.
