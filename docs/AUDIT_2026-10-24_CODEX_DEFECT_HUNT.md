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
| R3-21 | minor | README | Rust 1.85+ (manifest says 1.87); "10 protocols" (12 registered); DPI tiers list (Naive, VLESS-WS, VLESS-XHTTP are Strong); "build SHA changes on every checkout build" (only when `VPNCTL_BUILD_SHA` is set). |
| R3-22 | minor | docs | `PROTOCOL_TESTING.md` lists AnyTLS, Trojan and Naive as not shipped; `commercial-operations.md` describes the old backup script (optional key, best-effort off-site, `zstd -19`). |
| R3-23 | minor | test quality | `spec_privilege_semantics.rs` compares inputs to themselves; `cli admin hash-password` test never calls the command; `resolve_one_accepts_valid_ipv4_chars_only` discards every result. |
| R3-24 | minor | cleanup | Unused: `legacy/shell.rs` topbar/foot/root_class + nav, `set_server_jump_via` (stale `server.jump_via.set` audit), `clash_api::Snapshot::{bytes_per_user, connection_count_for_user}`. |

Found while testing wave 2 (not by a hunter): inventory write transactions
opened with a deferred `BEGIN` read and then write; in WAL mode a concurrent
commit between the two makes SQLite return `SQLITE_BUSY` at once, bypassing
`busy_timeout` (seen as a flaky "database is locked" in an admin smoke test).
Fixed in wave 2: every inventory transaction uses `BEGIN IMMEDIATE`, guarded by
`crates/inventory/tests/spec_write_transactions.rs`.
