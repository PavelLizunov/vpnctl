# vpnctl codebase inventory — 2026-05-17 (overnight burst)

Generated as part of the overnight burst per Pavel: «проанализировал
всю кодовую база, расписал какой элемент сколько LOC занимает,
расписал каждую фичу и ее флов, записал артефакты».

Snapshot commit: `aef1c6b` (HEAD after the burst). Workspace tests
green: **149 admin_smoke + 102 vpnctld unit + 38 inventory spec + ~50
protocol/ssh/wizard unit suites = ~500 tests** across the workspace.

## Lines of code (production + tests)

### By crate

| Path | LOC | Files | Role |
|---|---|---|---|
| `crates/core` | 511 | 1 | Types + traits + `Registry` (THE architectural seam — every kernel and protocol plugs in here). |
| `crates/crypto` | 192 | 1 | UUID v4, x25519 keypair (REALITY + WG), short-id, password gen. |
| `crates/ssh` | 1 103 | 6 | `SshTransport` trait + `russh` impl + `MockTransport` for tests. |
| `crates/protocols` | 4 139 | 14 | 7 protocols × ~600 LOC each + helpers (`vless+reality`, `tuic-v5`, `hysteria2`, `shadowsocks-2022`, `wireguard`, `anytls`, `trojan`). |
| `crates/kernels` | 824 | 3 | `sing-box` kernel (install + render + apply); `amneziawg` kernel. |
| `crates/hosters` | 67 | 1 | DigitalOcean / Cloudzy / Generic notes (mostly metadata). |
| `crates/inventory` | 7 425 | 14 | SQLite store + 11 migrations + audit log + sub-access log + traffic stats + node-health + admin-alerts + bash migration planner + backup/restore. |
| `cli` | 2 411 | 15 | `vpnctl` binary: 14 subcommands (server, user, grant, revoke, deploy, status, sub, bootstrap, render, backup, restore, migrate, uuid, registry). |
| `daemon` | 20 180 | 24 | `vpnctld` binary: admin UI + /sub/<token> + /api/v1 + 4 background pollers (retention, clash-api, node-probe, health-monitor, backup-scheduler, rate-limit-cleanup). |
| **Total** | **36 852** | 99 | |

### By daemon module (hottest)

| File | LOC | Purpose |
|---|---|---|
| `daemon/src/handlers/admin.rs` | 6 361 | Every `/admin/*` GET/POST + shell + nav + 30+ helper functions for sections. |
| `daemon/src/wizard_bootstrap.rs` | 1 073 | Phase E 9-phase SSE-streamed add-server pipeline (push key → harden SSH → install fail2ban → install sing-box → render config → restart → prove live). |
| `daemon/src/app.rs` | 797 | Router + AppState + 5 background-task spawners + admin-router wiring. |
| `daemon/src/clash_poller.rs` | 580 | Track-3 — diff engine + per-server poller for sing-box clash-api. |
| `daemon/src/health_monitor.rs` | 540 | **Phase G** — diff_rows pure function (8 detection rules + hysteresis) + scan_once + spawn loop. |
| `daemon/src/node_probe.rs` | 479 | Phase H chunk 1 — single-script SSH probe + tagged-line parser. |
| `daemon/src/rate_limit.rs` | 451 | Track-2 — token bucket per (IP, sub-token) + persistent bans + cleanup. |
| `daemon/src/clash_api.rs` | 394 | Clash-api types + parser + `SshClashClient`. |
| `daemon/src/ssh_subprocess.rs` | 386 | **Path C** — wraps `/usr/bin/ssh` via `std::process::Command` + `spawn_blocking` (avoids glibc 2.38 dep that crash-loops vpnctld on bookworm). |
| `daemon/src/node_probe_poller.rs` | 254 | **Phase H chunk 4** — periodic probe-and-INSERT runtime. |

### Tests

| Suite | LOC | Tests |
|---|---|---|
| `daemon/tests/admin_smoke.rs` | ~6 100 | 149 (DOM + routing + copy contracts + visual hooks) |
| `daemon/tests/sub_endpoint.rs` | ~250 | 6 (token resolution + rate-limit + persistent ban) |
| `daemon/tests/sub_security.rs` | ~280 | 8 (no-token-leak, fingerprint-leak, missing-grant edge) |
| `crates/inventory/tests/spec_*.rs` | 3 137 | 38 (split across spec_audit_paginated, spec_access_buckets, spec_inventory, spec_migration, spec_node_health, spec_sub_access, spec_sub_rate_bans, spec_vpn_stats) |
| `crates/protocols/tests/spec_*.rs` | 2 157 | 84 (per-protocol render + share_link + byte-equality) |
| `crates/ssh/tests/` | 558 | 12 (russh transport happy + error paths) |
| Total | **~12 500** | **~500** |

Tests-to-production ratio: **~34%** (~12.5K test LOC / 36.9K total). Higher than typical for Rust projects — driven by the methodology rule "every public API gets a test-writer-agent pass + every commit gets a review-agent pass".

## Artefact inventory

### Binaries (2)

| Binary | Crate | Build target | Purpose |
|---|---|---|---|
| `vpnctl` | `cli/` | host (cargo build --release) | Operator CLI; reads `/var/lib/vpnctl/inv.db` (or `--db`). |
| `vpnctld` | `daemon/` | `x86_64-unknown-linux-gnu.2.36` via `cargo zigbuild` | Admin HTTP daemon + /sub/<token>; lives at `/opt/vpnctl/vpnctld` on 192.168.0.236, root:root 0755. Build via cargo-zigbuild to avoid glibc 2.38 dep (see CLAUDE.md). |

### CLI subcommands (14)

| Subcommand | Purpose |
|---|---|
| `vpnctl uuid` | Smoke test — emit a fresh UUID v4. |
| `vpnctl registry` | List all registered kernels + protocols (text or JSON). |
| `vpnctl server {add,list,show,remove,secret,set-fingerprint}` | Server CRUD + per-server secret + TOFU pin (NEW this burst). |
| `vpnctl user {add,list,show,remove,regen-tuic,regen-sub-token,set-wg,traffic-limit}` | User CRUD + secret rotations + traffic-limit. |
| `vpnctl grant <user> <server>` | Grant access. |
| `vpnctl revoke <user> <server>` | Revoke access. |
| `vpnctl deploy <server>` | Full SSH-push: install kernel + mint missing secrets + render config + restart. Idempotent. |
| `vpnctl status <server>` | Query kernel runtime status over SSH. |
| `vpnctl sub <user> [--qr]` | Print all share links for the user; optional ASCII QR. |
| `vpnctl bootstrap` | Provision a new node from `root:password` (push key, record fingerprint, add to inventory). |
| `vpnctl render <server>` | Render kernel-native config to stdout (offline review). |
| `vpnctl backup {snapshot,list,prune}` | `inv.db` snapshot operations. |
| `vpnctl restore <snapshot>` | Restore inventory from snapshot file. |
| `vpnctl migrate from-bash <dir>` | Import bash project state. **NEW this burst:** `--i-really-mean-overwrite-address` gate. |

### Admin web endpoints (26)

| Method | Path | Handler | Purpose |
|---|---|---|---|
| GET | `/admin/` | `dashboard` | Metrics + alerts tile + heavy-users heatmap + limit alerts + audit timeline. |
| GET | `/admin/monitoring` | `monitoring` | Sparklines + KPIs over `/api/v1/stats/sub-access`. |
| GET | `/admin/servers` | `servers` | List + quick-add form. |
| POST | `/admin/servers` | `server_quick_add` | One-field server add. |
| GET | `/admin/servers/new` | `wizard_new` | Phase E step 1 form (IP + root pw). |
| POST | `/admin/servers/new` | `wizard_new_submit` | Step 1 validate + session cookie. |
| GET | `/admin/servers/new/step2` | `wizard_step2_stub` | Step 2 EventSource attach page. |
| GET | `/admin/servers/new/sse` | `wizard_step2_sse` | Step 2 SSE stream of bootstrap pipeline. |
| GET | `/admin/servers/{id}` | `server_detail` | Detail + drift + protocols + kernels + grants + **fingerprint section (NEW)**. |
| POST | `/admin/servers/{id}/deploy` | `server_deploy` | One-click full deploy. |
| POST | `/admin/servers/{id}/protocol/{pid}` | `server_protocol_set` | Toggle protocol. |
| POST | `/admin/servers/{id}/kernel/{kid}` | `server_kernel_set` | Toggle kernel. |
| POST | `/admin/servers/{id}/set-fingerprint` | `server_set_fingerprint` | **NEW** — auto-detect via ssh-keyscan OR manual paste. |
| POST | `/admin/servers/{id}/grants/{uid}` | `server_grant_user` | Grant from server side. |
| POST | `/admin/servers/{id}/grants/{uid}/revoke` | `server_revoke_user` | Revoke from server side. |
| GET | `/admin/users` | `users` | List + create form. |
| POST | `/admin/users` | `user_create` | Mint UUID + WG keypair + tuic_password + sub_token. |
| GET | `/admin/users/{id}` | `user_detail` | Full per-user view: share links + WG + traffic + UA clusters + sub-access log. |
| POST | `/admin/users/{id}/sub-token/regenerate` | `user_regen_sub_token` | Rotate sub_token. |
| POST | `/admin/users/{id}/wireguard/regenerate` | `user_regen_wireguard` | New WG keypair. |
| GET | `/admin/users/{id}/wireguard/conf/{server_id}` | `user_wireguard_conf_download` | `.conf` attachment. |
| POST | `/admin/users/{id}/traffic-limit` | `user_traffic_limit` | Set/clear per-user cap. |
| POST | `/admin/users/{id}/grants/{server_id}` | `user_grant_server` | Grant from user side. |
| POST | `/admin/users/{id}/grants/{server_id}/revoke` | `user_revoke_server` | Revoke from user side. |
| GET | `/admin/users/{id}/delete-confirm` | `user_delete_confirm` | "Type the id to confirm" gate. |
| POST | `/admin/users/{id}/delete` | `user_delete` | After confirm — CASCADE through grants. |
| GET | `/admin/audit[.csv]` | `audit` / `audit_csv` | Phase D — paginated + filtered + CSV export. |
| GET | `/admin/alerts` | `alerts` | **NEW Phase G** — infra alerts feed (`?show=all` includes acked). |
| POST | `/admin/alerts/{id}/ack` | `alert_ack` | **NEW Phase G** — idempotent ack. |
| GET | `/admin/settings` | `settings` | Tweaks (theme/accent) + deploy key view + backups. |
| POST | `/admin/backup/snapshot` | `backup_snapshot_now` | Manual snapshot trigger. |
| GET | `/admin/backup/download/{name}` | `backup_download` | Off-site `.bak` download. |
| POST | `/admin/tweak/{kind}` | `set_tweak` | Cookie set for theme/accent. |
| GET | `/api/v1/health` | `health::health` | Liveness JSON. |
| GET | `/api/v1/stats/sub-access` | `stats::sub_access_buckets` | Phase F sparkline data. |
| GET | `/sub/{token}` | `sub::sub` | Subscription URL (rate-limited, token-resolves to user, JSON envelope). |
| GET | `/admin/assets/*` | static | admin.css + favicon.svg. |

26 unique paths (+ trailing-slash duplicates for axum 0.8 exact-match).

### Database migrations (11)

| # | File | Purpose |
|---|---|---|
| 0001 | `init.sql` | servers + users + grants + server_secrets + audit_log. |
| 0002 | `sub_token.sql` | Adds `users.sub_token UNIQUE`. |
| 0003 | `sub_access_log.sql` | Track-1 abuse-signal log. |
| 0004 | `sub_access_keep_after_user_delete.sql` | SET NULL on user delete (preserves audit). |
| 0005 | `sub_rate_bans.sql` | Track-2 persistent rate-limit bans. |
| 0006 | `vpn_connection_stats.sql` | Track-3 clash-api deltas. |
| 0007 | `node_health.sql` | Phase H chunk 2 node telemetry snapshots. |
| 0008 | `users_wireguard_private.sql` | Server-generated WG keypair storage. |
| 0009 | `server_kernels.sql` | Multi-kernel support (was scalar). |
| 0010 | `user_traffic_limits.sql` | D.6c per-user cap + alert threshold. |
| 0011 | `admin_alerts.sql` | **NEW Phase G** — operator-facing alerts + partial index. |

### Background tasks (6, all spawned by `app::build`)

| Task | Cadence | What it does |
|---|---|---|
| `spawn_retention_purger` | 1h | Deletes >30d rows in `sub_access_log` + `vpn_connection_stats` + `node_health` + ACKED `admin_alerts`. |
| `spawn_rate_limit_cleanup` | 10 min | Sweeps idle rate-limit buckets + expired persistent bans. |
| `spawn_clash_poller` | 5 min (`VPNCTLD_POLL_INTERVAL_SECS`) | SSH-curls clash-api on each sing-box node → DiffEngine → `record_vpn_stats`. |
| `spawn_node_probe_poller` | 10 min (`VPNCTLD_NODE_PROBE_INTERVAL_SECS`) | **NEW** SSH-execs the probe script → INSERT into `node_health`. |
| `spawn_health_monitor` | 10 min (`VPNCTLD_HEALTH_MONITOR_INTERVAL_SECS`) | **NEW** Diffs the two newest `node_health` rows per server → INSERT `admin_alerts` + audit. |
| `spawn_backup_scheduler` | 1h | `VACUUM INTO` snapshot + retention prune (24h / 30d / 12mo). |

### Environment variables (operator knobs)

| Var | Default | Effect |
|---|---|---|
| `VPNCTL_DB` | `/var/lib/vpnctl/inv.db` | Inventory file path. |
| `VPNCTLD_ADMIN_USER` | `slovn` | Basic-auth username. |
| `VPNCTLD_ADMIN_PASSWORD` | (required) | Basic-auth password — `/etc/vpnctl/vpnctld.env`. |
| `VPNCTLD_BIND` | `0.0.0.0:18402` | HTTP listener. |
| `VPNCTLD_DEPLOY_KEY` | `/var/lib/vpnctl/.ssh/id_ed25519` | SSH key for poller + deploy. |
| `VPNCTLD_POLL_INTERVAL_SECS` | 300 | Clash-api poll interval. |
| `VPNCTLD_NODE_PROBE_INTERVAL_SECS` | 600 | **NEW** Node-probe interval. |
| `VPNCTLD_HEALTH_MONITOR_INTERVAL_SECS` | 600 | **NEW** Phase G scan interval. |
| `VPNCTLD_NOTIFY_WEBHOOK_URL` | unset | **NEW** (stub'd, Phase G chunk 3): when set, alerts also POST JSON to this URL. |

### Files installed on `192.168.0.236`

| Path | Owner | Perm | Purpose |
|---|---|---|---|
| `/opt/vpnctl/vpnctld` | root:root | 0755 | Binary. |
| `/opt/vpnctl/vpnctld.prev` | root:root | 0755 | **NEW** auto-saved previous binary on deploy (rollback hook). |
| `/opt/vpnctl/assets/admin.css` | root:root | 0644 | UI stylesheet. |
| `/opt/vpnctl/assets/favicon.svg` | root:root | 0644 | Tab icon. |
| `/var/lib/vpnctl/inv.db` | user:user | 0640 | SQLite inventory. |
| `/var/lib/vpnctl/inv.db-wal` | user:user | 0640 | WAL sidecar. |
| `/var/lib/vpnctl/backups/inv.db.<ts>.bak` | user:user | 0600 | Hourly snapshots. |
| `/var/lib/vpnctl/.ssh/id_ed25519` | user:user | 0600 | Deploy key (auto-gen if absent). |
| `/etc/vpnctl/vpnctld.env` | root:user | 0640 | Env file (admin pw + tunables). |
| `/etc/systemd/system/vpnctld.service` | root:root | 0644 | Systemd unit. |
| `/etc/iptables/rules.v4` | root:root | 0640 | Persistent firewall (tcp/18402 from LAN). |

## Features and flows

### Phase A/B — editorial shell + dashboard (shipped early)

**Flow:** `GET /admin/` → `dashboard` handler → reads `count_servers` / `count_users` / `count_grants` / `recent_audit(20)` / `top_users_by_traffic(24h, 5)` / `users_traffic_vs_limit()` / `unacked_alert_count` (NEW) → renders 4-tile metric row + alerts tile (Phase G, conditional) + limit alerts + heavy-users heatmap + audit timeline. Theme + accent stored in cookies via `/admin/tweak/{kind}`.

**Code:** `daemon/src/handlers/admin.rs:248` (`shell`), `:352` (`dashboard_metrics`), `:513` (`dashboard`).

### Phase C-1/2/3 — users CRUD + UX (shipped early)

**Flow:** `GET /admin/users` → list of all users with grant counts + ASCII bar; `POST /admin/users` mints ALL secrets (UUID + tuic_password + WG keypair + sub_token) on one-button click; `GET /admin/users/{id}` shows share links (with QR for VLESS/TUIC, `.conf` for WG, `vpn://` for AmneziaVPN), traffic stats, UA clusters, sub-access log; `POST /admin/users/{id}/delete-confirm` requires "type the exact id" double-submit before CASCADE.

**Code:** `daemon/src/handlers/admin.rs:1085` (`user_detail`), `:3855` (`user_create`).

### Track-1 — sub-access log (shipped)

**Flow:** Every `GET /sub/<token>` request: resolve token → user → write `(user_id, ip, ua, ts)` to `sub_access_log` via mpsc-bounded writer task (no per-request task spawn — prevents OOM by abusive token holder). UI surfaces last 20 hits per user on user-detail; aggregated by hour on `/admin/monitoring`; abuse signal "shared URL" when >2 distinct /16s per UA in 1h window.

**Code:** `daemon/src/access_log.rs` (mpsc + writer), `daemon/src/handlers/sub.rs:160` (call site).

### Track-1.1 — retention scheduler (shipped early, status corrected this burst)

**Flow:** Background task in `app::build`: every hour calls `purge_sub_access_older_than(30)` + `purge_vpn_stats_older_than(30)` + `purge_node_health_older_than(30)` (NEW) + `purge_acked_alerts_older_than(30)` (NEW). UNACKED admin_alerts are never auto-purged.

**Code:** `daemon/src/app.rs:256` (`spawn_retention_purger`).

### Track-2 — rate-limit /sub/<token> (shipped)

**Flow:** `RateLimiter` is a token-bucket per (IP, token): 5 burst, 1 token / 30s refill. On every `/sub/<token>` request, in order: check persistent IP ban → check IP bucket → check persistent token ban → check token bucket. After K=5 consecutive 429s on the same key, INSERT a `sub_rate_bans` row (5min ban). Cleanup task sweeps expired bans + idle buckets every 10 min.

**Code:** `daemon/src/rate_limit.rs`, `daemon/src/handlers/sub.rs:78` (gate).

### C-4 — backup + restore (shipped)

**Flow:** Hourly scheduler calls `snapshot_to(inv, /var/lib/vpnctl/backups/inv.db.<ts>.bak)` (SQLite `VACUUM INTO` — atomic + WAL-aware) + `prune_snapshots` with `Retention {keep_hourly: 24, keep_daily: 30, keep_monthly: 12}`. Settings page lists snapshots + "snapshot now" button + per-file download anchor for operator off-site (USB / Forgejo / cloud). Restore is CLI-only (`vpnctl restore <file>`) because the daemon can't replace its own open DB.

**Code:** `crates/inventory/src/backup.rs`, `daemon/src/app.rs:330` (scheduler).

### C-5 — migrate from bash (shipped + split-identity policy this morning)

**Flow:** `vpnctl migrate from-bash <inventory-dir>`: for each `<IP>.env` file → SSH (read-only) into the bash server → pull `/etc/sing-box/config.json` + `keys.env` → `build_migration_plan` (pure) → print plan → if `--apply`: insert servers/users/grants preserving UUIDs and TUIC passwords. New `--overwrite-existing` for replacing stale test users; **NEW this burst** `--i-really-mean-overwrite-address` for the L7 destructive-op gate (the vps-is-01 ↔ 104 recovery).

**Code:** `crates/inventory/src/migrate.rs` (planner), `cli/src/cmd/migrate.rs` (orchestrator).

### Phase E — add-server wizard (shipped 4477199)

**Flow:** `GET /admin/servers/new` → step-1 form (IP + root password); on submit, validate + stash in `WizardStore` keyed by HttpOnly+SameSite=Strict cookie + redirect to step-2 stub; step-2 page attaches an `EventSource` to `/admin/servers/new/sse?session=...`; the SSE handler consumes the session and streams the 9-phase pipeline (push pubkey → create non-root user → disable password auth → harden SSH → install fail2ban → install sing-box → render config → restart → prove live). Each phase emits a `step` SSE event with progress; final event is `done` with the new server's id.

**Code:** `daemon/src/wizard.rs` (store), `daemon/src/wizard_bootstrap.rs` (pipeline), `daemon/src/handlers/admin.rs::wizard_*`.

### Track-3 — clash-api per-user real-time stats (shipped)

**Flow:** Kernel render emits `experimental.clash_api: {external_controller: "127.0.0.1:9090"}`. Daemon poller every 5min SSH-curls `http://127.0.0.1:9090/connections` on each sing-box node → parses connections → `DiffEngine` computes per-user upload/download deltas (restart detection: if new total < prior, treat new as delta from zero) → `record_vpn_stats(server_id, &[VpnStatsDelta])`. UI surfaces per-server breakdown on user-detail + 24h heatmap on dashboard.

**Code:** `daemon/src/clash_api.rs` (client), `daemon/src/clash_poller.rs` (diff + poller).

### Phase D — audit timeline UI (shipped)

**Flow:** `GET /admin/audit?actor=&action=&page=` → `recent_audit_paginated` with LIKE-escaped action prefix + paginated 50/page; sticky-date section headers (Today / Yesterday / `<YYYY-MM-DD>`); `GET /admin/audit.csv?...` exports same filter as CSV with RFC 4180 escaping. Cap 10000 rows for the CSV path.

**Code:** `daemon/src/handlers/admin.rs:4181` (HTML), `:4399` (CSV).

### Phase F — monitoring sparklines (shipped)

**Flow:** `GET /admin/monitoring` reads `sub_access_buckets(since_hours, bucket_size)` from inventory → 4 KPI tiles (hits / distinct IPs / distinct users / peak IP-of-the-day) + 3 inline SVG sparklines (hits, distinct IPs, distinct users over last 24h with hourly buckets + gap-fill). Standalone JSON endpoint `/api/v1/stats/sub-access` returns the same data for external dashboards (Grafana etc).

**Code:** `daemon/src/handlers/admin.rs::monitoring` + `daemon/src/handlers/stats.rs`.

### Track-4 — UA fingerprint (shipped)

**Flow:** `ua_clusters_for_user(uid, since_hours)` groups sub_access rows by User-Agent + counts distinct IPs + distinct /16s. UI table on user-detail sorted by hits DESC with verdict column: "likely shared URL" if >2 distinct /16s in 1h window, "likely roaming" if many IPs in same /16, "—" otherwise.

**Code:** `daemon/src/handlers/admin.rs:2133-2275`, `crates/inventory/src/sqlite.rs::ua_clusters_for_user`.

### Phase H chunks 1-3 — node telemetry (shipped previously)

**Flow:** chunk 1: `node_probe::PROBE_SCRIPT` — single bash script over SSH emitting tagged lines (`SVC sing-box active`, `DISK / 9876 20480`, etc) with `PROBE_OK` sentinel. chunk 2: `record_node_health` stores it. chunk 3: `/admin/servers/{id}` reads `latest_node_health` for hero KPIs + 24h history + DECLARED vs OBSERVED port-drift banner. Until this burst, chunk 4 (the poller) was missing — table got zero rows.

### Phase H chunk 4 — node_probe poller (NEW this burst)

**Flow:** `spawn_node_probe_poller(inv)` in `app::build`: every 10min (configurable), for each sing-box server in inventory, run the probe via `SubprocessSshTransport` + `SshProbeClient::snapshot` + serialize the BTreeSet of listening ports to JSON + `record_node_health(...)`. Per-server failures isolated; missing SSH key logs at info and skips (matches `clash_poller` UX). Existing retention purger extended to also drop >30d node_health rows.

**Code:** `daemon/src/node_probe_poller.rs` (254 LOC), wired in `daemon/src/app.rs:113`.

### Phase G — infra alerts (NEW this burst)

**Flow:** `spawn_health_monitor(inv)` on the same 10min cadence as the probe. For each sing-box server: `recent_node_health_for_server(id, 24h)` → take the two newest rows → `diff_rows(prev, cur)` → for each `AlertEvent`: `insert_alert(kind, server_id, severity, summary, payload)` + mirror into `audit_log` as `alert.fire`. Detection rules: sing-box up/down (critical/info), fail2ban up/down (warning/info), disk_pct >=90 with 5pp hysteresis at 85, mem_used_pct >=95 with hysteresis at 90, sing-box log >500 MiB (Pavel's earlier disk-fill concern).

UI: `/admin/alerts` feed (default unacked, `?show=all` adds history) + per-row `ack` button (idempotent POST). Dashboard tile renders only when count>0 (quiet dashboard stays calm).

NOT in this commit (Phase G chunks 2-3): `server.unreachable` after N missing probes, `fail2ban.banned_self` detection, webhook transport (`VPNCTLD_NOTIFY_WEBHOOK_URL` env — Pavel must pick Telegram/ntfy/journald first).

**Code:** `crates/inventory/migrations/0011_admin_alerts.sql`, `daemon/src/health_monitor.rs` (540 LOC), admin handlers `alerts` + `alert_ack`, dashboard tile `dashboard_alerts_tile`.

### L7 — migrate destructive-op gate (NEW this burst)

**Flow:** Before `apply_migration_plan` runs in `--apply --overwrite-existing`, the CLI calls `report_address_overwrite_warnings(inv, plan)` which compares the existing `Server.address` / `ssh_port` / `ssh_user` to the bash data. If any change is detected AND `--i-really-mean-overwrite-address` is absent, bail with an explicit diff. This closes the methodology gap that allowed the vps-is-01 ↔ 104 cross-overwrite on 2026-05-17.

**Code:** `cli/src/cmd/migrate.rs::report_address_overwrite_warnings`.

### `vpnctl server set-fingerprint` (NEW this burst)

**Flow:**
- CLI: `vpnctl server set-fingerprint <id> <SHA256:…>` or `... --from-keyscan` (shells `ssh-keyscan -t ed25519 -p <port> <host> | ssh-keygen -lf -`).
- Web: section on `/admin/servers/{id}` with auto-detect button (primary) + manual paste form (escape hatch). Both POST `/admin/servers/{id}/set-fingerprint` with hidden `mode=keyscan|manual`. Validates shape (`SHA256:` + 1..=44 chars base64), audit-logs `server.set_fingerprint` with `{fingerprint, source}`.

**Code:** `cli/src/cmd/server.rs::SetFingerprint`, `daemon/src/handlers/admin.rs::server_set_fingerprint`.

### `decode_form_value` UTF-8 fix (NEW this burst)

Replaced `out.push(byte as char)` Latin-1 cast with `Vec<u8>` accumulator + `String::from_utf8_lossy`. Every form value can now legitimately carry UTF-8 (Cyrillic, emoji, etc) instead of silently mojibake-ing on bytes ≥ 0x80. 6 new unit tests pin the contract.

**Code:** `daemon/src/handlers/admin.rs:4060-4150`.

## Methodology layers (current, post-burst)

| # | Layer | What it catches |
|---|---|---|
| 1 | `cargo clippy --workspace --all-targets -D warnings` | API misuse, dead code, unwrap/expect/panic outside tests. |
| 2 | `cargo test --workspace` | DOM + routing + DB invariants + spec contracts. |
| 3 | Copy-contract subset of admin_smoke | Backend response prefix drift, editorial voice regressions. |
| 4 | review-agent (`general-purpose` agent on git diff) | Logic bugs, SQL injection, swallowed errors, library misuse. |
| 5 | Live-deploy on 192.168.0.236 + curl | Runtime + auth + DB integration. |
| 6 | `scripts/visual_check.py` (headless Chrome) | Layout overlap, grid overflow, font fallback. |
| **7** (NEW) | **Destructive-op confirmation gate in CLI/handler** | Operator typed the right `--server-id` / right address / right kind. The vps-is-01 ↔ 104 fix. |

## Known follow-ups (not blocking)

- Phase G chunk 2: `server.unreachable` + `fail2ban.banned_self` detection.
- Phase G chunk 3: webhook transport — needs Pavel to pick Telegram / ntfy.sh / journald.
- Multi-server UUID split-identity: main-brat on vps-de-01 has 5550051c (matches 93), but vpnctl `/sub/<token>` for that user includes a TUIC outbound with the wrong UUID for 104 — accepted trade-off; phones use bash-scanned links directly. Three options for Pavel: live with it / per-server-suffix users / canonical-only revoke.
- Phase F deep dive: live stats endpoint + per-server real-time tile on dashboard (Track-3 poller already writes the data; just needs a JSON endpoint + maud tile).
- Live-staging E2E for AnyTLS / Trojan / Hysteria2 / WireGuard on second VPS (Tier-2).

## Burst commit list (e928cd2..aef1c6b)

| Commit | What |
|---|---|
| `e33d94a` | `docs(burst): plan for 2026-05-17 overnight autonomous burst` |
| `e928cd2` | `docs(roadmap): mark shipped — Track-1.1/2/D/F/3/4/C-3.2-4/C-4/C-5/E` |
| `d391c73` | `feat(daemon): Phase H chunk 4 — node_probe poller wiring` |
| `a17fad6` | `feat(daemon): Phase G — infra alerts on top of node_health probes` |
| `aa83241` | `feat(cli/migrate): L7 destructive-op gate on Server.address overwrite` |
| `2fda5c6` | `feat(cli/web): vpnctl server set-fingerprint + matching web action` |
| `aef1c6b` | `fix(daemon/admin): decode_form_value UTF-8 — assemble bytes, then String` |

Total burst: **+7 commits**, **+~2 500 LOC code + tests + docs**, **+20 tests** (149 admin_smoke), 1 live-deploy with smoke verification. All CI runs green.
