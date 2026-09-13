# vpnctl backlog

Deferred work items with enough context to pick up cold. Newest first.

## Deploy All lock retry on concurrent user auto-deploy

**Status:** Surfaced in production testing (user `gelios` enable).

**Problem:**
When a user is enabled via `/admin/users/{id}/enable`, `vpnctld` spawns a background auto-deploy (`spawn_user_servers_redeploy` → `redeploy_servers_collect_errors`) targeting the user's granted servers.
If the operator simultaneously clicks **"Deploy all"** (or triggers `/admin/servers/deploy-all`), `run_deploy_all` attempts to acquire `DeployGuard` per server sequentially without retry.
Because the background auto-deploy holds `DeployGuard` for `bahnhof`, `run_deploy_all` immediately emits a per-server error:
`[apply] ✗ bahnhof: deploy already running for server 'bahnhof' — wait for it to finish, then retry`.

This causes the entire `run_deploy_all` stream to finish with a terminal `BootstrapEvent::Error`. Consequently:
1. `admin.js` receives an error event and does NOT auto-reload the page (`window.location`).
2. The UI banner `⚠ Config not yet deployed to: bahnhof, ch, de-1, is` remains visible until a manual page refresh, even though `ch`, `de-1`, and `is` succeeded in DB/audit and `bahnhof` was already being deployed by the background task.

**Proposed Fix:**
1. In `wizard_bootstrap::run_deploy_all` (or `redeploy_pipeline`), add a brief retry mechanism (e.g. up to 3-4 retries with 1-2s delay when encountering `DEPLOY_ALREADY_RUNNING_PREFIX`), matching the retry posture in `redeploy_servers_collect_errors`.
2. Alternatively, evaluate whether `run_deploy_all` should treat a concurrent in-flight deploy of the same revision as non-fatal or await the held `DeployGuard` permit before reporting error.

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
3. **Subscription base URL hard-coded.** `daemon/src/handlers/admin/legacy.rs`
   `ninitux_url()` hard-codes `https://ninitux.com/api/v1/app/config/<id>`
   (deliberate cutover contract) with a TODO to promote to
   `VPNCTLD_PUBLIC_SUBSCRIPTION_BASE_URL` env var for staging overrides.
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

## v2ray stats → billing-grade per-user attribution (Go helper)

**Status:** deferred (not needed now). Current clash-snapshot polling at 60 s
attributes **84–99 %** of bytes per user across all nodes — enough for
"who eats the traffic".

**Problem it would solve.** clash `/connections` is a snapshot of *active*
connections. Bytes from connections that open+close *between* polls are counted
in the server total but never sampled per-user → a residual sampling-ceiling gap
(worst on cdn / hysteria2 QUIC churn: ~84 %; VLESS nodes 88–99 %). Dropping the
poll interval to 60 s shrank the gap but cannot fully close it.

**Fix.** Enable sing-box `experimental.v2ray_api.stats` — **cumulative** per-user
uplink/downlink counters that survive connection close → no sampling gap, ~100 %
on every node including churny QUIC. Verified in sing-box v1.13.12 source
(`experimental/v2rayapi/stats.go` `RoutedConnection` / `RoutedPacketConnection`)
that the *same* counter mechanism already counts VLESS+vision and hysteria2 — the
clash per-connection bytes are already non-zero for both, so the vision/splice
worry is unfounded.

**Why deferred.** 84–99 % already answers the per-user question. The hoster bills
*wire* traffic (~2× payload + caddy / slipstream), reconciled via
`servers.usage_coefficient`, so exact per-user *payload* isn't needed for billing.

**Becomes worth doing when:**
- enforcing hard `users.monthly_bandwidth_limit_bytes` to the GB on churny nodes, or
- wanting to drop poll frequency back to 5 min (less node CPU / SSH) while keeping
  accuracy — cumulative counters don't need frequent sampling.

**Implementation — lean path (Go helper, NOT Rust gRPC):**
1. **Keep Rust untouched.** vpnctl SSH-execs a helper and parses its output,
   exactly like the current `curl 127.0.0.1:9090/connections` for clash. The gRPC
   weight stays isolated in a throwaway binary, off `Cargo.toml` / `cargo-deny`.
   (gRPC is heavy in *both* Go and Rust — the win is isolating it, not the language.)
2. **Helper** (`tools/singbox-stats-helper/`, ~60 lines Go): dials the local
   v2ray_api gRPC `StatsService`, `QueryStats` pattern `user>>>`, prints
   `name → {up, dn}` JSON. Reuses sing-box's own `stats.proto`. Built with the same
   Go toolchain/recipe as `tools/singbox-attr-patch`; static `CGO=0`; deployed per
   node like the patched sing-box.
3. **Config.** Render `experimental.v2ray_api.{listen, stats:{enabled, users:[…]}}`
   in `crates/kernels/src/sing_box.rs`. Per-user counting requires the user be
   listed (`countUser := user != "" && s.users[user]`) — mirror the inbound user
   list, which the config already re-renders on every user add/remove, so no new
   operational coupling. Bind the gRPC listener to loopback only.
4. **Poller.** Switch the per-user-row byte source in `daemon/src/clash_poller.rs`
   from the clash snapshot to the helper's cumulative per-user totals (diff vs
   prior — same shape as today). `DiffEngine` already handles cumulative counters +
   restart detection; the server-wide-remainder logic is unchanged. The clash
   `/connections` poll can stay — it still feeds the live-connections drill-down,
   destinations, source IPs and sessions.
5. **First step:** 10-min spike on one node — temp `v2ray_api` config, confirm
   vision/hysteria2 counters increment as expected — before committing.

See also `tools/singbox-attr-patch/` (the clash `user` patch this builds on).
