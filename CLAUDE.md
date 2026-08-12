# vpnctl — Claude memory

Этот файл автоматически загружается в каждый чат с Claude в проекте `vpnctl`.

## Strategic context (final goal — keep aligned)

Confirmed by Pavel 2026-05-14:

- **Operator model.** Single operator (Pavel). No multi-tenancy, no
  RBAC. `actor="admin"` everywhere in audit. Don't waste cycles on
  role abstractions.
- **Users are operator-managed, NOT self-service.** No "request access"
  flow, no user-facing portal. Notifications cover *infrastructure*
  events only (server down, sing-box crash-loop, fail2ban banned-self).
- **Users are assumed maximally low-tech** (confirmed by Pavel
  2026-05-16). One action ceiling — «ctrl+c is already too much»;
  the realistic user can press exactly one button: scan QR / tap
  share-link / import file. Therefore for EVERY protocol the operator
  must be able to hand them a **single artefact** (one QR / one URL /
  one `.conf`) that works on import without ANY further user action,
  including filling in fields, choosing parameters, or generating
  keys. This is the design north-star for all `share_link` and `/sub`
  output:
    * Symmetric-secret protocols (VLESS, TUIC, Hy2, Trojan, AnyTLS,
      SS-2022): already trivially compliant — secret is server-side,
      embedded into the link.
    * WireGuard / AmneziaWG: the operator-provided `--wireguard-pubkey`
      flow violates this — user must generate keys on-device first.
      The default UX for WG must be `--gen-wireguard` (server generates
      Curve25519 pair, stores BOTH halves, hands user a complete
      ready-to-import config). Operator-provided pubkey stays as
      opt-in for security-paranoid sub-cases (sole operator can pick
      per user). Implication: the `users.wireguard_private` column is
      a SECRET that lives in inv.db; backup encryption and access
      control must reflect this.
    * Any future protocol designed assuming user-side key generation
      MUST add a server-generated default unless explicitly waived.
- **Web is the ONLY operator surface; CLI is implementation detail**
  (strengthened by Pavel 2026-05-16: «упровления CLI же должно
  происходить через web морду, то есть на вебе я жму кнопку, и
  дальше происходит магия не видная оператору»). The operator
  NEVER needs to open a terminal — every action they can take has
  a button in the admin UI. CLI commands are kept as automation /
  scripting / disaster-recovery hooks; documenting an operator
  task as "run `vpnctl X` from a shell" is a UX bug, not the spec.
  Implication for every new feature: a CLI command is not done
  shipping until the web equivalent exists, even if it temporarily
  shells out to the CLI binary internally.
- **Add-server wizard is THE core differentiator over the bash project.**
  Operator pastes IP + root password → admin does ALL the magic
  automatically: push pubkey, create non-root user, disable password
  auth, harden SSH, install fail2ban, install sing-box, render config,
  restart, prove it's live. Streaming UX (SSE) with per-step progress.
  This is Phase E and it's the most important phase.
- **Production deployment.** Private-only: LAN `192.168.0.236` plus
  Tailscale tailnet access. No public exposure or Funnel; OAuth/2FA
  remains a later concern.
- **Mobile / responsive.** Not needed.
- **Migration from bash `vpn-control`.** **Seamless preservation** of
  every existing client. Old phones holding `vless://` / `tuic://`
  links keep working byte-for-byte after the switch. The protocols
  crate's `share_link()` MUST produce identical output to the bash
  scripts for the same secret material — there's a regression test
  due here. Migration tool reads `inventory/<IP>.env` and imports
  servers + users + grants preserving UUID and password material.
- **Backups are critical, not optional.** If `192.168.0.236` burns
  today, every sub_token is lost and every client has to re-import.
  Need: scheduled `inv.db` snapshot + asset bundle + off-site copy
  (homelab Forgejo is a candidate target) + a documented restore
  procedure.
- **Design source = me (Claude).** No Figma. The editorial voice
  ("a daily report from your homelab", sentence-case, mono CLI
  inline) lives in code + this file; consistency is on me.
- **v1.0 is far.** Defined as "everything in the roadmap shipped
  AND we have months of operating experience without rolling back".
  Until then keep cutting v0.x with no marketing stunts.

### Roadmap (current order, post-2026-05-14)

| Phase | Suffix | Status | What |
|---|---|---|---|
| A, B | shell + read-only servers/dashboard | ✅ shipped | masthead, nav, themes, dashboard KPIs |
| C-1 | users list + detail + QR | ✅ shipped | commit `aafc180` |
| C-2 | UX polish (collapsible Tweaks, copy contracts, favicon) | ✅ shipped | commit `663a653` |
| C-3.1 | writes — regenerate sub-token | ✅ shipped | commit `276e47d` |
| C-3.2-4 | writes — add user / grants / delete | ✅ shipped | `2a5ce95` add + `60a90e9` grant/revoke + `0b1fec5` delete-confirm |
| Track-1 | abuse signal: per-user sub-fetch log + UI | ✅ shipped | `1e91eeb` |
| Track-1.1 | retention scheduler (sub_access_log + vpn_stats hourly purge >30d) | ✅ shipped | `1e33e29` |
| Track-2 | rate-limit `/sub/<token>` (per-IP, per-token), persistent bans | ✅ shipped | `555fd5a` token+IP bucket + `daemon/src/rate_limit.rs` |
| C-4 | backup + restore | ✅ shipped | `bbf427f` VACUUM INTO snapshot + retention + Settings download + `vpnctl restore` |
| C-5 | migrate from bash | ✅ shipped | `0530251` + `33b3025` split-identity policy |
| E | add-server wizard (THE feature) | ✅ shipped | `1821c99` step1 form + `4477199` SSE-streamed bootstrap (sub-iter 4b) |
| Track-3 | clash-api polling on each node, per-user real-time conns/traffic | ✅ shipped | `537342c` kernel block + `cd61838` client + `f22df7d` diff engine + `d36b7c9` UI + `473b2e4` poller reapply + `54ee77f` feature-gate |
| D | audit timeline | ✅ shipped | `1a2d8c9` paginated + filtered + CSV export |
| F | monitoring | ✅ shipped | `dbfd211` sparklines + `4d810f2` 24h dashboard sparkline + heatmap |
| Track-4 | UA fingerprint heuristic (roaming vs shared URL) | ✅ shipped | `272a3ec` ua_clusters_for_user + likely-shared/-roaming classifier on user-detail |
| H | node telemetry (read side) | ✅ chunks 1-4 shipped | `3970530` probe + `604cf0c` storage + `d5ff423` /admin/servers/{id} detail page; chunk 4 poller wired in `app.rs::build()` via `spawn_node_probe_poller` + `spawn_health_monitor` (10-min interval, env-overridable). **Verified live 2026-05-22**: 1496 probe rows across 3 servers (de:554, fi:310, is:632), last probe seconds-old on all three, every row reports `sing_box_active=1`. Phase G alert state-machine consumes these rows in `health_monitor.rs` — fires `server.singbox.down` / `fail2ban.down` / `disk.pressure` / `mem.pressure` / `singbox.log.too_big`. |
| G | infra notifications | ✅ shipped | `dbfd211` alerts + Telegram bot transport + admin_alerts table + dashboard tile (security audit 2026-05-18 rolled the test-send + token-via-stdin parts). |
| L7 | migrate destructive-op gate | ✅ shipped | `--i-really-mean-overwrite-address` flag in `cli/src/cmd/migrate.rs`; pinned by 5 unit tests in commit `0068c8f` (the impl itself landed earlier post-2026-05-17 vps-is-01 ↔ 104 cross-overwrite). |
| **WG-T** | **wgturn-core kernel + protocol** | ✅ shipped 2026-05-18 → ✅ live-deployed 2026-05-19 | VK-TURN-relayed WireGuard «emergency channel». Phase 1 `c06c175` (kernel skeleton + stub protocol + bootstrap + 17 tests). Phase 2 `4e08b2d` (offline `wgturn://` share-link encoder ported from `pkg/wgshare` af0f209f, 11 new tests + extracted `wg_addressing` shared peer-octet helper). 2026-05-19: kernel schema rewrite `e55877f` (upstream parses wg-quick INI with `#@wgt:` metadata, NOT TOML; needs separate WG-quick backend on loopback 51821) + Go 1.24 install path `86006c0`. End-to-end verified live on vps-de-01: `wgturn-cli` binary built + both systemd units active (`wgturn`, `wg-quick@wgturn-be`) + brat's [Peer] rendered + e2e `wgturn-cli connect-url '<...>' --vk-link '<...>'` reaches the VK auth phase from claude-chat. |
| **DG-1** | **sing-box pre-apply diff guard** | ✅ shipped 2026-05-19 `e55877f` | INCIDENT: a vpnctl deploy on vps-de-01 silently dropped `claude-chat-proxy` UUID b25684c3-... from sing-box's `inbounds[0].users[]` (the user was a service-account not in vpnctld's inventory). Result: all .142-host outbound HTTPS via the http-proxy broke tcpdump-silent at Reality handshake. FIX: `SingBox::apply_config` now reads the live `/etc/sing-box/config.json` BEFORE atomic-rename, diffs `users[*].uuid` set vs new config, REFUSES the deploy if any UUID would be removed (unless `VPNCTLD_ALLOW_USER_REMOVAL=1`). 7 new unit tests + live-tested on prod (audit row 13:39:22 shows refused deploy with the lost UUID spelled out + remediation paths). |
| **NM-1..7** | **ninitux subscription-server merge — full migration** | ✅ shipped + decommissioned 2026-05-19 → 2026-05-20 | Replaced the parallel Python `subscription-server` running on 192.168.0.207:8100 (33 production users, public endpoint `https://ninitux.com/api/v1/app/config/<device_id>`) with vpnctld's Rust implementation. **Phase 1** (`89cd16c`): per-server VLESS UUID overrides (`grants.client_uuid`) so each (user, server) pair can carry the same UUID subscription-server used historically. **Phase 2** (`9353c1c`): import script extended `set grants.client_uuid` from subscription-server's clients table, 23/23 UUIDs aligned. **Phase 3** (`3269a3e` + `e41f5c1`): vpnctld endpoint `GET /api/v1/app/config/{*tail}` byte-equivalent on the primary URI to subscription-server; defence-in-depth catch-all closes the `/api/v1/app/config/<id>/extra` `WWW-Authenticate: vpnctl admin` leak. **Phase 4 → 5**: nginx cutover on 192.168.0.207 (`proxy_pass http://192.168.0.236:18402/...`), 33/33 byte-identical primary URIs vs subscription-server, rate-limit on the nginx side (10r/s + burst 20). **Phase 5.5** (`52e4304`): `route_layer` for admin middleware closed a fingerprint leak on unmatched paths (probes hitting `/etc/passwd` got `401 WWW-Authenticate: Basic realm="vpnctl admin"`). **Phase 6** monitor cron on 192.168.0.236 ran daily for ~0.5 day before being skipped. **Phase 7** decommission (2026-05-20T14:38 UTC): `docker compose down` on `subscription-server` (data volume preserved + `subscriptions-db-phase7-*.tar.gz` archive, compose file disabled), port 8100 free, vpnctld is the only `/api/v1/app/config/` backend. **Naming convention rolled in alongside**: server IDs in inv.db are ISO-3166-1 alpha-2 lowercase (`de`/`fi`/`is`), usernames batch-lowercased + future creation gated by `^[a-z0-9._-]{2,32}$` + live-edit JS in the add-user form. URI fragment: `vless://...#{Country} VLESS ~{client_name}` (separator `~` chosen because it's the only ASCII char unreserved by RFC 3986 AND absent from every production user id). Full grant matrix: 33 users × 3 servers = 99 grants. Multi-SNI failover URIs (port 2083 icloud.com on de, ports 8443/8444 on is) dropped at Phase 7 — vpnctld's render schema is single-inbound per protocol and rebuilding that for backward-compat with subscription-server legacy URIs wasn't worth it for the few hours of overlap. |
| **NM-8** | **Layer-1 abuse signal hooked to production endpoint** | ✅ shipped 2026-05-20 | Phase 3-7 cutover left a gap: `/api/v1/app/config/<device_id>` (the endpoint mobile clients ACTUALLY hit) was NOT writing into `sub_access_log` — that table only filled from the legacy `/sub/<token>` handler which post-Phase-5 sees ~zero production traffic. So the operator's per-user IP / UA fingerprint / abuse-distribution surface (heavy-users tile + Track-1 timeline on `/admin/users/<id>`) was effectively blind to every real client. Fix: `vpn_router::get_config` now `try_send`s an `AccessLogRecord` after a successful URI render (same bounded-mpsc + dedicated writer pattern as `sub.rs`). Failed lookups + multi-segment paths intentionally NOT logged — preserves the pre-Phase-3 anti-probing posture from the original handler. |
| **NM-9** | **X-Forwarded-For consumption (trusted-proxy gated)** | ✅ shipped 2026-05-20 `4d238e6` | After NM-8 every Layer-1 row carried `ip=192.168.0.207` (nginx peer) because vpnctld read only `ConnectInfo<SocketAddr>` — the rate-limit token bucket also collapsed to ONE bucket for all 33 production users (a single abuser would exhaust it on behalf of everyone). New module `daemon/src/real_ip.rs` parses `X-Forwarded-For` leftmost IP, BUT only when the immediate peer is in `VPNCTLD_TRUSTED_PROXIES` (default `192.168.0.207`, comma-separated env override). Untrusted peers' XFF is dropped on the floor (spoof defense). 5 unit tests pin happy + IPv6 + missing + malformed + untrusted-spoof cases. Wired into `sub.rs` (rate-limit + sub_access_log) + `vpn_router.rs` (sub_access_log). Live-verified: probe through nginx → sub_access_log row with real outbound IP `104.194.156.93` instead of nginx's `192.168.0.207`. |
| **NM-10** | **Protocol visibility — per-(server, protocol) hide + per-(user, server, protocol) deny** | ✅ shipped 2026-05-20 `3a656d7` + `cd71cf9` + `dbec8fc` | Pavel UX requirement: «нужно отдельная настройка которая позволяет добавлять или убирать конкретный протокол с конкретной подписки и/или скрывать его на сервер без явного удаления». Two orthogonal axes with OR-semantics deny resolution. Migration 0018 adds `server_protocols.hidden INTEGER NOT NULL DEFAULT 0` + new `grant_protocol_overrides` table with composite FK to `grants(user_id, server_id) ON UPDATE+DELETE CASCADE`. 5 new SqliteInventory methods (`is_server_protocol_hidden`, `set_server_protocol_hidden`, `set_grant_protocol_override`, `visible_protocols_for_subscription`, `list_protocol_overrides_for_user`) + bulk helper `list_server_protocols_with_hidden`, all transaction-wrapped + audit-on-actual-mutation (review-agent caught two no-op-audit-spam issues — fixed). `sub.rs` + `vpn_router.rs` render paths filter through `visible_protocols_for_subscription`. Hidden inbound STAYS running on the sing-box node so cached client URIs keep working — the toggle is "soft hide from public render", distinct from add/remove protocol which writes/deletes the row. 4 HTTP POST handlers under `/admin/{servers,users}/.../protocols/.../{hide,unhide,disable,enable}` (303 redirect to source page). Admin UI shipped in `dbec8fc`: server-detail Enabled-protocols section now offers a `[hide]`/`[unhide]` chip per enabled+compatible row (with a "✓ on · hidden" status marker in `--acc`), and user-detail Server-access section sprouts a "Per-protocol delivery" sub-grid for each granted server — three render branches (✓ delivered / ✗ user-blocked / server-hidden read-only) plus a compound "server-hidden + user-blocked" branch that keeps the unblock-user button so stale per-user overrides on a server-hidden protocol can still be cleared. Render iterates `server_protocols` table rows (not the in-memory `Server.enabled_protocols` cache) so OR-semantics matches `visible_protocols_for_subscription` byte-for-byte. 11 inventory spec tests + 10 admin_smoke UI tests pin every rule, including the both-axes-deny branch and alphabetical sort. |
| **NM-11** | **clash-api per-user attribution — KNOWN UPSTREAM BUG, not fixable from vpnctld** | ❌ blocked by sing-box | Layer 2 abuse-detection investigation (Pavel 2026-05-20): `vpn_connection_stats` had 1343 rows but `user_id = NULL` on every single one. Root cause traced to sing-box upstream: `experimental/clashapi/trafficontrol/tracker.go::TrackerMetadata.MarshalJSON` hardcodes the emitted JSON keys (`network, type, sourceIP, destinationIP, sourcePort, destinationPort, host, dnsMode, processPath`) and explicitly OMITS `User`, even though `adapter.InboundContext.User` IS populated server-side by every auth-bearing protocol (VLESS, TUIC, Trojan, etc). No vpnctld-side fix possible: the wire format doesn't carry the data we need. Three viable upstream paths: (1) PR the sing-box repo to add `"user": t.Metadata.User` (1-line change), (2) fork + maintain on every node (operationally heavy), (3) wait for sing-box V2 API. Recommendation: file upstream PR. Until then per-user clash-api attribution stays NULL — server-wide totals on the dashboard still work. |
| **NM-12** | **DPI-risk tier per protocol — coloured chip + small-font Weak in admin UI** | ✅ shipped 2026-05-20 `bfd86c1` | Pavel UX requirement: «давай начнём с того что ты уберёшь чтото плохие протоколы и пометишь их в ui как плохие и можешь даже шрифт меньше сделать у них». Before NM-12 the operator had no signal that "this protocol's wire format is trivially fingerprintable in RU/IR/CN 2026" — a freshly-enabled raw-WireGuard was visually indistinguishable from a battle-tested REALITY. New `vpnctl_core::DpiRisk { Strong, Moderate, Weak }` enum + `Protocol::dpi_risk()` trait method (default `Moderate`); carries `.label()` / `.tooltip()` / `.border_css()` / `.text_css()` so the chip palette has one source of truth (review-agent NM-12 caught a 4× match-arm dupe in the admin rendering — collapsed into the helpers). Tier is a property of the WIRE FORMAT, not a per-server config — compile-time static, no inventory state, no migration. Tier assignments: **Strong** — vless+reality (REALITY's `dest:` forwards probes to www.microsoft.com → indistinguishable from real visitor), wgturn (VK-TURN demuxer wraps raw-WG 0x01 handshake tag). **Moderate** — tuic-v5, anytls. **Weak** — shadowsocks-2022 (AEAD-random from byte 0, entropy fingerprint blocked on TSPU since 2024), wireguard (raw `0x01 0x00 0x00 0x00` handshake tag is hard-coded in the wire spec, dropped 100% on TSPU/GFW), trojan (our inbound has NO `fallback:` upstream → active TLS probe sees self-signed cert with no real HTML), hysteria2 (our inbound has NO `obfs:` parameter → bare QUIC on UDP/8444 blocked by TSPU since early 2026). Admin UI: coloured chip alongside each protocol name on server-detail + user-detail per-protocol grid (green for Strong, dotted grey for Moderate, accent-red for Weak); title-attr tooltip with the per-tier explainer; Weak protocol rows shrink font-size by 1px (`12px→11px` on server-detail, `11px→10px` on the denser user-grid) for visual de-emphasis without removing the toggle. Hidden Weak protocols KEEP the chip — chip is about wire format, not visibility (pinned by `nm12_server_detail_hidden_weak_protocol_still_shows_chip`). 7 admin_smoke tests pin Strong/Moderate/Weak chip rendering, the font shrink, the hidden-still-shows-chip rule, the defensive None branch for missing-from-registry pids, and the exact tier distribution (2 Strong + 2 Moderate + 4 Weak chips on a server with all 3 kernels). Live action 2026-05-20T20:41 UTC: 5 POST `/hide` calls (`fi: shadowsocks-2022/trojan/hysteria2/wireguard`, `is: hysteria2`) reduced subscription render from 13 visible protocols × server to 8, leaving only Strong + Moderate tiers exposed to clients. Inbounds keep running on the nodes so cached client URIs from before the hide continue to work — clients just stop being told about Weak protocols on next pull. |
| **DR-5** | **Restore fire-drill — close-out (Phase 5 a→e)** | ✅ shipped 2026-05-22 `168123d` + `2ecd1a3` + `2d44003` + `cd6b39b` + `6becbf1` | Closed the «backup exists but no one has ever tested restore on production data» gap. **Phase 1-4 (manual)**: extracted current backup to tmpdir + ran vpnctld against restored DB + hit `/api/v1/app/config/<device_id>` for ALL 33 production users → **32/32 byte-identical** (1 differ only in `timestamp` field = server-side `now()`). Identified 7 paths missing from the bundle that would have made a real restore non-functional (deploy SSH key being the headline — without it the restored vpnctld can't reach ANY VPN node, silent failure). **Phase 5a** (`168123d`): extended `vpnctl-backup.sh` to bundle the deploy SSH key, known_hosts, recipient.txt, geoip mmdbs, systemd units, iptables rules. Archive 473KB→58MB. **Phase 5b** (`2ecd1a3`): off-site copy via scp to `root@93.95.226.167:/root/vpnctl-backups/` (Iceland VPN node `is`), 30-day retention. Best-effort: if scp fails, the primary `192.168.0.207` archive is still good. **Phase 5c** (`2d44003`): Rust restore self-test — `POST /admin/backup/self-test` copies a snapshot to a tmpfile, runs the sqlx migrator against it, executes 6 invariant checks (table presence, FK preservation, user count > 0, server count > 0, schema_migrations max version matches HEAD, integrity_check PRAGMA), renders an HTML report. 7 unit tests + UI button in Settings. Review-agent flagged 7 issues, all fixed. Live-verified on prod: `PASS · 4ms`. **Phase 5d** (`cd6b39b`): integration test `daemon/tests/restore_e2e.rs` — seed → snapshot → mutate (revoke a grant + regenerate sub_token) → restore to a SECOND db path → diff `/api/v1/app/config/<id>` response between pre-mutation, post-mutation, restored. Asserts `pre != post` (proves mutation moved the bytes — guards against vacuous-pass) AND `pre == restored` (THE contract). Runs on every commit → byte-stability of the subscription endpoint after restore is now CI-protected, not just operator-tested. **Phase 5e** (`6becbf1`): «Disaster Recovery» section in `/admin/settings` (anchor `#disaster-recovery`) — 3-tier backup table (local/LAN/off-site), what's in each bundle (with explicit «deploy key — hard invariant» reminder), last self-test status (reads from `audit_log` `backup.self_test` rows, renders PASS/FAIL chip with timestamp + duration; renders «(duration missing)» on schema-drift), restore procedure (3 numbered steps with explicit «steps 1+2 on a NEW host because 236 is dead — there's no daemon to push buttons on, step 3 returns to Web UI on the recovered daemon»). Bilingual EN/RU throughout. Visual-checked via headless Chrome. Review-agent: 2 important findings fixed (duration fallback + procedure preamble). 985 workspace tests pass + 2 new integration tests. The restore story is now: bundled properly (5a), off-sited (5b), self-testable (5c), CI-protected (5d), operator-documented in-product (5e). |
| **NM-13** | **Admin UI audit pass — log cleanup + audit naming + tooltips + bilingual EN/RU shell + body-copy translation** | ✅ shipped 2026-05-21 `d7b1a75` + `cd644b2` + `e492b14` + `bf706ea` | Pavel 2026-05-21: «прошел по ui, добавил русскую версию, проверил ее на баги, сделал подсказки по каждому пункту, удалил старые записи с баганым ip из логов» + follow-up «продолжай, делай полный перевод». Three parallel discovery agents (Explore route-map, general-purpose tooltip-audit, general-purpose live-bug-hunt) ran against the running 192.168.0.236 instance + the codebase; their findings cluster shipped in three commits. **A. Prod data cleanup** (one-shot SQL, audit row `id=379`): deleted 59 `sub_access_log` rows where `ip='192.168.0.207' AND ts < '2026-05-20T19:17:00Z'` (pre-NM-9 nginx-peer-as-client-ip noise — post-NM-9 the XFF wire-up reads real client IPs); renamed 22 `audit_log` rows from `server_protocol.set_hidden`+`grant_protocol.set_override` (underscore-separator NM-10 drift) to the dot convention `server.protocol.set_hidden`+`grant.protocol.set_override` that every other audit action uses. **B. Code correctness** (`d7b1a75`): inventory now emits the dot form for future writes; the audit-page filter placeholder `user. / server. / grant` (which silently missed the 18 hide rows when operators typed the documented `server.` prefix) replaced with `server.protocol. / user. / grant. / settings.` plus tooltips on every filter control explaining the convention. Footer dropped the «axum + maud + htmx» lie (htmx never landed). User-detail Live-VPN-stats empty-state no longer hard-codes `192.168.0.236:/var/lib/vpnctl/.ssh`. Pagination "page N" carries a title attr explaining the 0-based-URL ↔ 1-based-label convention. **C. Tooltip pass** (`cd644b2`): 12 actionable elements + dense-table headers that had no explainer got bilingual title attrs — mint sub-token / generate WG keypair / ack / pin manually buttons; traffic-limit GiB + threshold-pct inputs; telegram bot-token + chat-id; UA fingerprint table per-column (user-agent / hits / ips / `/16 nets` / verdict — explains the abuse-detection heuristic); live VPN stats columns (clash-api 5-min tick caveat, wgturn excluded); ensure_installed / apply_config / TOFU jargon expanders. **D. Bilingual EN/RU shell** (`e492b14`): new `daemon/src/i18n.rs` module — `Locale { En, Ru }` + `K` (translation key) enum + exhaustive-match `t(loc, k) -> &'static str` (adding a key without populating both arms is a compile error); `Locale::from_request` resolves cookie `vpnctl_lang=ru` first, then `Accept-Language: ru*`, defaults En. `shell(active, theme, accent, lang, body)` signature extended + 12 callers updated. `[EN | RU]` toggle chip in masthead — active locale bold, other is `POST /admin/tweak/lang value=<x>` form button reusing the existing `set_tweak_cookie` helper (1-year HttpOnly SameSite=Lax cookie). `<html lang="ru">` set when ru selected for hyphenation + screen readers. First wave translates nav (Dashboard→Дашборд etc.), footer, masthead subtitle, common action buttons (deploy / save / hide / unhide / block / unblock / disable / enable / ack / filter / reset / export csv), page H1s, top-level eyebrows ("Server access"→"Доступ к серверам", "Enabled protocols"→"Включённые протоколы", etc.). Body copy, error messages, dense table contents, wizard SSE log lines stay English-only after this commit — future passes extend `K` + `t()` without touching the shell. Tests: 7 i18n unit + 5 admin_smoke i18n integration + 3 tooltip-pinning smoke = 15 new (218 admin_smoke total). Live-verified post-deploy: default EN nav, POST /admin/tweak/lang round-trip sets cookie + 303-redirects via Referer, with `vpnctl_lang=ru` cookie all 7 nav items render Russian + `<html lang="ru">` + Russian masthead subtitle. **E. Body-copy translation wave 2** (`bf706ea`): new `i18n::tr(loc, en, ru)` inline-pair helper added (trade-off vs `t()`: registry-overhead-free for one-off body copy that doesn't deserve a `K` enum entry; promote to `K` once a string appears in 2+ places). Translated body copy on every top-level page: dashboard (H1 «homelab одним взглядом», deck, all 4 KPI tile labels + sub-labels, "Homelab health" alerts tile, "Limit alerts" with N-user count + OVER badge, "Heavy users · 24h" with empty-state, "Recent activity" timeline with "автор: <actor>" prefix); monitoring (H1 "N обращений за последние 24 часа", deck, 3 KPI tiles, 3 sparkline labels, JSON-curl explainer); servers list (H1 + deck + quick-add form labels/placeholders/tooltips + wizard CTA + empty-state, `server_card` translates Hoster / jump / "N users granted access" / protocols / hidden / fingerprint / usage × meta rows + hidden-tooltip); users list (H1 + deck + search form with sort links + showing-N-of-M counter + add-user form with live-edit explainer + empty/filter-empty states, `user_row` translates uuid + sub-token mask + caveats + tuic/WG markers + CTA); audit (H1 + deck + filter form actor/action/buttons + empty-state); alerts (H1 + deck + counter + show-all toggle + 2 empty-states + per-row ack button + acked-timestamp); settings (H1 + deck + Appearance section + Backups section with retention + off-site + snapshot-now button + CLI-restore caveat); server-detail hero ("Live status" + empty-state + all 6 status tiles + active/down values); user-detail (H1 + deck + section eyebrows: Subscription / WireGuard keypair / Server access / Per-protocol share links / UA fingerprint / Live VPN stats — including `ua_clusters_section` + `live_vpn_stats_section` plumbing). 220/220 admin_smoke (4 new i18n tests: `i18n_ru_renders_translated_body_copy_on_each_page` walks all 7 top-level pages with the ru cookie and asserts distinctive Russian phrases per page; `i18n_en_default_renders_english_body_copy` symmetric guard against tr-arm-swap regression). Live-verified on prod: `vpnctl_lang=ru` cookie renders body copy in Russian across all 7 top-level pages + server-detail hero. Still English-only after wave 2 (incremental wave 3 candidates): server-detail Kernels / Enabled-protocols / drift / deploy-key body (~600 lines), user-detail sub-token / WG / traffic-limit / per-protocol grid body (~800 lines), wizard SSE log + step forms, the 12 tooltip strings added in cd644b2, error messages from `bad_request`/`not_found` paths (intentionally English for journalctl grep — Pavel «копи-контракт»). |
| **SS-1** | **orthogonal `Protocol::server_secret_specs()` — mint EVERY enabled protocol's secret** | ✅ shipped 2026-05-31 `c2a0437` | INCIDENT (kg): quick-add enabled 6 protocols but `bootstrap_server_secrets` hardcoded minting for only vless/wireguard/hysteria2 → a server with shadowsocks-2022 enabled failed deploy at render with `MissingSecret { ss2022.psk }`. Fix closes the long-standing orthogonality TODO: new `Protocol::server_secret_specs() -> Vec<ServerSecretSpec>` (default empty) in `crates/core`; each protocol declares its server-side secrets; the daemon minter iterates enabled protocols via the registry. New `crypto::gen_base64_key` (STANDARD padded base64) because ss2022 PSK is base64-DECODED by sing-box (Go StdEncoding) — the url-safe `gen_password` would crash the node config (matched to fi's working 24-char key). Adding a secret-bearing protocol is now one spec in its own file. Regression guard: all-protocols server → bootstrap → every protocol renders w/o MissingSecret. |
| **UX-1** | **operator-settable server `display_name`** | ✅ shipped 2026-06-01 `46aa163` | Pavel: kg rendered as bare "KG VLESS" in the sub while mapped servers showed full country names — the label came from a hardcoded `country_display_name()` match. Migration 0029 `servers.display_name` (nullable, additive); `set_server_display_name`/`server_display_name` inventory methods (trim, blank→clear, audit-on-actual-mutation); shared `server_display_label(id, custom)` resolver (custom → country-map → uppercased id) used by BOTH `/sub` + `/api/v1/app/config`; server-detail form + `POST /admin/servers/{id}/display-name`. Live: kg → "Kyrgyzstan VLESS ~ninitux". |
| **UX-2** | **SSE-streamed re-deploy (live per-step status)** | ✅ shipped 2026-06-01 `377457b` | The Deploy button did a synchronous POST→303 that read as "success" even when sing-box crash-looped (ssh_errors went only to audit). `wizard_bootstrap::run_redeploy` streams the deploy tail (validate→secrets→ensure_installed→render→apply) as `BootstrapEvent` step/ok/error; ends in `error` (not ok) on any kernel failure. `GET /admin/servers/{id}/deploy/sse` (EventSource), Sec-Fetch-Site same-origin guarded. Frontend: **external** `daemon/assets/admin.js` (CSP `script-src 'self'` forbids inline — NOTE: the Phase-E wizard's own inline SSE log is CSP-blocked in-browser, latent; admin.js is generic `[data-sse-url]` so a follow-up can fix the wizard too). POST form kept as `<noscript>` fallback. |
| **RL-1** | **rate-limit prod `/api/v1/app/config` (egress-aware + spoof-proof)** | ✅ shipped 2026-06-01 `2ebc4cb` | Bug-scout HIGH: the prod subscription endpoint had NO rate-limit (legacy `/sub` had both axes). A naive per-IP limit is CATASTROPHIC here — a VPN-connected client's refresh egresses its node, so vpnctld sees the SERVER's IP; N users on one server collapse into ONE per-IP bucket (Pavel: "33 обновления если все на одном конфиге"). Design: per-`device_id` (post-resolve, path-segment → not spoofable) is THE per-user limit; per-IP is anti-flood ONLY for non-egress IPs (`is_known_server_address()` exempts our nodes). Throttle-only, no ban (would cut real users). review-agent CRITICAL: leftmost-XFF is client-spoofable behind appending nginx → an attacker could claim a server IP to dodge per-IP/claim exemption → fixed with `real_ip::resolve_peer_real_ip` reading `X-Real-IP` (nginx overwrites it; not forgeable) for the security decision; logging keeps leftmost-XFF. Live: flood → 200×5→429; real user unaffected. |
| **AL-1** | **`server.unreachable` re-fires after a manual ack while still down** | ✅ shipped 2026-06-01 `adef8da` | Bug-scout HIGH (the kg 2026-05-31 21:09 mystery): operator acked the alert while the node was still down; `FailState.fired` is in-memory and once true every later failing tick returned `NoChange`, so the caller never re-attempted the insert → the acked alert never re-fired (only a recovery reset `fired`). Fix: new `UnreachableTransition::StillUnreachable` (counter ≥ threshold && already fired) → dispatcher runs the SAME idempotent `insert_alert_if_no_unacked`: no-op while open (partial-UNIQUE dedup, no spam/push), re-opens after an ack (Ok(Some) → audit+push). Self-healing; also mitigates daemon-restart. Integration test: fire→no-dup→ack→next-tick re-fires. |
| **NV-2** | **naive + hysteria2 delivered through `/api/v1/app/config` (ninitux endpoint) + naming + auto-firewall** | ✅ shipped 2026-06-04/05 (PRs #6–#9) | The endpoint clients ACTUALLY use was VLESS-only; naive/HY2 never reached the operator's app. Now a generic `collect_extra_protocol_uris(pid, require_secret)` in `vpn_router.rs` renders naive (Caddy kernel, needs `naive.domain`) AND hysteria2 (sing-box, UDP/8444, Salamander obfs auto-applied when the secret's minted) AFTER all vless. Opt-in by grant + NM-10 visibility (hide = request-time kill-switch); failure-isolated (a render error serves the rest, never drops vless); byte-identical for un-entitled users. **naive client-support reality:** Xray/v2ray don't implement naive (only sing-box-Cronet + the standalone client) — so for the custom ninitux app the operator added naive support themselves; hysteria2's `hysteria2://` scheme is broadly understood. **Fragment naming:** extra protocols carry the server display-label `{label} NAIVE/HY2 ~{user}` like vless (daemon re-labels the share_link's fragment; injection-safe via NINITUX_QUOTE). **Auto-firewall:** `Kernel::open_firewall(ssh, protocols)` (default no-op; sing-box opens each enabled protocol's `listen_ports()` via best-effort idempotent ufw — `command -v ufw` guard makes DO/cloud-firewall hosts a clean no-op) wired into all 4 deploy paths — a fresh `deploy` is reachable without a manual `ufw allow`. |
| **UX-3** | **naive↔HY2 co-location pairing (`pair=<node>`) — per-server opt-in** | ✅ shipped 2026-06-05 | naive can't carry UDP, so a client routes UDP over the HY2 co-located on the SAME physical node as a given naive. The ninitux endpoint stamps a node's naive AND hysteria2 share-links with a shared `pair=<server id>` query param (before the `#fragment`), so the client matches naive↔HY2 by node. **Per-server opt-in** (migration 0031 `servers.udp_pair_enabled`, default 0): operator toggles it on the server-detail page (`POST /admin/servers/{id}/udp-pair`, audited `server.udp_pair.set`; `is_server_udp_pair_enabled`/`set_server_udp_pair_enabled` inventory methods); the render emits `pair=` only when the flag is ON **and** the server exposes BOTH naive and HY2. **Single-server only by construction** — the tag IS the server id (unique per node), so it can never join two nodes; different nodes → their own id; a naive- or HY2-only node, or one without the opt-in → none. Opaque (match-only); unknown to other clients (ignored); vless untouched. `add_query_param` inserts before the fragment (`?` then `&`); NINITUX_QUOTE-encoded (injection-safe). Tests: paired→both share, two paired→distinct, no-opt-in→none, single-protocol→none + inventory spec + admin_smoke toggle. |
| **XH-1** | **Xray-core kernel + VLESS+Reality+xhttp protocol — live-verified from RU** | ✅ shipped + live-verified 2026-07-01 (PRs #78–#80) | The operator's VPNRouter client embeds `Leadaxe/sing-box-lx` (a thin fork adding client-side xhttp + AWG2 — see `XH-1` precursor research that closed AWG2 via the native `amnezia_wg` kernel, see roadmap). sing-box has no SERVER-side xhttp inbound, so this needed a genuinely new kernel: **`Xray` (`crates/kernels/src/xray.rs`)** — prebuilt-binary install from `XTLS/Xray-core` releases (pinned exact-version, not a floor — no apt channel to track), hardened systemd unit (profile mirrors `wgturn.rs`'s), validate→snapshot→swap→poll→rollback `apply_config` — paired with **`VlessXhttp` (`crates/protocols/src/vless_xhttp.rs`)**, serving on a standalone **9443/TCP** (NOT 443 — sing-box owns it; NOT 8443 — double-claimed on `is` between caddy/vless-ws TCP and sing-box tuic-v5 UDP). Reuses the REALITY keypair `vless+reality` already mints on the same server (mints only `vlessxhttp.path`); no `flow=` anywhere (xhttp is Vision-incompatible). Kernel × Protocol orthogonality held: 2 new files + 4 registration-line edits, nothing else touched. Server/client JSON shapes verified directly against `XTLS/Xray-core` and `Leadaxe/sing-box-lx` SOURCE (not docs) — caught real schema differences from sing-box's shape (`id`/`email` not `uuid`/`name`; `log.loglevel` not `log.level`; `outbounds[].protocol` not `.type`). 151 new tests (121 from PR #78 + 30 from independent agents), zero regressions. **Two live-deploy bugs, both caught on the `is` pilot and fixed same-day** (review/tests cover logic, NOT live-environment assumptions — same lesson as the original staging-deploy table above): (1) **PR #79** — Xray-core's `run -test` infers config FORMAT from the file EXTENSION; validating a `config.json.new`-suffixed staging path failed with "Failed to get format of..." even though the JSON was valid (proved by copying the same bytes to a `.json`-suffixed path, which passed clean). Same bug class as the AWG2 `apply_config` fix (`awg-quick` also required an exact `<iface>.conf` filename). Fixed by staging at `config.staging.json` instead of `config.json.new`; also fixed a diagnostics gap where Xray's real failure reason went to STDOUT (not stderr), hiding the cause in the audit log until reproduced manually over SSH. (2) **PR #80** — TLS+Reality handshake worked but every xhttp request 404'd. Root cause traced through BOTH ends' source: Xray-core's `GetNormalizedPath()` (`infra/conf/splithttp/config.go`) always appends a trailing slash before `hub.go`'s prefix match; sing-box-lx's `auto`+REALITY resolves to `stream-one` (matching genuine Xray client behavior per their own `SPECS/011-XHTTP_STREAM_ONE_DOWNLINK` fix), sending the BARE path with NO trailing slash. A path without one is always shorter than the server's normalized match target → guaranteed 404 on every request. Fixed by appending `/` to every rendered occurrence (server inbound, client outbound, share-link). **Live-verified end-to-end same day**: `systemctl is-active xray` = active on `is`; real phone connection (main-brat, via the VPNRouter client) over a RU mobile network — conntrack shows an ESTABLISHED/ASSURED TCP session with 2.2MB sent / 194KB received (real payload, not a handshake-only blip), Xray's own access log attributes each destination to `email: main-brat` (per-user attribution works for xhttp, not just sing-box protocols), traffic includes `youtube.com`/`googlevideo.com` (throttled in RU since 2024) and `2ip.ru`/`2ip.io` (exit-IP checkers) — strong evidence of a deliberate "does this actually reach a blocked resource" test, not a synthetic probe. Closes acceptance criteria 1 (service active) and 2 (real client connects, RU handshake) from the original spec (`plans/xray-xhttp.md`). **Deferred, by design, not a gap**: subscription delivery (`vless://…type=xhttp` into `/sub`/`/api/v1/app/config`) — handshake confirmation was the gate, per the spec; a follow-up phase. **Separately diagnosed, NOT a vpnctl bug**: the same live-test session surfaced an AWG report (client dev) of "handshake works, no payload" on `is`/`de` — full read-only diagnosis (ip_forward, FORWARD/NAT, conntrack ESTABLISHED rules) showed BOTH nodes correctly configured; the real cause was `main-brat`'s out-of-band `awg://` link from 2026-06-28 going stale after later grants shifted the index-based octet assignment (`peer_octet_in_slash24`) — exactly the risk the AWG2 phase's own memory flagged ("only a never-re-pulled one-shot link goes stale"). Confirmed by recomputing the live octet ranking from `grants`/`users` and matching it 1:1 against `awg show` on both nodes. Fix is operational (re-issue a fresh link), not code — flagged in Known gaps below as a recurring UX risk worth a future stable-addressing pass. || **BB-1** | **Boosty→VPN subscription bridge — access follows the subscription** | ✅ code shipped 2026-07-10 (PR #111); prod rollout = goal-doc phase 5 | Павел продаёт VPN как Boosty-подписку; мост замыкает петлю «оплата ↔ доступ». New crate `crates/boosty-bridge`: pure `reconcile()` (только LINKED-пользователи достижимы — структурный инвариант) + `sync_once` оркестрация над операторским форком `boosty_api` (git-pin на hardening-rev `ee204ec`: обрезка тела refresh-ошибки — токен не эхается в логи/HTML; `encode_segment` для blog-slug). Migration 0040: `users.boosty_subscriber_id` (partial-UNIQUE) + singleton `boosty_settings` (креды = СЕКРЕТЫ: маска `••••<last4>`, никогда в audit; + `last_report_json`/`last_sync_at`). Поллер `boosty_sync_poller.rs`: дефолт EnableOnly («auto-provision, disable on a button»), `auto_disable_lapsed` opt-in; `enabled` перечитывается на каждом тике. **Флипы реальные:** каждый применённый enable/disable редеплоит серверы затронутых пользователей через общий `wizard_bootstrap::redeploy_servers_collect_errors` (per-server DeployGuard + lock-retry + missing-key guard; выделен из `spawn_user_servers_redeploy` — у бриджевой копии не было retry) + один summary-audit `boosty.autodeploy`; `servers_pending_deploy_for_user` знает `boosty.enable/disable`. **Живучесть auth:** Boosty ротирует refresh-токен на каждом refresh, а каждый проход рефрешится → ротированный токен персистится ДО проброса ошибки синка (упавший после auth fetch раньше НАВСЕГДА убивал мост — invalid_grant до ручной перевыдачи кредов); reqwest-клиент с таймаутами 10s/30s (refresh держит auth-мьютекс клиента — зависший коннект замораживал поллер и /admin/boosty навечно); refresh-flow приоритетнее static access-токена (тот живёт ~час). **Fail-safe:** ошибка API = ноль записей (тест); ПУСТОЙ ростер подавляет все disable (`suppressed_disables` — опечатка в blog_url ≠ отключение всего флота). **Наблюдаемость:** алерт `boosty.sync.failed` (дедуп открытого, auto-ack на восстановлении) + двуязычный Telegram-push; auth-смерть называет веб-поверхность /admin/boosty (не SSH); payload на строке алерта — /admin/alerts рендерит тот же auth/transient сплит. **GET без побочек:** /admin/boosty рендерит из последнего ПРИМЕНЁННОГО отчёта (не живой синк на GET — csrf-контракт + гонка ротации с поллером). CLI `vpnctl boosty {sync,link,unlink,status,configure}` (sync dry-run по умолчанию, `--apply` печатает `vpnctl deploy <id>` для затронутых серверов). Review-agent: 0 crit / 4 important (все пофикшены) / 7 minor (m2/m3/m5/m6/m7/m11 пофикшены; отложено: дедуп mask-хелперов, CLI-секреты через stdin). Goal-док с критериями приёмки: `docs/GOAL_BOOSTY_BRIDGE.md`. Открытые продуктовые вопросы (§7 goal-дока): все ли уровни подписки дают VPN (сейчас — любой активный), когда включать `auto_disable_lapsed` на проде (рекомендация: после недели EnableOnly). |

### Known gaps / backlog (post-2026-06-01 multi-agent bug-scout)

A 4-agent read-only scout (deploy-parity · sub-render · auth/rate-limit ·
alert state-machine) ran 2026-06-01. The two HIGH findings shipped (RL-1,
AL-1). Open items, ranked, for a future session:

- **IMPORTANT — web-deploy doesn't provision the node cert.**
  `/etc/sing-box/cert.pem` (needed by tuic-v5 / hysteria2 / trojan / anytls
  inbounds) is generated ONLY by the CLI path (`cli/src/cmd/deploy.rs`,
  `openssl req -x509`); the web/wizard deploy never creates it → those
  protocols crash-loop sing-box on a web-deployed node. Latent today
  (de/fi/is/nl were CLI/migrated + have the cert; kg serves vless-only).
  Fix: move cert-gen into the sing-box kernel `ensure_installed`/`apply_config`
  so BOTH paths provision it idempotently. Caught on kg 2026-05-30.
- **IMPORTANT — fail2ban never installed by any deploy path** despite the
  add-server wizard UI promising it + `health_monitor` alerting on
  `server.fail2ban.down`. NEEDS VERIFICATION first (kg showed fail2ban
  active after a reboot — the recycled box may have had it pre-installed).
  If confirmed, add a harden step to the kernel `ensure_installed` /
  bootstrap (same fix surface as the cert gap above).
- ~~**MINOR — amneziawg H1-H4 / Jc obfs params not randomised per-server**~~
  — **CLOSED**, see the AWG2 phase (PR #73, `crypto::gen_amnezia_obfs()`).
  Re-verified live 2026-07-01 during the XH-1 diagnosis: `is` and `de`
  carry genuinely distinct per-server params (`is`: jc=4/h1=65577653...;
  `de`: jc=7/h1=1707807384...) via `awg show`. This entry was stale —
  AWG2 shipped after it was written and never got removed here.
- **MINOR — geoip «update now» SSE is a state-changing GET** that bypasses
  the POST-only Origin CSRF middleware (only a soft `Sec-Fetch-Site` check,
  skipped when the header is absent). Idempotent → low impact; make it a
  POST or hard-require Sec-Fetch-Site.
- **MINOR — trojan `share_link` uses the raw server IP as `sni=`**
  (effectively empty-SNI; NM-12 already tags trojan Weak). Use a
  configurable `trojan.sni` cover-domain secret with a sane default.
- **MINOR — `resolve_real_ip` leftmost-XFF is client-spoofable** behind the
  appending nginx (`$proxy_add_x_forwarded_for`). No longer
  security-critical after RL-1 (rate-limit + egress decision now use the
  spoof-proof `resolve_peer_real_ip`/`X-Real-IP`). Residual: the LOGGED IP
  (`sub_access_log`) + the legacy `/sub` per-IP bucket still trust the
  spoofable leftmost → IP-based abuse intelligence (geo, /16-clustering)
  can be poisoned. Fix = read `X-Real-IP` (or rightmost-XFF) globally;
  deferred because it changes the established logged-IP semantics.
- **MINOR — AWG/WireGuard octet assignment drifts with unrelated grant
  changes, silently staling out-of-band links.** `peer_octet_in_slash24`
  (`crates/protocols/src/wg_addressing.rs`) assigns `10.66.0.<2+index>`
  by a user's POSITION in the server's full granted-user list (`ORDER BY
  id`, any protocol) — adding/removing ANY grant on that server shifts
  every later user's octet. A polling subscription self-heals (octet
  recomputed every render); a one-shot `awg://` handed out manually does
  NOT — the server's `AllowedIPs` for that peer moves on, the cached
  client config doesn't, and WireGuard silently drops payload from a
  source IP outside the peer's configured `/32` (handshake still
  succeeds — auth is by pubkey — so the failure LOOKS like a forwarding
  bug, not a stale link). Hit live 2026-07-01: `main-brat`'s 2026-06-28
  out-of-band link (`vpnctl-awg2-singbox-lx` memory) was `.22`/`.23` on
  `is`/`de`; by 2026-07-01 the live peers had moved to `.23`/`.24`,
  costing a full read-only diagnosis (ip_forward/FORWARD/NAT/conntrack
  on both nodes, all correctly configured) before the real cause
  surfaced. No code fix shipped — re-issuing a fresh link works today.
  If this recurs, consider either a STABLE per-(user, server) octet
  (persisted at first grant, not recomputed by position) or an
  admin-UI nudge on the Flow F/D cards ("link may be stale, regenerate
  if payload doesn't flow").

### Three-layer visibility model (abuse detection)

The admin needs to spot abuse — primarily a subscription URL that's
been shared past one human, secondarily a single client racking up
unreasonable traffic. Three independent surfaces, each catches a
different bug class:

| Layer | Source | What it catches | What it misses | Cost to add |
|---|---|---|---|---|
| **1. /sub fetch log** | vpnctld access log → `sub_access_log` table | URL leaked / shared (many ASNs hitting one user's URL); scrapers pulling on a tight loop; UA-based "what client are they on" fingerprint | Real-time connections (clients re-fetch only periodically); device count behind NAT | LOW — Track-1, ✅ shipped |
| **2. VPN protocol stats** | sing-box `clash-api` on each node, polled by vpnctld via SSH | active connections, traffic up/down, per-user real-time | Same NAT problem; needs SSH polling overhead; new column in deploy | MEDIUM — Track-3, planned after E (wizard touches deploy anyway) |
| **3. UA fingerprint** | UA strings + IP+time+ASN clustering on Layer-1 data | Approximate "is this the same physical device roaming vs is this many devices sharing the URL" | Never exact — NAT collapses devices; clients with no UA are invisible | LOW — Track-4, low priority |

A device count **behind NAT** is roughly impossible from the server
side without client cooperation. Track-4 is the best we can do.

When making non-trivial design decisions, re-read this section first
and check the choice doesn't quietly bake in an assumption that
contradicts a confirmed answer above.

## Multi-session conventions (BLOCKING — общее дерево, несколько сессий)

Pavel работает из **нескольких параллельных сессий Claude** в одном и
том же рабочем дереве `/home/user/vpn-control/vpnctl`. У каждой сессии
свои таски, ветки и uncommitted-файлы. Правила, чтобы сессии не топтали
друг друга (введены 2026-06-10 после инцидента: сессия закоммитила фикс
на чужую ветку `feat/server-delete`, предположив, что дерево на main):

1. **`git branch --show-current` ПЕРЕД каждым коммитом.** Другая сессия
   могла переключить дерево в любой момент. Никогда не предполагай main —
   даже если в начале твоей сессии это был main.
2. **Stage только свои файлы.** Никогда `git add -A` / `git add .` — в
   дереве почти всегда чужие uncommitted-правки. `git status --short`
   перед коммитом; чужие `M`/`??` файлы не стейджить и не «чинить».
3. **Не трогать чужое состояние.** Никаких `reset --hard` / `checkout` /
   `stash` / `clean`, затрагивающих не-свои файлы или ветку другой
   сессии. Если свой коммит попал на чужую ветку: `git worktree add` от
   main → `cherry-pick <sha>` → на чужой ветке `git reset --keep
   <sha>~1` (`--keep`, НЕ `--hard` — `--hard` снесёт чужие uncommitted
   tracked-правки).
4. **Работа для main — через свой worktree** (`git worktree add
   /tmp/vpnctl-<topic> main`), а не через переключение общего дерева.
   `git worktree list` показывает занятые. Гочи: `cargo zigbuild` в
   worktree требует СВОЙ `target/` (с `CARGO_TARGET_DIR` на общий target
   падает с «cannot find binary path»); следи за диском (`just gc`).
5. **Деплой на 192.168.0.236 — ТОЛЬКО из main (CI green).** Прод-демон
   один: деплой из feature-ветки перезапишет бинарь и потеряет фиксы
   других сессий. Перед деплоем — бэкап текущего бинаря
   (`sudo cp -a /opt/vpnctl/vpnctld /opt/vpnctl/vpnctld.bak-<метка>`).
   Если Pavel явно пишет «устанавливай», «выкладывай» или «деплой»,
   это означает полный цикл: PR → зелёный CI → merge в main → backup →
   production install → systemd/health/UI verification. Локальный commit
   или merge без live-проверки нельзя называть «готово».
6. **После `git pull` перепроверь ветку** (п.1): pull на чужой ветке
   тянет её upstream, не main — «Merge … into <branch>» в выводе pull
   это красный флаг, что ты не на main.

## Workflow rules (BLOCKING — must run before every commit)

Эти правила — про то, как мы (Pavel + Claude) разрабатываем `vpnctl`.
Они **обязательны** для каждой feature/refactor/fix. Хук в
`.claude/settings.json` ловит `git commit` и напоминает, если шаги
пропущены.

### Перед коммитом (после написания/правки кода)

1. **Review-agent** — независимая проверка через `Agent` (subagent_type =
   `general-purpose`), prompt из шаблона ниже. Агент не видит мой
   reasoning, только diff. Возвращает JSON списка findings. Я обрабатываю
   `critical` и `important` (фиксы), `minor` — opt-in.

2. **Test-writer-agent** — для **новой публичной функции/API** запускаю
   через `Agent` (`general-purpose`) с prompt'ом, содержащим **только
   спеку** (signatures + behavior contract), **без реализации**. Агент
   пишет тесты в отдельный файл (`tests/spec_*.rs` или
   `#[cfg(test)] mod spec_*`). Прогоняю их у себя. Тесты которые падают
   = либо bug в реализации (фиксим), либо неверная спека (правим спеку
   и регенерим тесты).

3. **Локальные gates**: `just ci` (fmt-check + clippy -D warnings + test
   + deny). Без зелёного — коммит не делать.

   **Особое внимание `cargo fmt --check`** — самый частый CI-killer
   в текущей сессии. Сценарии, которые НЕ выглядят как «надо
   проверить fmt», но всё равно требуют его:

   * **Тесты от test-writer-agent** — агент пишет код «как удобно»
     (длинные строки, custom multi-line layout); rustfmt их обычно
     перепаковывает. Caught 2026-05-18: spec_admin_alerts.rs
     слетел в CI на cbb4d41.
   * **Mass-replace через Python/sed скрипт** — мой собственный
     `error_helper_migrate.py` оставил indent drift, который
     rustfmt бы переписал. Если только cargo build + clippy
     зелёные — этого мало; `cargo fmt --check` тоже обязателен.
   * **Любой commit с ≥2 файлами правок** — увеличивает шанс что
     rustfmt захочет переупаковать какой-то блок.

   Дешевле всего: запускать `cargo fmt --all` (НЕ только `--check`)
   ДО прогона тестов — fmt всё равно нужен, и если что-то меняется
   локально, лучше сразу включить в тот же коммит, а не получить
   отдельный «fmt-only» hotfix.

### После push

4. `gh run watch <id> --exit-status` — блокируюсь до конца CI.
   Если красное → `gh run view --log-failed` → fix → push повтор.

   **НЕ коммитить новый код поверх нерезолвенного red CI.** Audit
   2026-05-18 (после 11-коммитной сессии) показал 4 коммита landed
   atop unresolved red — pushed без CI watch. Это копит «long fix-
   trail» как `818bad2 → 0310ad0` где fmt-fail из 5 коммитов
   собрался в один hotfix задним числом. Правило: если предыдущий
   commit на main НЕ green → следующий commit это либо hotfix для
   него, либо ждём.

## Server invariant — deploy-key authorization (post-2026-05-20)

**Hard invariant** (confirmed by Pavel 2026-05-20):

  **Every server visible in `/admin/servers` MUST have vpnctld's
  deploy pubkey in its `root@<host>:~/.ssh/authorized_keys`.**

The pubkey is:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGeysXLLw9o1GtUjYUbxuA/D3A9RSDo1y+aZOstAkIja vpnctld-deploy
```

Live on 236 at `/var/lib/vpnctl/.ssh/id_ed25519` (private)
+ `.pub` (public). Read via `sudo cat`.

### Why this matters

Without the key, `vpnctl deploy <server>` fails silently in the
exact failure mode caught 2026-05-20: a grant added in inv.db
(`INSERT INTO grants(user_id, server_id) …`) is visible to the
ninitux endpoint immediately (`/api/v1/app/config/<device_id>`
emits a vless URI for the server) — but the sing-box config on
the server is never updated → user's UUID is not in
`vless-in.users[]` → Reality TLS handshake succeeds → VLESS auth
rejects unknown UUID → client connection drops with no useful
diagnostic.

This is the same shape of silent-failure as DG-1
(`SingBox::apply_config` users[] diff guard), just one layer
earlier: DG-1 catches *removals* at apply-time, but a server
that vpnctld can't reach gets NO apply-time at all.

### When adding a new server

The wizard flow (Phase E) already pushes the deploy key as
step 1 of bootstrap. For servers added by any OTHER path —
bash-migrate import, manual `vpnctl server add`, hand-INSERT
into inv.db — the key MUST be pushed before any user grants are
made visible. Otherwise the operator's first sign that the
deploy doesn't reach is a confused user reporting "URL appears in
my app but doesn't connect".

### When auditing existing servers

```bash
ssh user@192.168.0.236 \
  "sudo cat /var/lib/vpnctl/.ssh/id_ed25519.pub" \
  | tee /tmp/vpnctld-deploy.pub

# For each server in `vpnctl server list` (or
# `sudo sqlite3 /var/lib/vpnctl/inv.db 'SELECT id, address, ssh_port, ssh_user FROM servers'`)
# probe with vpnctld's key:
ssh -i /var/lib/vpnctl/.ssh/id_ed25519 -o BatchMode=yes \
    -p <port> <ssh_user>@<address> "hostname"
# success → key already authorized.
# `Permission denied (publickey)` → key NOT present; push it.
```

### Push procedure (when claude-chat key is authorized)

```bash
PUB=$(ssh user@192.168.0.236 "sudo cat /var/lib/vpnctl/.ssh/id_ed25519.pub")
ssh root@<server> "grep -qxF '$PUB' ~/.ssh/authorized_keys || echo '$PUB' >> ~/.ssh/authorized_keys"
```

(The `grep -qxF` makes the push idempotent — running twice
doesn't duplicate the line.)

### When the operator can't be SSH'd to either

If neither vpnctld's key nor the operator's recovery key
(`claude-chat`) works, the daemon is locked out of that node.
Per the operator-action policy below, the error message MUST
acknowledge this and point at the hoster's serial console /
KVM — NOT instruct the operator to SSH from elsewhere (if the
operator could SSH, the daemon could too via the same path).

### Future runtime enforcement (deferred)

A dashboard alert `server.deploy_key_missing` (Phase G-2) would
catch this at probe-time: vpnctld's node_probe SSH attempt
returns `Permission denied (publickey)` → fire a critical alert.
Storage + state-machine already exist (`admin_alerts` table,
Phase G chunk 1); just needs the probe classifier to recognise
this specific error string. Caught 2026-05-20 on the `stg` host
(84.19.3.104).

## Operator-action policy (post-2026-05-18)

Pavel: «не должен просить меня сделать что-то вручную на серверах».
Strict reading: **error messages, alerts, doc-comments, and UI
copy MUST NOT instruct the operator to SSH anywhere**. The daemon
either does the action itself (via reference key / sshpass / its
own SSH transport), surfaces a web button that does it, OR — when
truly impossible (e.g. daemon banned, no peer server to relay
through) — explicitly says «daemon can't help, use hoster's
serial console / KVM».

Forbidden patterns in operator-facing output:
  * `ssh root@<host>` followed by a shell command — say «click X
    button on /admin/Y» instead
  * `echo '<paste>' >> ~/.ssh/authorized_keys` — replace with «push
    deploy key» button reference
  * `cat /etc/<file>` / `journalctl …` / `systemctl …` — these
    leak the operator-must-shell mental model. Acceptable only in
    audit_log payloads + dev-facing doc-comments, never in 4xx/5xx
    response bodies or admin HTML copy.

Caught 2026-05-18 — 3 violations in `alert_sink::classify_ssh_failure`,
`/admin/settings` Deploy SSH key section, and the
`server.fail2ban.banned_self` alert payload. All three fixed in
the same commit + a unit test pins the new contract
(`classify_ssh_failure_recognises_permission_denied` asserts
`!msg.contains(">> ~/.ssh/authorized_keys")`).

For the genuinely-out-of-band case (fail2ban banned the daemon's
own outbound IP — by definition daemon can't unban itself), the
message MUST acknowledge «daemon is locked out and can't self-
recover» + point at the hoster's console. NOT ask the operator
to SSH from elsewhere, because if THEY could SSH the daemon could
too via the same path.

### Когда правила можно сократить

- **Чисто docs/README/CLAUDE.md правки** — пункты 1-2 пропускаем,
  пункт 3 (`just ci`) обязателен (fmt-check всё равно).
- **Hotfix** — review-agent можно пропустить ТОЛЬКО если ВСЕ ТРИ
  условия выполнены одновременно:
  1. impl ≤ 5 строк,
  2. изменение трогает РОВНО ОДИН surface (не 3 sympathy edit'а как
     в db3998c: server_inbound + client_config + share_link),
  3. изменение НЕ меняет ни один output, который запинен
     byte-equality тестом (`*_byte_equal*`).

  Уточнено 2026-05-16 после methodology check session: db3998c
  формально проходил по строке 1, но завалил 2 и 3, и review-agent
  retroactively нашёл 4 important findings (3064903).

### gh run watch — НЕ optional (правило #4 выше)

После каждого `git push` обязателен `gh run watch <id> --exit-status`
ЛИБО до конца текущего conversation turn, ЛИБО при batch-серии —
для head-коммита. Если CI красное → `gh run view --log-failed` →
fix → push. Пропуск `watch` ≠ методология; красные CI просто
сидят незамеченными.

Caught 2026-05-16: `4d7ad63` flake-fail просидел ~50 минут без
обнаружения, пока Pavel не попросил «проверь методологию» —
тогда `gh run list` показал red и я пофиксил в `7040a0c`.

### Protocol / Kernel / handler fix → vpnctld redeploy обязателен

Изменение в `crates/protocols/`, `crates/kernels/`, или
`daemon/src/handlers/` меняет поведение **только** после redeploy
бинаря на 192.168.0.236. Локальный `cargo test` пройдёт зелёно,
CI пройдёт зелёно, но `/sub/<token>` (и любой live endpoint) будет
продолжать отдавать **старые** байты пока vpnctld не пересобран и
рестартован. Делать в той же сессии:

```bash
# Daemon + CLI from the SAME revision — installing only vpnctld used to
# leave /usr/local/bin/vpnctl stale, which broke the weekly kernel updater
# (old CLI migrations lagging the live DB).
# Export the SHA BEFORE building so the binaries report `<semver>+<sha>`
# (vpnctl_core::build_version reads VPNCTL_BUILD_SHA at compile time).
export VPNCTL_BUILD_SHA=$(git rev-parse --short HEAD)
cargo build --release -p vpnctld -p vpnctl
scp target/release/vpnctld target/release/vpnctl scripts/deploy.sh \
  user@192.168.0.236:/tmp/
# scripts/deploy.sh installs BOTH atomically (temp file + rename), so a
# failed copy can never leave a partial executable nor a stale CLI.
ssh user@192.168.0.236 'sudo /tmp/deploy.sh /tmp/vpnctld /tmp/vpnctl && \
  rm -f /tmp/vpnctld /tmp/vpnctl /tmp/deploy.sh && \
  sudo systemctl restart vpnctld'
# Verify the new behaviour with a curl that exercises the changed code path.
```

Caught 2026-05-16: db3998c пофиксил VLESS flow в коде, но
`/sub/<token>` на 236 ещё ~25 минут возвращал outbound без flow,
потому что бинарь был от 11:28 UTC (до фикса). После redeploy
`/sub/<tester-token>` сразу начал возвращать `flow: 'xtls-rprx-vision'`
— fix landed end-to-end.

## Agent prompt templates

Тексты ниже — копировать целиком в `Agent.prompt`, подставив `{...}`.

### `review-agent` prompt template

```
You are an independent code reviewer for the vpnctl Rust workspace
(github.com/PavelLizunov/vpnctl). You haven't seen the design discussion,
only the diff below.

Architectural invariants (cannot be violated):
- Kernel × Protocol orthogonality: adding a new kernel (wgturn, xray) or
  protocol (Hysteria2, WireGuard) must NOT require touching CLI, inventory,
  SSH or crypto crates.
- Protocols are STATELESS; per-server secrets arrive via RenderCtx.
- Inventory write paths must be auditable (audit_log row per mutation).
- No `unwrap()` / `expect()` / `panic!()` outside `#[cfg(test)]`.
- No `unsafe`. No `openssl-sys` / `native-tls`.

Files changed: {file list from `git diff --name-only HEAD~N..HEAD`}
Diff: {git diff HEAD~N..HEAD}

Find issues. Categories, in priority order:
1. CORRECTNESS: bugs, off-by-one, wrong error mapping, swallowed errors,
   race conditions, resource leaks, command injection in any exec(),
   path traversal in upload()/read_file(), unhandled panics.
2. ARCHITECTURE: violations of the invariants above; tight coupling;
   stateful things that should be stateless.
3. SECURITY: secrets logged to stdout/audit payload; missing host-key
   verification path; weak randomness; permission/visibility leaks.
4. DUPLICATION across codebase: for every new function ≥ 20 lines in
   the diff, search the whole repo for similar implementations (grep
   for 3-4 distinctive identifiers or library calls from the body —
   e.g. if the function calls `Command::new("ssh-keyscan")`, grep for
   that string in `**/*.rs` outside the diff). Report HIGH severity
   if a near-duplicate exists; the fix is "extract to shared helper",
   not "inline both copies". (this would have caught the ssh-keyscan
   triplication on 2026-05-17)
5. TEST COVERAGE: a new public function with no test for its error path;
   tests that would pass even if the implementation was inverted.
6. LIBRARY MISUSE: anything that goes against russh / sqlx / tokio /
   clap official patterns (cite the doc if you reference it).

Output ≤300 words as a single JSON array:
[{"severity":"critical|important|minor",
  "file":"crates/.../foo.rs:42",
  "issue":"one-line description",
  "fix":"concrete change, ≤2 sentences"}]

DO NOT comment on:
- style / formatting (rustfmt handles it)
- doc completeness
- naming preferences (unless objectively confusing)
- micro-optimisations
```

### `test-writer-agent` prompt template

```
You are writing Rust tests for vpnctl, INDEPENDENT of the implementation.

CRITICAL: You have NOT seen the implementation source. Only the spec
below. If a test fails when run, that means the implementation is wrong
or the spec is ambiguous — DO NOT weaken the test to make it pass.

Crate under test: {crate name, e.g. vpnctl-inventory}
Cargo manifest deps you may use: {list, e.g. tokio, tempfile, serde_json}

Public API spec (verbatim signatures + behavior):
{paste signatures + per-function "must" rules; no impl, no internal
 helpers; if there are invariants — list them}

Behavior contract (rules every test must verify):
{e.g. "WAL journal mode is enforced after open()",
      "FK CASCADE removes grants when their user is deleted",
      "duplicate add_server returns AlreadyExists, not generic sqlx error"}

Write to {path, e.g. crates/inventory/tests/spec_inventory.rs}. Constraints:
- Each test has its own tempdir / fresh state.
- Test names describe the spec rule being checked.
- ≤300 lines total.
- Use `#[allow(clippy::unwrap_used, clippy::expect_used)]` on the test
  module (workspace lints forbid them in non-test code; tests can use
  them for setup).
- Cover at least: happy path, ONE expected-failure path, one boundary
  edge case per function.
- DO NOT add tests that just call the function and assert "no panic".
  Every test must check observable behavior against the spec.
```

### Lessons from the first real staging deploy (84.19.3.104, Debian 12)

`vpnctl bootstrap stg ... && vpnctl deploy stg` worked end-to-end after
**three** fixes that ONLY surfaced on a live node — not via review-agent
or test-writer-agent. This empirically validates the three-layer
methodology (review → spec-tests → live-staging) all together; cutting
any layer would have shipped this bug-class.

| # | Surface | What live caught | Fix |
|---|---|---|---|
| 1 | `kernels::sing_box::ensure_installed` | Minimal Debian 12 has no `curl` / `gpg` / `ca-certificates` — exec exit=127 «curl: команда не найдена». | apt-install prerequisites first; `set -eu`; `command -v sing-box` final assertion. |
| 2 | `kernels::sing_box::ensure_installed` | sing-box service crash-loops with «open /var/log/sing-box.log: permission denied» — same gotcha that's in the old vpn-control HANDBOOK. | `install -o sing-box -g sing-box -m 0640 /dev/null /var/log/sing-box.log`; recursive chown of `/etc/sing-box`. |
| 3 | `kernels::sing_box::apply_config` | `systemctl reload-or-restart` returns 0 even when the service immediately exits — deploy reports «complete» while sing-box crash-loops. Silent failure = worst kind. | After restart, poll `systemctl is-active` for up to 8 s; on failure, dump `journalctl -u sing-box -n 20` to stderr and exit 1. |

Takeaway: review/test-writer cover **bugs in code logic**; live-staging
covers **assumptions about the environment**. Both layers are required.

### Methodology for the admin SITE (six layers, post-Phase-C-2)

Phase C-2 surfaced bug classes the original three-layer
(review / spec-tests / live-deploy) workflow could not catch on
HTML-rendering code paths. The site stack now uses **six layers**,
each catching a strict subset of issues that the others miss:

| # | Layer | What it catches | What it misses |
|---|---|---|---|
| 1 | `cargo clippy --workspace --all-targets -D warnings` | API misuse, dead code, unwrap/expect/panic outside tests | Anything CSS-only or HTML-string-only |
| 2 | `cargo test --test admin_smoke` (currently 34 tests) | DOM presence, classes, routing, status codes, escaping, masking | Floating panels overlapping content, grid overflow, font-rendering issues |
| 3 | **Copy-contract tests** (subset of admin_smoke) | Backend response prefix drift, headline / deck / empty-state copy regressions | Style of NEW copy that was never pinned (additive — pin it) |
| 4 | review-agent | Logic bugs, security issues, library misuse | Whether the page actually *renders* well |
| 5 | Live-deploy + curl on `192.168.0.236` | runtime + auth + DB integration | Visual layout (curl never paints) |
| 6 | **`scripts/visual_check.py`** (headless Chrome over CDP) | Floating panel overlap, grid overflow, font fallback, anything pixels-related | Cross-browser quirks (we render only on homelab Chromium) |

Phase C-2 evidence — bugs each new layer caught that no other would:

| Bug | Caught by |
|---|---|
| Tweaks panel covered the page footer on every page | layer 6 (visual screenshot) — invisible to layers 1-5 |
| Inline `tweaks live →` indicator duplicated panel state | layer 6 — DOM-test was happy |
| SHA256 fingerprint overflowed `.ed-server__meta dd` | layer 6 — content was correct, just escaped its column |
| Backend errors used 4 different prefixes | layer 3 (copy-contract) — pre-existing inconsistency invisible to all live curl tests because each was tested in isolation |
| `auth required` had no `vpnctl admin:` prefix | layer 3 |
| Favicon missing → blank browser tab | layer 3 — would be invisible to layer 6 because Chrome shows a default square; only the explicit test caught it |

#### Run order for any user-visible UI change

```bash
# 1. Static checks (fast, runs in CI)
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p vpnctld --test admin_smoke

# 2. Live deploy to homelab (daemon + CLI binaries, then CSS + favicon)
#    Build daemon + CLI from the SAME revision; scripts/deploy.sh installs
#    both atomically so /usr/local/bin/vpnctl never lags /opt/vpnctl/vpnctld.
#    Export the SHA first so the binaries carry `<semver>+<sha>` provenance.
export VPNCTL_BUILD_SHA=$(git rev-parse --short HEAD)
cargo build --release -p vpnctld -p vpnctl
scp target/release/vpnctld target/release/vpnctl scripts/deploy.sh \
  user@192.168.0.236:/tmp/
scp daemon/assets/{admin.css,favicon.svg} user@192.168.0.236:/tmp/
ssh user@192.168.0.236 '
  sudo /tmp/deploy.sh /tmp/vpnctld /tmp/vpnctl &&
  sudo install -o root -g root -m 0644 /tmp/admin.css /opt/vpnctl/assets/admin.css &&
  sudo install -o root -g root -m 0644 /tmp/favicon.svg /opt/vpnctl/assets/favicon.svg &&
  rm -f /tmp/vpnctld /tmp/vpnctl /tmp/deploy.sh &&
  sudo systemctl restart vpnctld'

# 3. Backend copy contract — confirm error responses match the prefix
ADMIN_PW=$(grep VPNCTLD_ADMIN_PASSWORD inventory/vpnctld-192.168.0.236.env | cut -d= -f2)
curl -sS -u "slovn:${ADMIN_PW}" http://192.168.0.236:18402/admin/users/no-such
# Expect: vpnctl admin: no such user 'no-such'

# 4. Visual gate — PNG of every page that changed
python3 scripts/visual_check.py http://192.168.0.236:18402/admin/users \
    /tmp/users.png "slovn:${ADMIN_PW}"
python3 scripts/visual_check.py http://192.168.0.236:18402/admin/users \
    /tmp/users-collapsed.png "slovn:${ADMIN_PW}" "vpnctl_tweaks=closed"

# 5. Read /tmp/*.png with the Read tool — actual eyeballs on the diff.
```

#### Backend / frontend copy contract

**Backend:** every response body in the `/admin/*` tree starts with
`vpnctl admin: `, ends with a single `\n`, and (where applicable)
includes the offending value + the allowed alternatives so the
operator can fix the request without consulting source. The
`error_text()` helper in `daemon/src/handlers/admin.rs` is the single
source of truth; auth.rs duplicates the literal prefix because the
basic-auth layer runs before the admin module is reachable. Tests in
`admin_backend_error_responses_use_unified_prefix` pin the four
canonical strings (404 user, 401 auth, 400 invalid value, 404 unknown
tweak kind).

**Frontend:** the editorial voice is sentence-case with em-dashes and
mono-font CLI commands inline (`span.ed-mono { "vpnctl user create" }`).
Every empty state must quote a literal CLI command (operators CAN'T
yet create users / servers via the web — losing the command would
strand them). `admin_frontend_section_headlines_match_voice` and
`admin_empty_states_quote_cli_commands` are the regression net. When
adding a new screen: first write the headline + deck strings, then
**add a copy-contract test for them in the same commit** so future
edits surface in code review.

#### Where MCP servers fit

We have three MCP servers wired (when their connections are healthy);
each is useful at a different point in the loop:

- **context7** — `mcp__context7__query-docs` / `resolve-library-id`.
  Use when the diff touches a dependency's API surface (axum upgrade,
  `qrcode` crate options, maud's `PreEscaped` semantics) or before
  picking a new dep. Cheaper and more current than guessing from
  training data — relevant for axum 0.8's path-param routing edge
  cases that bit us in Phase A.
- **sequential-thinking** — `mcp__sequential-thinking__sequentialthinking`.
  Use for layered layout / architecture decisions where the failure
  mode is "I picked the wrong abstraction". Phase C-2's CSS-Grid
  `justify-self: end` shrink-to-content gotcha would have been worth
  a sequential-thinking pass — instead it took two screenshot rounds
  to diagnose.
- **memory** — `mcp__memory__create_entities` etc. Use for
  cross-session state that genuinely doesn't fit in CLAUDE.md
  (e.g. a long-lived "copy catalog" mapping every user-facing string
  to its file:line + history of edits). For now CLAUDE.md is enough;
  re-evaluate when the admin UI grows past ~20 screens.

Headless Chrome runs at `http://192.168.0.142:9222` (homelab CDP
endpoint, exposed on the LAN). The script reuses the persistent tab,
disables the network cache, and accepts both basic-auth and a
synthetic Cookie header so collapsible / theme / accent states can be
captured without round-tripping through real cookie storage.

### Гочи методологии (lessons learned)

- **Hook input приходит на stdin, не в env var.** В `.claude/settings.json`
  читаем JSON через `python3 -c "..."` (или `jq`, если установлен — но в
  нашем dev-контейнере `jq` нет; `python3` есть всегда).
- **Settings watcher не подхватывает файлы созданные мид-сессии.** После
  любого редактирования `.claude/settings.json` нужно либо открыть UI
  `/hooks`, либо перезапустить Claude Code. Иначе хук молча игнорируется,
  даже если pipe-test зелёный.
- **Pipe-test обязателен** перед коммитом hook-а:
  `echo '{"tool_input":{"command":"git commit -m x"}}' | bash -c '<your cmd>'`
  должен вернуть ожидаемый вывод. Без этого силлентли break.
- **Sub-agents изолированы**: review-agent / test-writer-agent видят
  только то, что я кладу в `prompt`. Если я сошлюсь на «design discussion
  выше» — они не увидят. Brief как нового коллегу, paste'ить полный spec.

### Когда добавить новый kernel (wgturn, xray, hysteria-server)

Триггер: пользователь просит «добавь поддержку X».

Сценарий:

1. **Plan-agent** (`Agent`, `subagent_type=Plan`): «Design the file
   structure for adding kernel `X` such that no existing crate other
   than `crates/kernels/` and `cli/src/registry.rs` is touched.»
2. По плану создаю `crates/kernels/src/<x>.rs` + `pub use`.
3. `cli/src/registry.rs`: один `register_kernel`.
4. `inventory::server_secrets` — расширить конвенцию ключей (записать
   в CLAUDE.md и в doc-comment модуля).
5. Review + Test-writer — как обычно.



## Что это

Преемник bash-проекта `vpn-control`. Lightweight Linux-only CLI на Rust для
управления VPN-инфраструктурой (sing-box + расширяемые ядра/протоколы).
Цель — единственный статический musl-бинарник, без БД-сервера, без агента
на ноде, SSH-first.

## Где живёт проект (важно — GitHub-first)

| | |
|---|---|
| **Canonical home** | https://github.com/PavelLizunov/vpnctl |
| **Issues / PRs** | только на GitHub |
| **Primary CI** | GitHub Actions (`.github/workflows/ci.yml`) |
| **Mirror (LAN dev)** | http://192.168.0.207:18300/slovn/vpnctl (Forgejo) |
| **Mirror CI** | Forgejo Actions (`.forgejo/workflows/ci.yml`) — best-effort |

`origin` настроен так:
```
fetch  git@github.com:PavelLizunov/vpnctl.git
push   git@github.com:PavelLizunov/vpnctl.git              (GitHub, primary)
push   ssh://git@192.168.0.207:18222/slovn/vpnctl.git      (Forgejo, mirror)
```
`git push` улетает в оба. Если когда-то надо отключить mirror — просто
`git remote set-url --delete --push origin '.*forgejo.*'` (или удалить
конкретный URL).

## Архитектурный принцип (нельзя нарушать)

Два **независимых** trait-уровня:

| Trait | Что значит | Где живёт |
|---|---|---|
| `Kernel` | Демон на ноде, который держит соединения | `crates/kernels/src/` |
| `Protocol` | Wire-формат, предъявляемый клиенту | `crates/protocols/src/` |

`Kernel::supported_protocols()` декларирует, какие `Protocol` это ядро может
поднять. `Registry::validate_server` ловит несовместимости **до** SSH-сессии.

Добавление нового ядра (wgturn, xray, hysteria-server) или протокола
(WireGuard, Hysteria2, ShadowSocks-2022) **не требует правок** в `core`,
`ssh`, `crypto`, `inventory` или `cli` — только новый файл-модуль
+ одна строка регистрации в `cli/src/main.rs`.

## Структура

```
vpnctl/
├── Cargo.toml                workspace, edition 2024, MSRV 1.85
├── rust-toolchain.toml       pin: stable + clippy + rustfmt
├── deny.toml                 cargo-deny policy (no openssl-sys, no native-tls)
├── rustfmt.toml              edition 2024, max_width 100
├── justfile                  just check / test / clippy / fmt / ci / run
├── crates/
│   ├── core/                 типы + traits + Registry
│   ├── crypto/               UUID, x25519, password, short_id (3 unit tests)
│   ├── ssh/                  trait SshTransport + MockTransport (russh impl in v0.2)
│   ├── protocols/            impl Protocol — vless+reality, tuic-v5
│   ├── kernels/              impl Kernel — sing-box (полный)
│   └── inventory/            InMemoryInventory (sqlx+sqlite in v0.2)
└── cli/                      clap бинарь `vpnctl`, subcommands: uuid, registry
```

## Lints — централизованно

Все clippy/rustc lints в `[workspace.lints]` в корневом `Cargo.toml`. Каждый
крейт включает их через `[lints] workspace = true` в своём Cargo.toml.
**Не пиши** `#![deny(...)]` или `#![forbid(unsafe_code)]` в `lib.rs` — это
дублирование.

Запрещены:
- `unsafe_code` (forbid)
- `unwrap_used`, `expect_used`, `panic`, `dbg_macro` (deny)

## Типичные команды

```bash
just check       # cargo check --workspace --all-targets
just test        # cargo test --workspace
just clippy      # cargo clippy --workspace --all-targets -- -D warnings
just fmt         # rustfmt
just fmt-check   # CI-mode rustfmt
just deny        # cargo deny check
just audit       # cargo audit
just run uuid    # cargo run --bin vpnctl -- uuid
just ci          # fmt-check + clippy + test + deny — прогон до push
```

## CI

| Where | File | What it gates |
|---|---|---|
| **GitHub Actions (primary)** | `.github/workflows/ci.yml` | check + fmt + clippy -D warnings + test + `cargo deny` + `cargo audit` |
| Forgejo Actions (mirror) | `.forgejo/workflows/ci.yml` | то же без deny/audit, в `rust:1.85-slim-bookworm` |

Зелёный GitHub CI — обязательное условие для merge в main. Forgejo — best-effort.

## Грабли

### Контейнер claude-chat не персистентит `~/.cargo` и `~/.rustup`
При рестарте контейнера Rust-тулчейн исчезает. Восстанавливается через
`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal --component rust-analyzer`.
Решение на уровне инфры: добавить `~/.cargo` и `~/.rustup` в персистентные
volumes Docker compose (TODO для Pavel).

### Disk hygiene — `target/` забивает диск контейнера (40G)
Цикл build/zigbuild/test за сессию раздувает `vpnctl/target` до 10–14G;
диск claude-chat (40G) уходил за 70%, а cron/systemd в контейнере НЕТ,
так что чистить по таймеру нечем. Решение — в build-пайплайне:

```bash
just gc          # threshold-guarded: чистит target/ ТОЛЬКО если >8G
just gc 4        # свой порог в GB
just clean       # безусловный cargo clean
```

`just gc` — это prerequisite recipe для `just ci`, поэтому самый частый
pre-push прогон сам триммит раздутый target (тёплый кэш нормального
билда <8G не трогается). Логика в `scripts/clean-target.sh`; работает и
без cargo на PATH (fallback `rm -rf target`, что для места = `cargo
clean`). **Грабли деплоя:** prod-бинарь собирается через
`cargo zigbuild` (см. ниже) — это тоже копит артефакты в `target/`, так
что после серии деплоев гоняй `just gc` (или просто `just ci`).

### Mirror remote — см. секцию «Где живёт проект» выше
Один `git push` уходит в оба remote. Fetch — только из GitHub.

### Без C-линкера (`cc`) на хосте cargo install ничего не соберёт
В Dockerfile claude-chat теперь зашит `build-essential` (Pavel сделал
2026-05-13). Если попадёшь в окружение без cc — поставь
`apt-get install -y build-essential pkg-config libssl-dev` от рута.

### sqlx + DATABASE_URL
Когда добавим sqlx (v0.2 milestone), для CI нужен
`cargo sqlx prepare --workspace` локально + коммит `.sqlx/` директории +
`SQLX_OFFLINE=true` в CI env.

### `VPNCTLD_TRUSTED_PROXIES` **обязательная** переменная при reverse-proxy
**После Bundle 1 (2026-05-22, commit `f881ba9`, аудит I4)** — default
trusted-proxies список **пустой** (раньше был зашит `192.168.0.207`).
Если демон стоит за nginx / любым reverse-proxy, который терминирует
TLS и форвардит `X-Forwarded-For`, **обязательно** прописать в
`/etc/vpnctl/vpnctld.env`:

```
VPNCTLD_TRUSTED_PROXIES=<IP-проксика>[,<IP2>,...]
```

Иначе:
- `resolve_real_ip` будет игнорировать XFF → в `sub_access_log.ip`
  попадёт сам прокси (LAN RFC1918) вместо реального клиента;
- сработает `sub_access.suspicious_local_ip:<user>` warning **на каждый
  легитимный** /sub запрос → alert-fatigue, реальные сигналы хоронятся.

Случилось ровно так на проде 2026-05-23 после деплоя `f881ba9` (10
false-positive за 2 часа). Защита от повторения добавлена в
`access_log.rs::is_trusted_reverse_proxy` (commit `<this>`): даже если
operator забыл выставить переменную, детектор сам сверяется со списком
и не тревожит зря. **Но всё равно выставляй переменную явно** — без
неё клиентский IP в логах останется = IP прокси, и весь IP-based
intelligence (geolocation, abuse-detection, /16-clustering) ломается.

При поднятии второго инстанса `vpnctld` за nginx — первым делом
дописать `VPNCTLD_TRUSTED_PROXIES`. Проверить можно одной командой:
```
ssh user@<host> 'sudo grep VPNCTLD_TRUSTED_PROXIES /etc/vpnctl/vpnctld.env'
```

**ИНВАРИАНТ доверенного прокси (X-Real-IP) — post-2026-07-11 TT-0 review.**
Как только IP прокси попал в `VPNCTLD_TRUSTED_PROXIES`, `resolve_peer_real_ip`
(rate-limit + egress-exemption keying) начинает ДОВЕРЯТЬ заголовку `X-Real-IP`
от этого пира. Значит **каждый** `reverse_proxy`-блок на этом прокси, который
ходит на `vpnctld:18402`, ОБЯЗАН authoritatively выставлять
`header_up X-Real-IP {http.request.remote.host}` — иначе клиент подделает
`X-Real-IP: <ip-ноды>` и обойдёт per-IP лимит / заявит egress-exemption.
Defense-in-depth на `.210`: в начале `route {}` стоит `request_header -X-Real-IP`
(срезает клиентский заголовок ДО роутинга; только наши `header_up`-строки могут
его выставить), так что забытый `header_up` в будущем блоке не вернёт spoofing.
При добавлении нового прокси перед `vpnctld` — повторить оба: `header_up
X-Real-IP` на каждом vpnctld-блоке + site-level `request_header -X-Real-IP`.

## Связанные репо и серверы

- **Старый bash-проект `vpn-control`** — живёт пока только в локальном
  Forgejo (`slovn/vpn-control`). Там список production VPN серверов
  (`SERVERS.md`), inventory с секретами (`inventory/<IP>.env`, не коммитить!),
  и SSH-ключ `claude-dev` (`/home/user/.ssh/id_ed25519`,
  НЕ `/home/appuser/.ssh/`). Если миграция на vpnctl завершится успешно,
  старый репо уйдёт в archive.
- **Production VPN серверы** — пока не трогаем, миграция на vpnctl будет
  только когда v0.2 пройдёт интеграционный тест на staging.

## Live-deploy `vpnctld` на homelab (LAN + Tailscale)

`vpnctld` (admin UI + `/sub/<token>`) поднят на homelab-хосте
**192.168.0.236** и доступен из LAN и приватного Tailscale tailnet:

| | |
|---|---|
| URL | http://192.168.0.236:18402/admin/ |
| Tailscale URL | http://vpnctld/admin/ (`tailscale serve --http=80`, tailnet only) |
| Health | http://192.168.0.236:18402/api/v1/health |
| Auth | basic-auth, user `slovn`, пароль в `/etc/vpnctl/vpnctld.env` (sudo cat) |
| Бинарь | `/opt/vpnctl/vpnctld` (root:root 0755) |
| Assets | `/opt/vpnctl/assets/admin.css` |
| Inventory DB | `/var/lib/vpnctl/inv.db` (user:user 0640) |
| EnvFile | `/etc/vpnctl/vpnctld.env` (root:user 0640) |
| Systemd unit | `/etc/systemd/system/vpnctld.service` |
| Firewall | iptables INPUT: `192.168.0.0/24 → tcp/18402 ACCEPT`, persisted в `/etc/iptables/rules.v4` |

Tailscale Serve проксирует `http://127.0.0.1:18402`, сохраняется после
перезагрузки и доступен только участникам tailnet. Funnel выключен.

Креды для локального доступа из контейнера: `inventory/vpnctld-192.168.0.236.env`
(в проекте `vpn-control`, gitignored через `inventory/*.env`).

### Обновление бинарника / ассетов / БД

```bash
# 1. собрать (контейнер glibc 2.41, host 2.36 — binary использует max GLIBC_2.34, OK)
cd ~/vpn-control/vpnctl && cargo build --release -p vpnctld

# 2. SCP
scp target/release/vpnctld user@192.168.0.236:/tmp/vpnctld
scp daemon/assets/admin.css user@192.168.0.236:/tmp/admin.css

# 3. install + restart
ssh user@192.168.0.236 '
  sudo install -o root -g root -m 0755 /tmp/vpnctld /opt/vpnctl/vpnctld &&
  sudo install -o root -g root -m 0644 /tmp/admin.css /opt/vpnctl/assets/admin.css &&
  rm /tmp/vpnctld /tmp/admin.css &&
  sudo systemctl restart vpnctld &&
  sudo systemctl status vpnctld --no-pager | head'
```

### Грабли деплоя на 192.168.0.236

- **iptables INPUT policy DROP** — на хосте есть hand-crafted iptables (не
  UFW, не firewalld), и любой новый порт надо явно открыть + сохранить в
  `/etc/iptables/rules.v4`. Загружается из `iptables-restore.service`.
- **Бинарь динамически линкуется к glibc** — при сборке в claude-chat
  (Debian trixie, glibc 2.41) и деплое на bookworm (2.36) проверь
  `objdump -T <binary> | grep GLIBC_ | sort -u` — нужно ≤ 2.36. Сейчас
  максимум — 2.34, но новая dep может затащить 2.38+.
- **SSH-pulling deps = glibc upgrade hazard** — добавление `vpnctl-ssh` /
  `russh` / любого async-runtime / native-crypto dep в `[dependencies]`
  (а не `[dev-dependencies]`) пропулит glibc 2.38 syscalls и daemon
  на bookworm моментально упадёт в crash-loop с "GLIBC_2.38 not found".
  Тoже самое с `tokio::process` (`pidfd_spawnp` это 2.39).
  Caught 2026-05-16: D.5 poller wire shipped, vpnctld crash-looped 30+
  раз за минуту.
  **Решение (Path C):** `crate::ssh_subprocess::SubprocessSshTransport`
  оборачивает системный `/usr/bin/ssh` через
  `std::process::Command` + `tokio::task::spawn_blocking`. Никакого
  russh, никакого `tokio::process`. См. doc-comment в
  `daemon/src/ssh_subprocess.rs`.
  **Build:** `cargo zigbuild --release -p vpnctld --target
  x86_64-unknown-linux-gnu.2.36`. zigbuild ставит cargo install +
  zig binary download (см. ниже). Verify max GLIBC symbol **до
  push** через `objdump -T target/x86_64-unknown-linux-gnu/release/vpnctld
  | grep GLIBC_ | sort -u | tail -3` — должно быть ≤ 2.36.

### Сборка vpnctld для production (bookworm-2.36-compatible)

Контейнер claude-chat имеет glibc 2.41, host 192.168.0.236 имеет
glibc 2.36. Прямой `cargo build --release` затащит `pidfd_*` (2.39),
crash на target. Используем `cargo-zigbuild` который таргетирует
старую glibc через zig as cross-linker.

Bring-up (один раз на свежий контейнер):
```bash
export PATH=/home/appuser/.cargo/bin:$PATH
cargo install --locked cargo-zigbuild      # ~30s
mkdir -p /tmp/zig && cd /tmp/zig
curl -fsSL -o zig.tar.xz https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz
tar -xf zig.tar.xz
export PATH=/tmp/zig/zig-linux-x86_64-0.13.0:$PATH   # add to PATH for zigbuild
```

Сборка:
```bash
cd ~/vpn-control/vpnctl
cargo zigbuild --release -p vpnctld --target x86_64-unknown-linux-gnu.2.36
# Output: target/x86_64-unknown-linux-gnu/release/vpnctld
objdump -T target/x86_64-unknown-linux-gnu/release/vpnctld | grep GLIBC_ | sort -u | tail -3
# Expected: all ≤ GLIBC_2.30 (some weak symbols are OK at .25/.28/.29/.30)
scp target/x86_64-unknown-linux-gnu/release/vpnctld user@192.168.0.236:/tmp/vpnctld
ssh user@192.168.0.236 'sudo install -o root -g root -m 0755 /tmp/vpnctld /opt/vpnctl/vpnctld \
  && rm /tmp/vpnctld && sudo systemctl restart vpnctld'
```

Все примеры в CLAUDE.md / scripts которые ссылаются на
`cargo build --release` устарели — заменяй на `cargo zigbuild
--release --target x86_64-unknown-linux-gnu.2.36`.
- **`MemoryDenyWriteExecute=true`** в systemd unit — может сломать future
  JIT (если когда-то добавим V8/wasmtime). Сейчас OK.
- **Креды в EnvironmentFile**, не в `Environment=` — `systemctl cat`
  не палит пароль в логах.

## Version snapshot (post-Track-1, 2026-05-14)

The detailed phased roadmap lives at the **top** of this file
(`Strategic context → Roadmap`). This section is the version-stamped
high-level summary so external readers (CHANGELOG, release notes) can
get oriented without reading the whole methodology block.

- **v0.1** ✅ scaffold (workspace, traits, registry, smoke binary), CI
- **v0.2** ✅ `russh` transport, `sqlx+sqlite` inventory with migrations,
  CLI subcommands (`server`, `user`, `grant`, `deploy`, `status`, `sub`),
  e2e integration test via testcontainers
- **v0.3** ✅ bootstrap fresh-node (SSH harden, fail2ban, sing-box install,
  config render), ProxyJump via russh, subscription URLs (offline-
  generated, byte-stable across rebuilds), `backon` retry layer
- **v0.4** ✅ daemon `vpnctld` + REST API + `GET /sub/<token>` + admin UI
  Phase A (editorial shell, theme/accent cookies) + Phase B
  (dashboard metrics, servers list)
- **v0.5** ✅ admin UI feature delivery complete
  - ✅ Phase C-1: users list + detail + inline-SVG QR (`aafc180`)
  - ✅ Phase C-2: collapsible Tweaks + footer overlap fix + favicon +
    unified backend copy contract (`d1c0578`, `663a653`)
  - ✅ Phase C-3.1: regenerate sub-token from web (`276e47d`)
  - ✅ Phase Track-1: subscription-access log + abuse-signal UI on
    user-detail (`1e91eeb`) — first abuse-detection layer
  - ✅ Phase C-3.2-4: web add-user (`2a5ce95`), grant/revoke (`60a90e9`),
    delete with double-submit confirm (`0b1fec5`)
  - ✅ Phase Track-1.1: retention scheduler wired in `daemon/src/app.rs`
    — hourly purge of `sub_access_log` AND `vpn_connection_stats`
    rows >30 days (`1e33e29`)
  - ✅ Phase Track-2: rate-limit `/sub/<token>` with per-IP + per-token
    token bucket + persistent bans table (`555fd5a` + `daemon/src/rate_limit.rs`)
- **v0.6** ✅ backups + migration shipped
  - ✅ Phase C-4: `inv.db` snapshot + retention + Settings UI download
    + `vpnctl restore` CLI (`bbf427f`)
  - ✅ Phase C-5: `vpnctl migrate from-bash <path>` preserves UUIDs +
    TUIC passwords, split-identity policy permits import of bash 93
    (`0530251` + `33b3025`)
- **v0.7** ✅ wizard + protocol breadth + audit/monitoring/UA fingerprint
  - ✅ Phase E: add-server wizard with SSE-streamed bootstrap
    (`1821c99` form + `4477199` sub-iter 4b SSE)
  - ✅ Phase Track-3: clash-api kernel block (`537342c`) + client
    (`cd61838`) + diff engine + storage (`f22df7d`) + UI (`d36b7c9`)
    + poller (`473b2e4` reapply + `54ee77f` feature-gate)
  - ✅ Phase D: paginated + filtered + CSV audit timeline (`1a2d8c9`)
  - ✅ Phase F: monitoring sparklines + `/api/v1/stats/sub-access`
    JSON endpoint (`dbfd211`) + 24h dashboard sparkline + heavy-users
    heatmap (`4d810f2`) + D.6c traffic limits + alerts (`fdbd618`)
  - ✅ Phase Track-4: UA fingerprint section on user-detail with
    likely-shared / likely-roaming classifier (`272a3ec`)
  - ✅ Phase H chunks 1-3: node_probe + node_health storage + per-server
    detail page with DECLARED vs OBSERVED drift banner (`3970530`,
    `604cf0c`, `d5ff423`)
  - ✅ AnyTLS protocol (`ce521ec`) + Trojan protocol (`f8823b0`) for
    РФ-DPI diversity; 7 protocols total across 2 kernels
  - ✅ `--gen-wireguard` CLI + AmneziaVPN Flow C `vpn://` deep-link
    (`522d449` + `091b82e`)
- **v0.8 (in progress, post-2026-05-17)** — closing the last gaps
  - ✅ Phase H chunk 4: node_probe poller wired in `daemon/src/app.rs::build()`
    via `spawn_node_probe_poller(inv)` + `spawn_health_monitor(inv.clone())`,
    10-min default interval (env override `VPNCTLD_NODE_PROBE_INTERVAL_SECS`).
    Verified live 2026-05-22 — 1496 probe rows across de/fi/is, all healthy.
    See **H** row in Roadmap.
  - ✅ Phase G: infra notifications — `admin_alerts` table + state-machine
    in `health_monitor.rs` consumes node_probe rows. Fires: `server.singbox.down`
    (critical), `server.fail2ban.down`, `server.disk.pressure`, `server.mem.pressure`,
    `server.singbox.log.too_big`, `server.unreachable`, `server.fail2ban.banned_self`.
    Telegram transport wired (`alert_sink.rs::TelegramSink`); webhook / ntfy.sh
    still deferred until Pavel picks one — Telegram covers single-operator case.
  - ✅ Phase 5 a→e (Restore fire-drill close-out, 2026-05-22): bundled deploy
    key + geoip + systemd + iptables, off-sited to Iceland, web-clickable
    self-test, CI-protected byte-equality via `daemon/tests/restore_e2e.rs`,
    Disaster Recovery section in /admin/settings consolidating the «what to
    do if 236 burns» story. See **DR-5** row in Roadmap.
  - ✅ L7 methodology fix: `vpnctl migrate from-bash --overwrite-existing`
    requires `--i-really-mean-overwrite-address` flag when `Server.address`
    changes (shipped `0068c8f`, see L7 row in Roadmap). Stale line cleaned
    2026-05-22.
  - ✅ `vpnctl server set-fingerprint <id>` CLI + web action — shipped
    `2fda5c6` (2026-05-17) + `ec275c5` (2026-05-18, extracted
    `vpnctl-host-fingerprint` crate as single source of truth shared
    between CLI + admin handler). `/admin/servers/{id}` exposes both an
    «auto-detect via ssh-keyscan →» button + a «pin manually» input;
    both POST to `/admin/servers/{id}/set-fingerprint`, audit emits
    `server.set_fingerprint` with `{fingerprint, previous, source}`
    payload. Verified live 2026-05-22: all 3 prod servers (de/fi/is)
    pinned, no operator ever needs to drop to raw SQL or CLI for this.
    The AUTONOMOUS_PLAN.md:273 «raw SQL workaround» note is HISTORICAL —
    that was the 2026-05-16 fire-drill day, the proper feature shipped
    the day after. Memory was stale.
  - ✅ `decode_form_value` UTF-8 review — re-verified 2026-05-22, NOT a
    latent bug. Implementation in `daemon/src/http_util.rs:39-72` is
    bounds-checked (`b'%' if i + 2 < bytes.len()`), uses `from_utf8_lossy`
    (correct lenient policy for form input — paste-from-broken-Windows-
    clipboard MUST not 4xx the operator), and every consumer routes
    through `form_field` which further validates per-field. The
    `e250789` audit's «deferred minor» note was about being LESS lenient
    (rejecting invalid UTF-8 explicitly); on reflection that would be
    a regression in UX. Closed as «no fix needed».
  - ✅ Bulk-ack of admin_alerts via web — shipped 2026-05-22.
    `POST /admin/alerts/ack-all` + «ack all (N)» button on /admin/alerts
    header (renders only when `unacked_total > 0`, double-submit
    confirm via JS). Inventory helper `ack_all_unacked_alerts()` does
    one indexed UPDATE; preserves existing acked_at timestamps; audits
    `alerts.ack_all` with `{count}` only when count > 0 (audit-on-
    actual-mutation NM-10 contract). Trigger: 2026-05-22 fire-drill
    where 33 `sub_access.suspicious_local_ip` alerts had accumulated
    from legit LAN testing (claude-chat curl runs into /sub/* are real
    LAN access → real alert per /sub fetch + user, but Pavel-the-tester
    knew it was him). Pre-bulk-ack workaround was raw SQL (CLI
    exception per «web is THE operator surface»). Live-used the new
    button to clean the 33 backlog + 2 visual-demo seeds. Review-agent
    1 important catch (JS apostrophe escape — added
    `js_single_quote_escape` helper + forward-compat smoke test that
    asserts inner confirm() body has 0 bare apostrophes, so a future
    `don't` in translated copy can't silently break the dialog).
  - ✅ NM-11 upstream PR filed 2026-05-22 — [SagerNet/sing-box#4159](https://github.com/SagerNet/sing-box/pull/4159)
    against `testing` branch (verified via `gh pr list --repo
    SagerNet/sing-box --state merged` — every recent PR merges to
    `testing`, not `dev-next` which was my first wrong guess). 1-line
    diff: `"user": t.Metadata.User` added in the JSON marshal map in
    `experimental/clashapi/trafficontrol/tracker.go`. Fork lives at
    `PavelLizunov/sing-box`, branch `feat/clashapi-emit-user-field`,
    commit `c29c5db`. PR body explains the driver (vpnctld's NULL
    `vpn_connection_stats.user_id`), the compatibility (additive JSON
    key, no schema/protocol break), and the test plan (manual curl
    against clash-api with VLESS-authenticated connection). Until/
    unless upstream accepts, per-user clash-api attribution stays
    NULL — but the **upstream gate** is now in flight rather than
    sitting as a TODO.
  - ✅ **Second wave 2026-05-23 (post-audit operator UX).** The
    audit/polish sprint surfaced a regression-of-itself (I4 broke
    prod) + a backlog of high-visibility UX gaps. Shipped same-day:
      * `6448652` **P0 I4 hotfix** — `VPNCTLD_TRUSTED_PROXIES=192.168.0.207`
        wired into prod `/etc/vpnctl/vpnctld.env` (env-var was empty after
        the I4 deploy → every legit /sub through nginx fired
        `suspicious_local_ip` warning). Belt-and-braces: detector
        side now ALSO suppresses the alert when peer IP is in
        `trusted_proxies()`, so a future deploy without env-config
        is self-healing. Doc'd in CLAUDE.md «Грабли». 10 acked
        backlog alerts cleared via /admin/alerts bulk-ack button.
      * `b4608d2` **P1 alert auto-recovery** — `check_user_traffic_limits`
        and `check_fingerprint_drift` now silently ack open warnings
        when the underlying condition clears (used % drops below
        threshold, observed fingerprint matches pinned). Removes the
        monthly «manually-ack-30-stale-warnings» tax.
      * `07a9fd3` **P1 disabled-user count** on dashboard Users tile
        («N paused» amber sub-line, hidden when 0). Surfaces B1.user
        soft-suspended accounts at the top-level glance so paused
        users don't fall off the operator's radar.
      * `5e7be3f` **P2 A3 per-server resource sparklines** — disk %
        / mem-used % / sing-box log MiB over 24h on
        /admin/servers/<id>, reusing `sparkline_svg`. Quiet contract
        (omitted on fresh servers with no probes). Live demo on de:
        log file climbs predictably → operator can preempt the
        500 MiB alert.
      * `9620e9b` **P2 B2 bulk grant/revoke** on server-detail.
        «grant all (N)» (no confirm, idempotent) + «revoke all (N)…»
        (destructive, double-submit confirm matching the C-3.4
        delete-user pattern). Single summary audit row per batch
        instead of N per-user rows.
      * `85aa251` **P2 A5 fleet-wide search** at `/admin/search?q=`
        with a compact nav search bar. Substring match across users
        (id/uuid/sub_token/device_id), servers (id/address), alerts
        (kind/summary). Audit search stays at /admin/audit (its own
        filter form is the right surface for that data shape).
    Tests went 1037 → 1049 (+12). All 7 commits CI-green; no
    rollbacks. The trusted-proxies regression-of-the-audit-fix
    became its own «грабли» entry — future operator provisioning
    a second `vpnctld` behind a reverse proxy gets the explicit
    «must set env-var» warning instead of finding out via 10
    false-positive alerts.

  - ✅ **Audit & polish sprint 2026-05-22 (7-bundle session).** Three
    parallel audits ran (code-health, reusability, operator-value);
    the safe-fix + top-ROI subset shipped same day:
      * `f881ba9` Bundle 1: `internal_error()` leak fix (opaque body)
        + `vpnctl admin hash-password` real subcommand (closes B2 doc
        lie) + `assert_auth_safe_for_addr` startup gate (B3 — refuses
        non-loopback bind without VPNCTLD_ADMIN_USER/PASSWORD) + stale
        TODO sweep + `0.1.0`→`0.8.0` Cargo bump (I2) + orphan
        `crates/inventory/src/mem.rs` deletion (I3) + `VPNCTLD_TRUSTED_PROXIES`
        empty-by-default (I4 — operator-specific `192.168.0.207` no
        longer baked into the binary).
      * `e1988d1` Bundle 2 (D1): default «grant all servers» checkbox
        on user-create. One-click = usable user instead of 3 drill-
        downs.
      * `7b69245` Bundle 3 (A2): «Idle users» panel on dashboard with
        `idle_users(days, limit)` inventory helper. Renders only when
        ≥1 user is idle (quiet for healthy fleet).
      * `c7d3ca5` Bundle 4 (C3): Telegram push on user-traffic-limit
        crossed. Fires `user.traffic_limit:<user_id>` warning alert
        once per condition via the partial-UNIQUE dedup; reuses
        Phase G push pipeline (made `node_probe_poller::push_alert`
        `pub(crate)` for cross-module reuse).
      * `5f0fe55` Bundle 5 (B1.user): `users.disabled` flag via
        migration 0026. Soft-suspend without revoking grants or
        rotating secrets. Subscription pipelines (`/sub/<token>` +
        `/api/v1/app/config/<device_id>`) return an empty config
        envelope for disabled users; re-enabling restores byte-for-
        byte. Web action `POST /admin/users/{id}/{disable,enable}`
        with amber banner UI on user-detail.
      * `0b95209` Bundle 6 (I1): unified add-user audit payload across
        CLI / web / migrate. All three paths now emit `user.add` with
        `{uuid, wg_pubkey_set, wg_keypair_provenance}`; migrate added
        the missing per-user rows (was only writing a summary). Actor
        stays distinct (`cli` / `admin` / `migrate`) for filtering.
      * `359ae13` Bundle 7 (C2): stale-fingerprint detection alert in
        `health_monitor::check_fingerprint_drift`. Runs `ssh-keyscan`
        per server with a pinned fingerprint, fires
        `server.fingerprint.drift:<id>` warning + Telegram push on
        mismatch. Skips no-pin and ProxyJump servers; verified zero
        false-positives on the healthy 3-server prod fleet.
    Tests went from 1010 → 1037 (+27). All 7 commits CI-green; no
    rollbacks. Strategic-tension discussion (single-operator vs
    reusable product) explicitly flagged in Bundle 1 commit — full
    productisation (release artifacts, mTLS, OAuth) is a separate
    multi-session decision.
- **v1.0** far away — defined as "everything in roadmap shipped + months
  of operating experience without rolling back"

## Текущая дата контекста

См. системную инфу. Проект стартовал 2026-05-13.
