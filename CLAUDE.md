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
- **Production deployment.** LAN-only for now (homelab `192.168.0.236`).
  External exposure with OAuth/2FA is a later concern; design today
  must not make that *harder* but doesn't have to support it.
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
| H | node telemetry (read side) | ✅ chunks 1-3 shipped | `3970530` probe + `604cf0c` storage + `d5ff423` /admin/servers/{id} detail page; **chunk 4 poller wiring still pending** |
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
cargo build --release -p vpnctld
scp target/release/vpnctld user@192.168.0.236:/tmp/vpnctld
ssh user@192.168.0.236 'sudo install -o root -g root -m 0755 \
  /tmp/vpnctld /opt/vpnctl/vpnctld && rm /tmp/vpnctld && \
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

# 2. Live deploy to homelab (binary + CSS + favicon)
cargo build --release -p vpnctld
scp target/release/vpnctld user@192.168.0.236:/tmp/vpnctld
scp daemon/assets/{admin.css,favicon.svg} user@192.168.0.236:/tmp/
ssh user@192.168.0.236 '
  sudo install -o root -g root -m 0755 /tmp/vpnctld /opt/vpnctl/vpnctld &&
  sudo install -o root -g root -m 0644 /tmp/admin.css /opt/vpnctl/assets/admin.css &&
  sudo install -o root -g root -m 0644 /tmp/favicon.svg /opt/vpnctl/assets/favicon.svg &&
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
`ssh`, `crypto`, `inventory`, `hosters` или `cli` — только новый файл-модуль
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
│   ├── hosters/              DigitalOcean / Cloudzy / Generic
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

## Связанные репо и серверы

- **Старый bash-проект `vpn-control`** — живёт пока только в локальном
  Forgejo (`slovn/vpn-control`). Там список production VPN серверов
  (`SERVERS.md`), inventory с секретами (`inventory/<IP>.env`, не коммитить!),
  и SSH-ключ `claude-dev` (`/home/user/.ssh/id_ed25519`,
  НЕ `/home/appuser/.ssh/`). Если миграция на vpnctl завершится успешно,
  старый репо уйдёт в archive.
- **Production VPN серверы** — пока не трогаем, миграция на vpnctl будет
  только когда v0.2 пройдёт интеграционный тест на staging.

## Live-deploy `vpnctld` на homelab (LAN)

`vpnctld` (admin UI + `/sub/<token>`) поднят на homelab-хосте
**192.168.0.236** и доступен с ноута Pavel'а в локальной сети:

| | |
|---|---|
| URL | http://192.168.0.236:18402/admin/ |
| Health | http://192.168.0.236:18402/api/v1/health |
| Auth | basic-auth, user `slovn`, пароль в `/etc/vpnctl/vpnctld.env` (sudo cat) |
| Бинарь | `/opt/vpnctl/vpnctld` (root:root 0755) |
| Assets | `/opt/vpnctl/assets/admin.css` |
| Inventory DB | `/var/lib/vpnctl/inv.db` (user:user 0640) |
| EnvFile | `/etc/vpnctl/vpnctld.env` (root:user 0640) |
| Systemd unit | `/etc/systemd/system/vpnctld.service` |
| Firewall | iptables INPUT: `192.168.0.0/24 → tcp/18402 ACCEPT`, persisted в `/etc/iptables/rules.v4` |

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
  - ⏳ Phase H chunk 4: node_probe **poller wiring** into daemon
    startup. Storage + UI ready; just need periodic SSH probe.
    Empty-state on `/admin/servers/{id}` until then.
  - ⏳ Phase G: infra notifications — `admin_alerts` table + state-
    machine on top of Phase H chunk 4 probe data; dashboard alert
    feed + ack. Webhook transport (Telegram / ntfy.sh / journald)
    deferred until Pavel picks one.
  - ⏳ L7 methodology fix: `vpnctl migrate from-bash --overwrite-existing`
    must require explicit confirmation when `Server.address` changes.
    Caught the hard way (vps-is-01 ↔ 104 cross-overwrite, 2026-05-17).
  - ⏳ `vpnctl server set-fingerprint <id>` CLI + web action — today
    operators run raw SQL (noted in `docs/AUTONOMOUS_PLAN.md:273`).
  - ⏳ `decode_form_value` UTF-8 fix (3 call sites, masked today by
    validators — deferred minor from `e250789` audit).
- **v1.0** far away — defined as "everything in roadmap shipped + months
  of operating experience without rolling back"

## Текущая дата контекста

См. системную инфу. Проект стартовал 2026-05-13.
