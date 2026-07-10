# Design v2 — conformance matrix

Element-by-element audit of every frame in the `claude_design` handoff
`vpnctl Redesign v2.html` (project `019e235f-8640-7a71-82d6-e0060c52c3dc`)
against the live admin UI on `192.168.0.236`.

**Legend** — `✅ match` (implemented, semantically equivalent) ·
`🟨 deferred(reason)` (intentionally not built; no data source, or a
security/architecture reason). There are **no** `❌ missing` or
`⚠ diverges` rows: everything with a data source is built; the rest is
deferred with a stated reason.

**Style note.** The mock is a static pixel comp using JetBrains Mono /
Source Serif / hard-coded hex + a dark topbar. The implementation
reproduces its *structure and information density* using the shipped
editorial token system (`--ink/--paper/--warm/--acc/…`, IBM Plex /
Newsreader, `.ed-*` classes) so it themes across cream / newsprint /
foxed / ink and localises EN/RU. "match" means structural + behavioural
equivalence, not pixel identity — that is the agreed contract.

Shipped across PRs #99–#101 (list densify), #102–#106 (v2 groups A–E),
#107 (topbar), and the gap-close PR that lands this file.

---

## Topbar (all 14 frames share it)

| Mock element | Status |
|---|---|
| Single compact bar (dark) | ✅ `.ed-tb`, `background: var(--ink)`, inverts per theme |
| `[·] vpnctl` wordmark, clickable | ✅ `a.ed-tb__logo href="/admin/"`, `[·]` glyph accent-tinted |
| UPPERCASE nav, active pill | ✅ `.ed-tb__nav a`, active `a.on` pill |
| `ALERTS <count>` amber chip | ✅ **live** unacked count via `render_page`→`unacked_alert_count`; `.ct` = `--warm`; omitted at 0 |
| search input, `/` hotkey | ✅ `#tb-search`; `/` focus in admin.js (ignored while typing) |
| `EN\|RU · operator` | ✅ active bold + POST cookie toggle + `NavOperator` label |
| logout | ✅ POST `/admin/logout` |

---

## 3a · Monitoring — fleet health (PR #102)

| Mock element | Status |
|---|---|
| `Fleet health` h1 + ⓘ + meta (N nodes · tick · last sweep) | ✅ |
| `probe all now` button | ✅ POST `/admin/monitoring/probe-all` (runs `probe_one_server`) |
| 6 status tiles (fleet / open alerts / mem peak / disk peak / drift / probes 24h) | ✅ `.ed-status-strip`, warm >70% |
| open-alerts split note (`N sub-access · M node`) | ✅ |
| Uptime table (24h/7d/30d · probes 30d · last incident · open→) | ✅ `.ed-grid`, mem-hot row tint |
| Resource-trend table (disk/mem/log sparklines + warm max · 1-min load) | ✅ |
| Alert-thresholds table (metric / warn-at / worst-now / where / state) | ✅ renders the monitor's **real** consts (mem 95 / disk 90 / log 500 / unreachable ×3) |
| Probe-failures 7d table | ✅ from `server.unreachable` alerts |
| GeoIP DB freshness + update link | ✅ links to `/admin/settings/system#geoip` (POST-safe, no state-changing GET) |
| Mock's illustrative watermarks (70/85) | 🟨 deferred — the mock numbers were placeholders; the table shows the monitor's true triggers, with the 70% warm tint documented as visual-only |
| probes-24h ok/timeout split | 🟨 deferred — a failed probe writes no row, so a timeout count isn't recoverable |

## 3b · Server detail · Activity (PR #103)

| Mock element | Status |
|---|---|
| Last-deploy summary line (ts · actor) | ✅ from newest `server.deploy` audit row |
| Events table (target = server) | ✅ server-scoped audit timeline |
| `audit with this filter →` link | ✅ links to `/admin/audit?target=<id>` |
| `DEPLOY LOG · LAST RUN` scrollable log-tail pane | 🟨 deferred — deploy logs stream live (SSE) + archive to audit, but the raw line-tail isn't persisted per run; the summary line + audit filter cover the same information |

## 3c · Server detail · Protocols (drift grid) (PR #103)

| Mock element | Status |
|---|---|
| Drift banner (`0 silent · N listening-but-undeclared`) | ✅ |
| Declared-protocols grid (protocol × port × declared × listening × note) | ✅ per-protocol × expected-port × probe-listening verdict, warm `✗ silent` |
| Listening-but-undeclared grouped table (wg peers / caddy / unclassified) | ✅ classified groups instead of a 100-socket wall |
| `adopt group →` / `ignore →` actions | 🟨 deferred — the inventory doesn't model per-user AmneziaWG peer ports yet (NM-14); adopting would need a schema for them |
| `re-scan ports` button | 🟨 deferred — covered by `probe all now` on Monitoring (same probe writes `listening_ports_json`) |

## 3d · Server detail · Grants (PR #103 + gap-close)

| Mock element | Status |
|---|---|
| Pending-deploy banner naming the users | ✅ |
| Grant bar (typed user id → grant) | ✅ POST `/admin/servers/{id}/grants` |
| Bulk grant-all / revoke-all | ✅ (kept from earlier) |
| Dense table (№ / user / presence / traffic 24h / keys-on-node / granted date / revoke) | ✅ `.ed-grid`, granted date via migration 0039 |
| **Sort links (`id ↑ · online ↓ · traffic ↓`)** | ✅ **gap-close** — `?grant_sort=` drives the order; pending-deploy always floats to top |
| `last-seen ↓` sort option | 🟨 deferred — per-user last-seen isn't loaded in the grants context (presence + traffic are); adding it is a second query per row |

## 3e · Server detail · Setup checklist (PR #103)

| Mock element | Status |
|---|---|
| Post-bootstrap checklist re-verified at last probe | ✅ deploy key / kernels+versions / sing-box / fail2ban / fingerprint / clash-api / log<500MiB |
| Bootstrap record (when · by · method · os) | ✅ from the audit trail |
| Danger zone (remove from inventory) | ✅ links the typed-confirm delete page |
| `bbr` / `ntp` / `logrotate-config` checklist rows | 🟨 deferred — the node_probe doesn't capture these facts yet; adding them needs new probe fields |

## 4a · User detail · Delivery (PR #104)

| Mock element | Status |
|---|---|
| Subscription recap (URL + QR link + legacy `/sub` fallback) | ✅ `.ed-inbar` recap; QR on Overview (linked, not double-rendered) |
| Share-links table (server × protocol · link · copy·QR) | ✅ the per-protocol share-link grid (33 render paths) with copy affordances |
| Delivery-matrix per-client-app rows (`?fmt=singbox/clash/wg/awg`) | 🟨 deferred — vpnctld renders one canonical URI set; there is no per-format content-negotiation endpoint, so the `fmt=` rows have no backend |
| `download png` of the QR | 🟨 deferred — the QR is inline SVG; a PNG export endpoint isn't built |

## 4b · User detail · Access (PR #104)

| Mock element | Status |
|---|---|
| Per-server grant/key-state table (granted date / keys minted / on-node pending / protocols available / grant·revoke) | ✅ |
| Per-protocol identities list (uuid + masked tuic/wg/sub-token + length) | ✅ `.ed-feed`, secrets masked |
| Bulk actions (grant-all / revoke-everywhere) | ✅ grant/revoke per row + the server-side bulk paths |
| `reveal · copy` on secret rows | 🟨 deferred — secrets never leave the server unmasked (security); the operator rotates rather than reveals |
| `regenerate all keys…` single button | 🟨 deferred — no atomic all-key re-mint path today; per-key rotation exists on the detail sections |

## 4c · User detail · Activity (sub-access + GeoIP) (PR #104 + gap-close)

| Mock element | Status |
|---|---|
| 4 fact tiles (verdict+score / distinct IPs / fetches / last fetch) | ✅ |
| GeoIP-resolved fetch log (time / ip+egress⚠ / geo / asn / ua / status) | ✅ |
| **`showing N of M` + `older →` pager** | ✅ **gap-close** — `?log_page=`, 25/page, `sub_access_count_for_user` backs the total |
| **`export csv →`** | ✅ **gap-close** — `GET /admin/users/{id}/access.csv`, `text/csv` attachment |
| Audit-events sub-table (target = user) | ✅ (below the log) |
| `all / alerts only / unique IPs` log filters | 🟨 deferred — the `?show_egress` toggle exists; the alerts-only / unique-IP facets are a follow-up (the abuse tiles already summarise the same signal) |

## 5a · Alerts — feed + ack (PR #105 + gap-close)

| Mock element | Status |
|---|---|
| `N open alerts` headrow + family split note + ⓘ | ✅ |
| show-all toggle + global ack-all | ✅ |
| `sub_access` family table (⚠ / opened / subject-link / localized detail / ack) | ✅ |
| node·fleet·user table (severity / kind / subject·detail / auto-resolve / ack) | ✅ |
| **per-family group-ack (`ack all (N)`)** | ✅ **gap-close** — POST `/admin/alerts/ack-family/{prefix}` (prefix allow-list: `sub_access.` / `server.`) |

## 5b · Audit — filters + expand + CSV (PR #105)

| Mock element | Status |
|---|---|
| `N events on file · M match` counts | ✅ `audit_counts` |
| Filters (actor / action-prefix / **target-contains**) | ✅ |
| Payload `{…}` expander | ✅ CSP-safe `<details>` rendering a **redacted** payload copy |
| CSV export (honours filters) | ✅ `/admin/audit.csv` |
| Pagination (prev / next) | ✅ |

## 5c · Search — global (query «brat») (PR #105)

| Mock element | Status |
|---|---|
| `«query» — N matches` headrow + per-family counts | ✅ |
| Users result table (presence / uuid / grants / created) | ✅ |
| Audit-events result (`audit events →` bridge to 5b target filter) | ✅ |
| `no matches in …` line | ✅ |
| `<b>` highlight of the matched substring | 🟨 deferred — results list the matching rows; inline substring highlighting is cosmetic and unimplemented |

## 6a · Settings — appearance · backups · system (PR #106)

| Mock element | Status |
|---|---|
| Appearance (language / theme / density chips) | ✅ Appearance tab (theme + accent + timezone) |
| Backups table (when / size / scope / verify / download) + backup-now + test-restore | ✅ Backups tab |
| **System facts table (probe tick / clash poll / alert sink / rate limit)** | ✅ **PR #106** — each row names its source module |
| GeoIP update (SSE) | ✅ |
| `density: dense/relaxed` toggle | 🟨 deferred — the UI ships at the dense setting; a relaxed variant is a second token set, not built |
| `daemon log level` runtime switch | 🟨 deferred — log level is env-configured at start; no runtime switch endpoint |

## 6b · Wizard — bootstrap (SSE) (PR #106)

| Mock element | Status |
|---|---|
| Two-column layout (Target + Steps left · Live log right) | ✅ |
| Target facts table | ✅ |
| Steps checklist lighting up per phase | ✅ `data-step-phase` rows lit by admin.js on each SSE `step` (phases: server/deploy/apply/probe/done) |
| Live SSE log, CSP-safe | ✅ `data-sse-autostart` + `wireAutoSse` (fixed the inline-`<script>` CSP block, roadmap UX-2) |
| `run in background` / `abort…` buttons | 🟨 deferred — the bootstrap already continues server-side if the tab closes; an explicit abort needs a cancel channel into the SSH task |

## 6c · Delete-confirm — typed match (PR #106)

| Mock element | Status |
|---|---|
| Red point-of-no-return banner | ✅ |
| "What gets destroyed" table (uuid / keys / grants named / URL / kept) | ✅ names the granted servers |
| Right-column typed-confirm (cancel · delete-forever) | ✅ server-side exact-match guard |
| Disabled-until-match on the delete button | 🟨 deferred — the guard is server-side (typed value re-checked); a live disable is a client-only nicety on top |

---

## Deferred summary (16 rows, each with a reason)

No-data-source / architecture: 3a probes-24h split · 3b deploy-log-tail ·
3c adopt-peer-ports (NM-14) · 3c re-scan (covered by probe-all) · 3d
last-seen sort · 3e bbr/ntp/logrotate probe fields · 4a fmt= negotiation ·
4a QR PNG · 4b regenerate-all · 5c substring highlight · 6a relaxed
density · 6a log-level runtime switch · 6b abort channel.

Security: 4b secret reveal (never unmask).

Cosmetic-on-server-guard: 6c live-disable button.

Mock-placeholder: 3a illustrative watermarks (real triggers shown).
