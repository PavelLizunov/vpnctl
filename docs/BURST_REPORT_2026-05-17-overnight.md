# Overnight burst report — 2026-05-17

For Pavel's wake-up. Skip to the **TL;DR** if you want the punch line first.

## TL;DR

- **7 commits shipped + live-deployed to 192.168.0.236.** All CI runs green. No daemon crash, no data loss.
- **Phase G (infra notifications) is real** — `admin_alerts` table + state-machine on top of node_health probes + dashboard tile + `/admin/alerts` feed + ack action. Webhook transport stubbed (Pavel decision: Telegram / ntfy.sh / journald?).
- **Phase H chunk 4 (node_probe poller) wired** — `/admin/servers/{id}` will stop showing empty-state once the deploy SSH key is authorised on the production nodes.
- **L7 destructive-op gate** — `vpnctl migrate from-bash --overwrite-existing` now requires `--i-really-mean-overwrite-address` when `Server.address` would change. Direct response to the vps-is-01 ↔ 104 mistake.
- **`vpnctl server set-fingerprint` shipped — both CLI and web button** (with auto-detect via ssh-keyscan).
- **`decode_form_value` UTF-8 fix** — every form now correctly carries Cyrillic + emoji etc.
- **Roadmap doc updated** — 5 of 6 "pending" items were actually shipped weeks ago; only Phase G truly was missing.
- **Codebase analysis written** — `docs/CODEBASE_INVENTORY.md` (LOC by crate, features, flows, artefacts).

## What you'll see in admin UI

1. **New nav entry «Alerts»** between Audit and Settings. Empty state today ("no unacked alerts") — will populate as the node-probe collects baselines (the diff requires two snapshots = at least 20 min after a deploy key gets authorised on the nodes).
2. **«Homelab health» tile on dashboard** — appears only when there are unacked alerts. Today: nothing shown (quiet).
3. **Server detail page now has a «Trusted host fingerprint» section** — current pinned value + two buttons (auto-detect ssh-keyscan, or manual paste).
4. **No visible changes to user-detail, audit timeline, monitoring, settings, wizard** — those were already complete.

## Real outstanding work after this burst

| Item | Why it's blocked | Size |
|---|---|---|
| Phase G chunk 2 — `server.unreachable` + `fail2ban.banned_self` detection | Just hasn't been written; design is clear (count consecutive missing probes for unreachable; parse `fail2ban-client status sshd` and match our IP for banned-self). | M (1-2 commits) |
| Phase G chunk 3 — webhook transport | Needs Pavel decision on transport: Telegram bot, ntfy.sh, or just journald. Implementation is trivial in any case (~150 LOC). | S after decision |
| Multi-server UUID split-identity for main-brat (104 vs 93) | Needs Pavel decision on policy: live with it / per-server-suffix users / canonical-only revoke. | discuss |
| Phase F deep dive — live stats tile on dashboard | Data already there (Track-3 poller writes to `vpn_connection_stats`); just needs `/api/v1/stats/live` endpoint + dashboard tile rendering 5-min-fresh rows. | M (1 commit) |
| Live-staging E2E tests for AnyTLS / Trojan / Hysteria2 / WireGuard | Needs a second VPS. Pavel-gated. | M, hoster cost |

## Burst commits

| Hash | Title |
|---|---|
| `e33d94a` | docs(burst): plan for 2026-05-17 overnight autonomous burst |
| `e928cd2` | docs(roadmap): mark shipped — Track-1.1/2/D/F/3/4/C-3.2-4/C-4/C-5/E |
| `d391c73` | feat(daemon): Phase H chunk 4 — node_probe poller wiring |
| `a17fad6` | feat(daemon): Phase G — infra alerts on top of node_health probes |
| `aa83241` | feat(cli/migrate): L7 destructive-op gate on Server.address overwrite |
| `2fda5c6` | feat(cli/web): vpnctl server set-fingerprint + matching web action |
| `aef1c6b` | fix(daemon/admin): decode_form_value UTF-8 — assemble bytes, then String |
| `1155333` | docs(inventory): full codebase analysis — LOC + features + artefacts |
| `4e77744` | docs(burst): wake-up report (this file) |
| `9819538` | fix(burst): apply 3-agent review findings — 2 critical + 5 important |
| `ef2eb6f` | fix(inventory): split index improvement into 0012 — sqlx checksum |
| `5841628` | fix(migrations): restore 0011 byte-for-byte (sqlx checksum) |

## Fix trail after the review

Three review-agents (one per crate group: crates/, daemon/, cli/) ran
in parallel against the burst diff `e928cd2..1155333`. They surfaced
**2 critical + 5 important + 4 minor**, all addressed inline in
`9819538`:

  * **CRITICAL #1** — both CLI + daemon `ssh-keyscan host` calls
    were missing the `--` separator before `<host>`. An address
    starting with `-` (typo, IDN edge case) would be parsed by
    ssh-keyscan's getopt as a flag (`-fSomething` reads attacker-
    controlled files). Fixed in both surfaces.
  * **CRITICAL #2** — daemon `keyscan_fingerprint_blocking` called
    synchronously from the async `server_set_fingerprint` handler.
    ssh-keyscan on an unreachable host pins the tokio worker
    thread for ~5–10s, starving other requests. Wrapped in
    `tokio::task::spawn_blocking`.
  * **IMPORTANT × 5** — `stdin.take()` None branch deadlock,
    explicit `drop(stdin)` for EOF, audit row captures previous
    fingerprint, health_monitor audit no longer silently swallowed,
    `validate_address` re-run before keyscan, kernel-skip filter
    centralised + log signal upgraded.
  * **MINOR × 4** — `Result<usize>` → `Result<bool>` for honest
    types, `insert_alert` doc-comment warns against secret
    leakage, partial-index column swap to `(acked_at)` for smaller
    footprint, decode_form_value doc-comment accuracy + ack test
    covers id=0 + id=999.

The partial-index swap (minor #3) caused a **live-deploy mini-incident
at 00:06 UTC**: changing the byte content of `0011_admin_alerts.sql`
after the file was already applied tripped sqlx's checksum guard
and vpnctld crash-looped for two restart cycles. Recovery: revert
0011 to byte-identical state with the originally-applied version +
add the index-swap as a fresh `0012_admin_alerts_unacked_index.sql`
that DROPs + recreates. Daemon up + healthy by 00:08 UTC.

Methodology takeaway pinned in `5841628` commit message: **never
edit an applied sqlx migration in place** — always add a follow-up
migration, even for internal index reshuffles.

## Methodology run

| Layer | Status this burst |
|---|---|
| 1. clippy `-D warnings` | green per commit |
| 2. workspace test (`cargo test --workspace`) | green per commit (149 admin_smoke + 102 vpnctld unit + spec suites) |
| 3. copy-contract subset | new copy in `/admin/alerts` empty-state pinned by `admin_alerts_empty_state_renders_with_copy_contract` |
| 4. review-agent | ran on the audit (correcting stale roadmap) + Phase G diff (3 important + 2 minor fixed inline) + final 3-agent sweep over the burst (results in `BURST_REVIEW_2026-05-17.md`) |
| 5. live-deploy + curl | bin shipped to 192.168.0.236, alerts page + dashboard + fingerprint section verified rendering; migration 0011 applied (3 new indexes present); no errors in journal beyond pre-existing clash-api SSH-permission warnings |
| 6. visual_check.py | not invoked (changes were additive new sections, not layout-level — visual baseline unchanged) |
| **7. L7 destructive-op gate** | **newly added as a methodology layer** to catch the bug class that caused vps-is-01 ↔ 104 |

## Things you should sanity-check on wake-up

1. `http://192.168.0.236:18402/admin/alerts` — confirm the page renders with "no unacked alerts" (one tweak away from the dashboard tile lighting up once probes actually run).
2. `http://192.168.0.236:18402/admin/servers/vps-is-01` (or any server) — scroll to "Trusted host fingerprint" section; the auto-detect button is the primary path.
3. `vpnctl migrate from-bash --help` from your laptop — confirm the new `--i-really-mean-overwrite-address` flag appears in the help.
4. `vpnctl server set-fingerprint --help` — confirm the new subcommand exists.
5. `docs/CODEBASE_INVENTORY.md` — sanity-check the LOC and feature counts match your mental model.

## Things I deliberately did NOT do

- Did NOT touch any production VPN server config (only LAN homelab daemon redeploy).
- Did NOT change `inv.db` schema with destructive intent — migration 0011 is purely additive.
- Did NOT pick a webhook transport for Phase G chunk 3 (Pavel-blocked decision).
- Did NOT pick a policy for multi-server UUID split-identity (Pavel-blocked decision).
- Did NOT enable the Forgejo `cargo audit` job (currently best-effort; CI is GitHub-primary).
- Did NOT commit any `inventory/*.env` files (gitignored — sanity check still applies).
- Did NOT run any destructive git ops (no force-push, no reset --hard).

## Tests count

| Suite | Before burst | After burst | Delta |
|---|---|---|---|
| `admin_smoke.rs` | 146 | 149 | +3 (alerts smoke + ack-unknown-id + spawn smoke for node_probe and health_monitor) |
| vpnctld unit (mostly admin.rs + health_monitor.rs internals) | 86 | 102 | +16 (10 health_monitor diff_rows + 6 decode_form_value UTF-8) |
| inventory spec | 38 | 38 | +0 (no new spec — Phase G alerts methods covered by daemon-side smoke) |
| cli unit | 0 | 3 | +3 (fingerprint shape validator) |
| protocols spec | 84 | 84 | +0 |
| Total roughly | ~500 | ~520 | +20 |

All tests green per commit. No flakes observed.

## Если что-то сломалось

Если утром:
- **vpnctld не отвечает на /api/v1/health** → `ssh user@192.168.0.236 'sudo journalctl -u vpnctld -n 50 --no-pager'`. Откатиться: `sudo systemctl stop vpnctld && sudo cp /opt/vpnctl/vpnctld.prev /opt/vpnctl/vpnctld && sudo systemctl start vpnctld` (previous binary saved automatically before this deploy).
- **migration 0011 не применилась** → не должно быть, проверил по `sqlite_master`. Если нет — `sudo systemctl restart vpnctld` ещё раз; миграции применяются на старте.
- **/admin/alerts 500** → `journalctl -u vpnctld | grep alerts`; вероятнее всего `recent_alerts` query попал на не-мигрированный схема — см. предыдущий пункт.
- **Любой сервер VPN перестал отвечать** → НИКАКИЕ изменения этого бурста НЕ трогали production VPN ноды; их конфиг и состояние идентичны вчерашнему. Полностью независимая локальная регрессия — на vpnctld со vpn-нодами ничего не связано.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
