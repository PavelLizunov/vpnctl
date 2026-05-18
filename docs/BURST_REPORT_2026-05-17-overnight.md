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
| `cf79184` | docs(burst): append fix-trail + sqlx-migration takeaway |
| `486dcd7` | docs(claude.md): review-agent must grep codebase for new-fn duplicates |
| `fdba9e0` | refactor(daemon): extract decode_form_value to http_util module |
| `ec275c5` | refactor: extract vpnctl-host-fingerprint crate — single source of truth |

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

## Post-burst cleanup (morning of 2026-05-18)

Pavel asked «нашёл что-то нелогичное или излишнее в кодовой базе?».
Honest audit produced four findings + a methodology blind spot. Three
fixes shipped, one logged for next session, plus the prompt-template
update.

**Methodology blind spot — review-agent only sees the diff.** During
the overnight burst I introduced `cli/src/cmd/server.rs::fetch_
fingerprint_via_keyscan` and `daemon/src/handlers/admin.rs::keyscan_
fingerprint_blocking` in commit `2fda5c6`. Both were near-duplicates
of `daemon/src/wizard_bootstrap.rs::ssh_keyscan_fingerprint` shipped
months earlier in Phase E (`4477199`). The review-agent flagged real
bugs in the two NEW copies (`--` flag-injection defense, spawn_
blocking wrap) and I fixed them in `9819538` — but the wizard's
copy stayed broken because it was outside the diff. Same blind spot
caught a triplicated `is_valid_sha256_fingerprint` where the three
copies had drifted on the accepted base64 alphabet (URL-safe `_-`
allowed by some, rejected by others) — meaning a fingerprint
accepted by the web validator could be rejected by the inventory's
INSERT-time gate, producing a confusing late failure.

Both consolidated into the new `vpnctl-host-fingerprint` crate
(commit `ec275c5`, +76 / −339 net LOC). The crate exports
`validate_shape`, `fetch_via_keyscan`, `build_keyscan_args` (pub
to pin the `--` invariant in tests), and three Display-implementing
error variants. 26 spec tests including 3 that pin
flag-injection / `-t ed25519,rsa` / `-T 10` invariants. Review-
agent on this commit returned 3 minors — all fixed in-band:
positional algo-token match (substring match would mis-pin a
fingerprint on a DNS-legal hostname containing `ssh-ed25519`);
the argv-test extraction itself; `JoinError::is_panic()` to
distinguish panic from cancellation in the wizard's error report.

CLAUDE.md `review-agent` prompt template now includes a **new
category #4 DUPLICATION across codebase** (`486dcd7`) directing
the agent to grep the whole repo for similar implementations of
any new ≥20-LOC function. Test-pinned by example so the keyscan
triplication couldn't slip past a future review.

Background-agent parallelism: while I built the host-fingerprint
crate, a second agent extracted `decode_form_value` from
`admin.rs` to a new `daemon/src/http_util.rs` module (`fdba9e0`).
Pure move + 6 spec tests relocated. Set up so future surfaces
(CLI `vpnctl post`, future `/api/v1/*` form endpoint) don't
reinvent the function with the same Latin-1 bug the prior version
had before `aef1c6b`. Concurrent cargo invocations briefly
corrupted `target/debug/` and one Cargo.lock write — both
recovered cleanly (cargo regenerates incrementals; git checkout
restored the lock).

**Architectural audit** — 3 parallel review-agents on the burst
diff found no overengineering severity > cosmetic. Net architecture
verdict from the wider pass: **the system is well-fit for the
solo-operator scope.** Specific non-findings worth recording:
trait abstractions all have ≥1 real impl, no async wrappers
around sync code, no Repository pattern bloat, schema columns
all live, generic parameters all multiply instantiated, background
tasks unified in one `app::build` instead of scattered. Three
cosmetic smells logged below.

**Follow-ups (not blocking, deferred):**

  * `format_size_bytes(u64) -> String` ✅ **shipped** as
    `d41630d` — moved to `vpnctl_core::humanize::format_size_bytes`,
    12 spec tests, deck rendering verified on /admin/settings.
  * `crates/hosters/` (67 LOC, 3 hardcoded impls) — still pending.
    Architectural decision (fold to core vs inline to wizard) is
    Pavel-gated.
  * `daemon/src/handlers/admin.rs` — was 6361 LOC, now 6094 after
    tonight's series of helper extractions (form_field, path_segment_
    encode, bad_request/not_found/unauthorized/error_resp,
    delete vpn_kpi_tile). Split into submodules still deferred —
    mechanical move-only refactor that changes git blame for 6K LOC;
    worth doing once we hit 7K OR when next feature touches >3
    sections, NOT in the middle of an autonomous loop.

## Autonomous loop (overnight 2026-05-18, post-morning-audit)

Pavel asked «давай вообще все не останавливаясь, после каждого
действия делай ревью через запуск параллельного агента и таже
проверяй методологию». Loop ran 8 commits + one CI-recovery hotfix
+ one methodology pin. Each non-docs commit went through a parallel
review-agent before merge per the directive.

### Commits shipped

| # | Hash | What | Review-agent verdict |
|---|---|---|---|
| 1 | `1b633ad` | `form_field` + `path_segment_encode` → `daemon::http_util` (~11 inline sites consolidated, including the wizard's local copy with admitting comment) | `[]` |
| 2 | `5c6d8d3` | `bad_request/not_found/unauthorized` helpers + generic `error_resp` (40 sites) **+ newline-injection defense** in `error_text` (operator's curl-pipe-head can't be split anymore) | 5 findings — 1 important (3 missed exotic-code sites) + 1 important (response-splitting depth-in-defense); both applied inline |
| 3 | `f8fbf9e` | `vpnctl_core::shell::single_quote` (triplicated across russh / cli / wizard) + `ssh_safety_opts` extracted (2 SSH-arg blocks). New crate-level module with 8 spec tests (`$HOME` literalness, multi-quote escape chain, ssh-key round-trip). | `[]` |
| 4 | `8d38a6f` | Delete `vpn_kpi_tile`, fold into `status_tile(_, _, "var(--ink)")` — byte-identical HTML; UI dedup. | `[]` (CSS char-by-char identical) |
| 5 | `cbb4d41` | **feat(inventory)**: Phase G chunk 2 part 1 — `insert_alert_if_no_unacked` + `ack_open_alerts` + migration `0013_admin_alerts_unique_unacked.sql` (partial UNIQUE index on `(kind, COALESCE(server_id, '__GLOBAL__'))` WHERE `acked_at IS NULL`) + 13 spec tests by test-writer-agent | 2 important (`INSERT … SELECT … WHERE NOT EXISTS` race across pool connections) — both fixed by routing through SQL-engine-level UNIQUE constraint + `INSERT OR IGNORE`. 4 minor; 2 applied (inlined secret docs, acked-row regression test 12b). |
| 6 | `189c79c` | **feat(daemon)**: Phase G chunk 2 part 2 — `Probe` extended with `probe_source_ip` / `fail2ban_banned_ips` / `fail2ban_self_banned` (5 new parser tests); `ProbeOutcome` enum + `FailState` consecutive-fail counter + `dispatch_alerts` free fn + `auto_ack` helper. Alerts deck copy updated. 4 new admin_smoke tests (kind-render × 2 + dispatch-integration × 2). | 2 important (full re-fire cycle test, dispatch_alerts integration test) + 2 minor (DRY `auto_ack` extraction); all 3 applied inline. |
| 7 | `818bad2` | style: cargo fmt hotfix — CI on cbb4d41 + 189c79c both red on fmt-check after I ran tests + clippy but skipped fmt. No behaviour change. | docs-only (skip review per CLAUDE.md rule) |
| 8 | `0310ad0` | docs(claude.md): pin `cargo fmt --check` as explicit pre-push gate with the 3 scenarios that don't look fmt-affecting but are (test-writer-agent output, mass-replace scripts, ≥2-file commits). Recommendation: prefer `cargo fmt --all` over `--check` so any drift lands in the same commit. | docs-only |

### What's actually live on 192.168.0.236

- All 8 commits deployed via zigbuild (max GLIBC_2.30 ≤ bookworm's 2.36).
- `/admin/users/no-such` still returns the unified `vpnctl admin: no such user 'no-such'\n` prefix; newly verified that `/admin/users/%0A.poison` collapses the embedded `\n` to a space (od -c shows exactly 1 trailing newline in the body).
- `/admin/alerts` deck now mentions «unreachable hosts» + «locked myself out» categories; rendering verified.
- Phase G chunk 2 detectors are **dormant** on the homelab — they require the deploy SSH key to be authorised on each production VPN node. Once authorised, the `node_probe_poller` ticks every 10 min (default `VPNCTLD_NODE_PROBE_INTERVAL_SECS`), and 3 consecutive failures (default `VPNCTLD_UNREACHABLE_THRESHOLD`) fires `server.unreachable`. The `server.fail2ban.banned_self` detector fires immediately on any probe that observes the daemon's own outbound IP in the node's fail2ban-banned list.

### Codebase trim summary (cumulative for tonight)

Net diff across the 6 functional commits: **+~1900 / −~1100 lines**, but most additions are new tests + extensive rustdoc. Production code dropped by **~400 LOC** of duplicated boilerplate. `admin.rs` shrank from 6361 to ~6094 lines. Two new top-level modules added (`crates/core/src/{humanize,shell}.rs`), one new top-level crate (`vpnctl-host-fingerprint` from the morning audit). One new migration (0013) — additive UNIQUE index, no destructive changes.

### Methodology slip-and-fix

The two CI fmt-check failures in this session are the only methodology violation. Root cause: I ran `cargo test` + `cargo clippy` locally before push but skipped `cargo fmt --check`, twice. Pinned in `0310ad0` (CLAUDE.md update) with an explicit list of scenarios that don't visually look fmt-affecting. Next session should not repeat.

### What's left in v0.8

The roadmap's v0.8 «closing the last gaps» list is essentially **done** after tonight:

  * ✅ Phase H chunk 4 — node_probe poller wiring (shipped earlier in `d391c73`)
  * ⏳ Phase G chunk 3 — webhook transport. **BLOCKED on Pavel decision**: Telegram bot / ntfy.sh / journald. Implementation is ~150 LOC in any direction.
  * ✅ L7 destructive-op gate — shipped `aa83241`
  * ✅ `vpnctl server set-fingerprint` CLI + web — shipped `2fda5c6`
  * ✅ `decode_form_value` UTF-8 fix — shipped `aef1c6b`
  * **NEW**: Phase G chunk 2 detectors — shipped `cbb4d41` + `189c79c`

Once Pavel picks a webhook transport, v0.8 ships.

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
