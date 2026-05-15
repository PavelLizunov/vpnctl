# Autonomous-mode plan for vpnctl

**This document is the source of truth for autonomous loop iterations.**
Read it FIRST every iteration. Update the "Progress log" section
whenever you ship a commit.

Pavel invokes autonomous mode by `/loop` with the prompt at the bottom
of this file. The loop fires the same prompt each iteration; the
prompt tells you to (a) read this doc, (b) execute exactly one
backlog item, (c) update the progress log, (d) schedule next wake.

---

## Goal

Work through the vpnctl roadmap one self-contained chunk per iteration.
Each iteration = code + tests + clippy + fmt + deploy + commit + push +
update this doc. Don't try to ship more than one commit per iteration —
that's how mistakes pile up.

Stop when:
* The "Backlog" list below has no items not blocked on Pavel-only
  decisions, OR
* You've shipped 12 commits in this autonomous run (counted from the
  "session-started" marker in the Progress log), OR
* Three consecutive iterations failed at the same step (CI red, deploy
  fail, etc.) on the same task → log to "Needs Pavel" and stop, OR
* The currently selected backlog item asks for a Pavel-only decision
  → log to "Needs Pavel" and stop.

---

## Per-iteration algorithm (BLOCKING — follow exactly)

### Step 0 — boot

Run in parallel:
* `cd /home/user/vpn-control/vpnctl && git pull --ff-only`
* `export PATH="$HOME/.cargo/bin:$PATH" && cargo --version`
* If `cargo` missing → reinstall via the rustup one-liner (CLAUDE.md
  "Грабли"). If reinstall fails → log "cargo missing, can't proceed"
  to "Needs Pavel" and stop.

### Step 1 — pick task

Read the **Backlog** section below. Pick the FIRST item that:
* is not marked `[shipped]`, `[blocked]` or `[needs-pavel]`,
* has all listed prerequisites shipped,
* fits in one iteration (estimate < 400 lines net diff including tests).

If nothing fits, stop.

### Step 2 — write code

Apply the task's spec. Write tests in the same commit. For tasks that
expose a NEW public function/API, **use `Agent(general-purpose,
test-writer-agent)`** with the prompt template from CLAUDE.md
("test-writer-agent prompt template") — give the agent ONLY the spec
+ behaviour contract, NEVER the impl. Hand-written tests are OK for
tasks that just wire existing APIs.

### Step 3 — local gates (BLOCKING)

* `cargo fmt --all`
* `cargo clippy --workspace --all-targets -- -D warnings` — must be
  green. If red → fix; if can't fix in 3 attempts → log to "Needs
  Pavel" and stop.
* `cargo test --workspace` — must be green; same 3-attempt rule.

The git-gate hook (`.claude/hooks/git-gate.sh`) ALSO runs these on
commit, but running them yourself first lets you iterate faster.

### Step 4 — review-agent

Run `Agent(general-purpose, review-agent)` with the CLAUDE.md
"review-agent prompt template", on the diff of THIS commit
(`git diff HEAD --stat` first to size; if > 800 lines, summarize the
non-essential parts). Process findings:
* `critical` → fix immediately, re-run gates;
* `important` → fix unless it requires a Pavel-only decision (then
  log to "Needs Pavel");
* `minor` → fix opportunistically; OK to defer with a note.

### Step 5 — deploy + live verify

Build release: `cargo build --release -p vpnctld`.
SCP to 192.168.0.236, install, restart, check `is-active`. Run a
smoke curl that exercises the new feature (the spec for each
backlog item lists the expected curl).

If the smoke fails → revert the deploy by re-installing the previous
binary (use `git stash` + previous-commit binary), log the failure to
"Needs Pavel", stop.

### Step 6 — commit + push

The git-gate hook runs fmt + clippy + test on commit and the same +
test on push. If the hook blocks → fix; if the gate fires twice on
the same content → log to "Needs Pavel" and stop.

Commit message: long-form, follows the existing pattern (root cause /
fix / tests / live verify / co-author trailer).

### Step 7 — update Progress log + ScheduleWakeup

Append to "Progress log" below: timestamp, commit hash, what shipped,
test count delta, "live verified: yes/no".

If more backlog items remain AND budget not exhausted: call
`ScheduleWakeup(60s, "next iteration of autonomous vpnctl")`.

If the loop must end: omit `ScheduleWakeup` (the loop terminates
naturally).

---

## Safety rails (NEVER, no matter what)

1. **Do NOT change SSH port on DigitalOcean droplets.** DO Cloud
   Firewall blocks everything except 22 (per CLAUDE.md infrastructure
   notes). If a backlog item touches a DO server, leave SSH on 22.
2. **Do NOT commit `inventory/*.env`.** They contain UUIDs and
   passwords; they are gitignored and must stay so.
3. **Do NOT `git push --force` on `main`** for ANY reason. Even fixing
   a corrupted commit — make a new commit instead.
4. **Do NOT bypass the git-gate hook with `--no-verify`** unless
   you've spent 3 attempts trying to make the gate pass legitimately.
   If you do bypass, the next iteration's first task is to fix what
   the gate caught.
5. **Do NOT touch production VPN servers** (`84.19.3.104` and others
   in `inventory/`). Phase E (add-server wizard) is allowed to
   bootstrap NEW servers via stg, but never to mutate existing prod.
6. **Do NOT delete data in `/var/lib/vpnctl/inv.db`** under any
   circumstance. Backup automation exists; restore is manual.
7. **Do NOT migrate from bash `vpn-control` to vpnctl** (Phase C-5)
   in autonomous mode. The cutover is destructive and Pavel must be
   present.
8. **Do NOT change `.claude/settings.json` to disable the gate.**
   Disabling the gate to fix a problem the gate is catching is the
   wrong direction.
9. **Do NOT make architectural decisions Pavel hasn't confirmed.**
   Look at "Strategic context" in CLAUDE.md — if a task implies a new
   answer (e.g. multi-tenancy, mobile UX), log to "Needs Pavel".
10. **Do NOT touch backup encryption keys.** The recipient pubkey
    on 236 and the private key on 207 + Pavel's laptop are in their
    final state; rotation is Pavel-only.

---

## Backlog (priority order, top first)

| # | Status | Task | Spec / scope | Est. lines |
|---|---|---|---|---|
| 1 | [shipped backend] | **Track-2 chunk 2 — persistent auto-ban** | Backend SHIPPED in iteration 1: migration 0005, Ban API, handler escalation after K=10 429s, cleanup task. UI surface (admin tile + per-user view) deferred to Phase D / a later iteration since it's purely cosmetic on top of the ban table. | ~250 |
| 2 | [shipped] | **Phase D — audit timeline UI** | Inventory `recent_audit_paginated` + handler rewrite + filter form + sticky-date sections + pagination + CSV export. | ~600 (shipped iter 2) |
| 3 | open | **Phase F — monitoring sparklines** | New endpoint `/api/v1/stats/sub-access?bucket=hour&since=24h` returns JSON `{buckets: [{ts, hits, distinct_ips}]}`. New section on `/admin/monitoring` (currently placeholder) renders inline-SVG sparkline per metric. Reads from `sub_access_log` aggregated server-side. No JS — pure SSR. Tests: stats endpoint shape, sparkline svg width/height pinned. | ~250 |
| 4 | open | **Phase E — add-server wizard (THE feature)** | Multi-step form on `/admin/servers/new`. Step 1: IP + root password. Step 2: SSE-streamed log of `vpnctl bootstrap` + `vpnctl deploy` operations (push pubkey, harden SSH, install fail2ban, install sing-box, render config, start, prove live). Step 3: completion screen with the new server's id + first-grant prompt. **This is the largest item; expect 3 sub-iterations.** Sub-iteration 4a: form + `/admin/servers/new` GET handler + step-1 submit handler that validates IP+password and stashes to a session cookie (signed). Sub-iteration 4b: SSE handler that streams `vpnctl bootstrap` output via `tokio::process::Command`. Sub-iteration 4c: completion + audit + integration with existing `/admin/servers` list. | ~600 (3 sub-commits) |
| 5 | open | **C-3.4 — delete user (web)** | `POST /admin/users/{id}/delete` with double-submit confirm: GET `/admin/users/{id}/delete-confirm` shows "type the user-id to confirm" form; POST processes only if `confirm=<exact-id>`. Cascade behaviour already in inventory (FK SET NULL on sub_access_log per migration 0004; CASCADE on grants per 0001). Audit + redirect to `/admin/users`. Tests: requires confirm, CASCADE works, sub_access rows survive (per 0004). | ~150 |
| 6 | needs-pavel | **C-5 — migrate from bash vpn-control** | DESTRUCTIVE on production state. Per safety rail #7, Pavel must be present. Don't auto-pick this. |
| 7 | open | **Track-3 prep — clash-api on sing-box** | Just the kernel-side change: `crates/kernels/src/sing_box.rs::render_config` adds `experimental.clash_api: { external_controller: "127.0.0.1:9090" }` block. NO daemon-side polling yet — that's a follow-up. Tests: rendered config has the clash_api block; existing config tests still pass. | ~80 |
| 8 | open | **Track-4 — UA fingerprint heuristic** | Read-only analysis on top of Track-1's `sub_access_log`. New inventory method `ua_clusters_for_user(uid, since_hours) -> Vec<{ua, ips, distinct_asns}>`. UI: collapsible "UA fingerprint" section on user-detail showing one row per distinct UA with the IP set + "likely roaming" / "likely shared URL" classifier. Classifier rule (initial cut): if one UA appears across >2 distinct /16s simultaneously within a 1h window → "shared". | ~250 |
| 9 | open | **Phase G — infra notifications (chunk 1: server-down)** | Periodic task in daemon: every 5 min, ping each server in inventory (TCP-connect to ssh_port). On state change healthy→down, write audit row `server.health.down` and push a Telegram message via Bot API. Pavel's bot token + chat id read from env vars. Tests: state machine transitions, audit on transition, no spam on flap. | ~250 |

(When a task is shipped, change `open` → `[shipped <commit-hash>]`.)

---

## Needs Pavel (write here when blocked)

*(Empty at start of run. If you skip a task because it needs a
Pavel-only decision, append a row here with: timestamp, task #,
brief reason. Pavel reviews this in the morning.)*

---

## Progress log (append-only)

*(One line per shipped commit. Format: `YYYY-MM-DDTHH:MM:SSZ |
<hash> | <task #> | <one-line summary> | tests N→M | live: yes/no`)*

session-started: 2026-05-15T15:59:45Z

2026-05-15T16:50:00Z | 555fd5a | task#1 | Track-2 chunk 2 backend (migration 0005 + Ban API + handler escalation at == K + audit row + cleanup task) | tests 167→177 (+10: 9 spec_sub_rate_bans via test-writer-agent + 1 e2e ban) | live: yes (15 429s → 1 ban row, audit landed, 21st req returns ip-ban body) | review-agent: 3 important fixed inline (audit gap, conditional reset, ==K dedupe)

2026-05-15T17:35:00Z | <pending-commit> | task#2 | Phase D audit timeline UI (inventory recent_audit_paginated + handler rewrite + filter form + sticky-date headers + pagination + CSV export) | tests 177→190 (+13: 8 spec_audit_paginated via test-writer-agent + 5 admin_smoke audit) | live: yes (filter `user_` literal-matches 0 rows, `user.` matches via prefix; CSV download has Content-Disposition + RFC 4180 escape) | review-agent: 3 important fixed inline (LIKE escape, CSV `||` ambiguity, pagination row-count) + 4 minor fixed (dead idx, url-builder unification, page overflow clamp, payload Err warn-log)

---

## Loop prompt to feed `/loop` (copy this verbatim)

```
Read docs/AUTONOMOUS_PLAN.md in vpnctl. Execute exactly one iteration
of the per-iteration algorithm: pick the next backlog item, ship it
(code + tests + review-agent + deploy + commit + push + log update),
then call ScheduleWakeup(60s) for the next iteration. Stop conditions
and safety rails are in the doc — respect them rigidly. If you stop,
write a one-line summary to "Needs Pavel" or "Progress log" so Pavel
knows why on his return.
```
