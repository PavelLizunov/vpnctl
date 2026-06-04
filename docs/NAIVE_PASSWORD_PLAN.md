# Naive — fleet delivery plan

Two orthogonal parts. **Part A** decouples the `naive` protocol's per-user
credential from `tuic_password`. **Part B** delivers the naive URI into the
endpoint the operator actually uses (`/api/v1/app/config`, the "ninitux"
vpn-router app), which today is VLESS-only by design.

| Part | What | Status |
|---|---|---|
| **A** | dedicated `users.naive_password` secret | ✅ approved 2026-06-04 — ready to implement |
| **B** | render naive URI in `/api/v1/app/config` | 🔬 design — gated on a one-device app-tolerance test |

---

## Background — two distinct gaps

1. **Credential gap.** `naive` reuses `User.tuic_password` (server basic-auth
   password = client password). 33/40 production users migrated VLESS-only and
   have **no** `tuic_password` → `client_config`/`share_link`/`server_inbound`
   all fail for them (`crates/protocols/src/naive.rs:176`
   `"user '…' has no tuic_password"`). **Part A** fixes this.

2. **Delivery gap.** Two subscription endpoints render differently:
   - `/sub/<token>` (`daemon/src/handlers/sub.rs`) — sing-box JSON; iterates
     **all** enabled+visible protocols (`for pid in &server.enabled_protocols`)
     → **renders naive**.
   - `/api/v1/app/config/<device_id>` (`daemon/src/handlers/vpn_router.rs:294`
     `collect_vless_uris_for_user`) — base64 of newline-joined `vless://` only.
     Hardcoded `if !visible.contains("vless+reality") { continue }` at line 329,
     no loop over other protocols. Byte-compatible with the decommissioned
     Python subscription-server (NM-1..7), which only ever emitted `vless://`.
     → **never renders naive**, regardless of Part A.

   The operator interacts with users **exclusively** through endpoint #2.
   So naive is invisible to the real fleet until **Part B** lands.

---

## Part A — dedicated `naive_password`

### Goal
New secret column `users.naive_password`, minted for every user (new users in
`add_user`; existing 40 via startup backfill). `naive.rs` uses it instead of
`tuic_password`. Removes the per-user `tuic_password` SQL stopgap.

### Blast radius (small)
- Migration `0031` is **additive** (`ALTER TABLE … ADD COLUMN`) → WAL-safe,
  online, trivially reversible (old binary ignores the column).
- `/api/v1/app/config` bytes **unchanged** (that path never reads naive secrets).
- `/sub` bytes change **only** for users granted naive on a naive server
  (today: `main-brat`, `naive-test`). The other 38 are byte-identical.

### Changes — commit by commit

**Commit 1 — schema + storage** (`core` + `inventory`)
- `crates/inventory/migrations/0031_users_naive_password.sql`:
  `ALTER TABLE users ADD COLUMN naive_password TEXT;`
- `crates/core/src/lib.rs`:
  - `User`: `#[serde(skip_serializing, default)] pub naive_password: Option<String>` (≈ line 130)
  - `Debug` impl: `.field("naive_password", &…map(|_| "<redacted>"))` (≈ 226)
  - secret tests (≈ 268, 288): add `"PW_NAIVE_MUST_NOT_LEAK"` (both) + `"naive_password"` (serialize test)
- `crates/inventory/src/sqlite.rs`:
  - **6 SELECTs** feeding `row_to_user`: 1502, 1566, 1577, 1634 (`u.` alias), 1810, 1982 — add `naive_password`
  - **INSERT** 1469 — add column + `.bind`, mint-if-absent (mirror `sub_token` 1454-1457)
  - `row_to_user` 4487 — `naive_password: r.try_get("naive_password")?`
  - new `backfill_naive_passwords(pool)` mirroring `backfill_sub_tokens` (4677, txn-wrapped/idempotent/crash-safe) + call in `open()` after line 470
  - test helper 4738 + a backfill unit test

**Commit 2 — protocol switch** (`crates/protocols/src/naive.rs`)
- 3 sites: `server_inbound` 133, `client_config` 148, `share_link` 176 —
  `tuic_password` → `naive_password`; error text → `"no naive_password"`;
  doc-comment 27/32.

**Commit 3 — `User { … }` literal compile-fix**
- `cargo build` enumerates every literal (CLI `user.rs`, web `admin.rs` ≈ 6801,
  restore, tests) → add `naive_password: None` (minting lives in `add_user`).
  `#[serde(default)]` keeps old JSON snapshots deserialising.

### Safety gates
1. `just ci` (fmt + clippy `-D` + test + deny)
2. independent review-agent on the branch
3. `daemon/tests/restore_e2e.rs` must confirm `/api/v1/app/config` bytes
   **unchanged** and `/sub` unchanged for non-naive users.

### Deploy (prod-safe + rollback)
1. **Backup `inv.db`** on 236 (as `user`, `VACUUM INTO`) — rollback point.
2. `cargo zigbuild` vpnctld (glibc ≤ 2.36) → scp → `systemctl restart`.
3. `open()` auto-runs `0031` + `backfill_naive_passwords` (40 rows, in a txn:
   all-or-nothing; failure → daemon won't start → roll back, no half-state).
4. Verify: daemon healthy; `count(*) WHERE naive_password IS NOT NULL = 40`;
   `/api/v1/app/config` byte-stable; `/sub` non-naive byte-stable;
   `/sub` main-brat now uses `naive_password`.
5. Re-deploy `cdn` (Caddyfile basic_auth ← `naive_password`); drop the
   main-brat `tuic_password` stopgap.

**Rollback:** additive migration → previous binary ignores the column;
restore the backup only if needed.

---

## Part B — render naive into `/api/v1/app/config`

### The hard requirement (operator's words)
> naive must appear in the subscription **without breaking vless under any
> circumstances**.

### The unknown we cannot resolve from docs
The vpn-router app (`app:"vpn-router" v2.4.1`) has only ever been fed `vless://`
(the legacy server emitted nothing else). Two failure modes are possible and
**undocumented for this app**:
- **Parser intolerance** — a strict line parser could reject the *whole*
  base64 blob on one unknown `naive+https://` line → client loses vless too.
- **No naive outbound** — sing-box's naive outbound ships only in Cronet
  builds; a minimal build may parse the line but be unable to tunnel it.

Reference sing-box subscription parsers *skip* unknown/unsupported lines, and
`naive+https://` is a recognised scheme — but that is not a guarantee for this
specific app. **Only an on-device test settles it.**

### Safe-by-construction design

1. **Opt-in = the naive grant.** `vpn_router.rs` appends a naive URI **only**
   for a (user, server) that is granted naive AND passes the existing
   `visible_protocols_for_subscription` filter it already calls for vless.
   → Any user **not** granted naive gets a **byte-identical** response.
   **vless cannot break for the 38 ungranted users — guaranteed, not tested.**

2. **Naive strictly last.** Emit all `vless://` first, then append naive URIs
   (two-pass: `collect_vless_uris` ++ `collect_naive_uris`). A line-by-line
   tolerant parser keeps every vless even if it chokes on the trailing naive.

3. **Request-time kill-switch (already exists).** NM-10 `hide` on
   `(server, naive)` is read on every request → hiding naive instantly reverts
   affected users to vless-only, **no redeploy**. This is the abort button.

4. **Device-test gate before any rollout.** After deploy, only `main-brat`
   (+`naive-test`) carry the naive line. Operator loads main-brat on one test
   device:
   - vless still connects? **and** naive usable? → proceed, grant gradually.
   - anything off? → `hide` naive on `cdn` (instant) → investigate.

   Gradual grant rollout (each grant = one opt-in) only after the device test
   passes.

### Honest guarantee statement
- **Ungranted users (the fleet default):** vless can **never** break — the
  render literally cannot add a naive line without a grant. Absolute.
- **Test/opted-in users:** worst case (intolerant app) breaks only *their*
  config, *instantly* revertible via `hide`, and we test before granting wider.
  "Physically impossible" isn't achievable for opted-in users without knowing
  the app's parser; "contained + instantly revertible + tested first" is.

### Changes
- `crates/protocols/src/naive.rs` — reuse `share_link` for the URI (single
  source of truth for the `naive+https://user:pass@domain#tag` format).
- `daemon/src/handlers/vpn_router.rs` — add `collect_naive_uris_for_user`
  (mirror `collect_vless_uris_for_user`: skip auto-suppressed, require naive in
  `visible_protocols_for_subscription`, require `naive.domain` server secret),
  caller appends after vless. NM-8 access-log path unchanged.
- tests: `daemon/tests/vpn_router_endpoint.rs` — ungranted user byte-identical;
  granted user gets naive **after** all vless; hidden naive → no line.

### Rollout order (depends on Part A landed first)
1. Land + deploy Part A (naive renders for all 40 once granted).
2. Land + deploy Part B (naive in `/api/v1/app/config`, opt-in by grant).
3. Device test on main-brat. Pass → grant naive to target users gradually.
   Fail → `hide` naive (instant), deliver naive via `/sub` instead, or
   investigate the app.
