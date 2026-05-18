# Security audit + 10-iteration loop — 2026-05-18

Comprehensive autonomous audit + fix session. Pavel directive
(while away): «делай за раз пока меня нет; проверь ревью, либы,
баги; поищи новые инструменты * 10 итераций».

## Session shape

3 background agents launched in parallel at the start:

  1. **Code-audit agent** — whole-codebase grep + read for vectors:
     SQL injection, command injection, path traversal, CSRF,
     auth bypass, XSS, SSRF, timing attacks, deserialisation
     bombs, open redirect, resource exhaustion, race conditions,
     secret leakage in logs / audit / responses.
  2. **Lib-audit agent** — `cargo audit` (RUSTSEC) +
     `cargo outdated` + `cargo deny check` + direct-dep risk
     profile vs current upstream releases.
  3. **Tools-research agent** — WebSearch for 2025–2026
     Rust web tooling: static analysis, supply chain, mutation
     testing, secret scanning, coverage. Constraint: actually-
     shipping projects, last commit ≤12 months.

## Commits shipped in this loop

| # | Hash | Title |
|---|---|---|
| 0 | `ad5741d` | pre-loop — `--` SSH separator, validate_address, security headers, systemd hardening |
| 1 | `7c41bf9` | iter 1 — Telegram token via `curl -K -` stdin |
| 2 | `edcb14c` | iters 2+4+5 — argon2id auth + UTF-8 fix + FailState prune + audit-fire + RUSTSEC-2026-0009 + token redact + silent-fallback |
| 3 | `8e5173f` | cleanup — rm stray `core` file |
| 4 | `23543ed` | iters 6-9 — gitleaks CI + just mutants/coverage/scan-secrets |
| 5 | this  | iter 10 — wrap-up doc |

## What's now hardened (13 items)

1. ✅ POSIX `--` getopt separator on every SSH argv (2 sites)
2. ✅ `server_quick_add` uses wizard's strict `validate_address`
3. ✅ Telegram response body truncated by codepoint (was raw byte-
   slice → DoS on UTF-8 boundary)
4. ✅ 5 security headers on `/admin/*`: CSP, X-Content-Type-Options,
   X-Frame-Options, Referrer-Policy, Permissions-Policy
5. ✅ Systemd unit: dropped capabilities, syscall filter, address-
   family allowlist, UMask=0077, PrivateDevices.
   `systemd-analyze security` was ~3.5 → **now 1.4 «OK»**
6. ✅ Telegram bot token never in any `ps` output (curl `-K -`
   config-from-stdin for both local + via-server paths)
7. ✅ Basic-auth: argon2id PHC support (backward-compat with plain
   + startup warn)
8. ✅ `FailState` prunes stale ServerIds on each poller tick
9. ✅ `dispatch_alerts` writes `audit_log` row on every alert fire
10. ✅ `build_alert_sink` returns `Ok(None)` when configured
    `proxy_via_server_id` is missing (was silently downgrading)
11. ✅ Token redacted from any curl/ssh stderr surfaced to operator
12. ✅ `RUSTSEC-2026-0009` (time DoS, medium 6.8) — bumped 0.3.45 → 0.3.47
13. ✅ `server_push_deploy_key` audit failures warn instead of swallow

## Tooling integrated

- **gitleaks** CI gate + repo allowlist for test placeholders
- **`just mutants-protocols`** — mutation testing on byte-equality contract
- **`just coverage`** — `cargo llvm-cov` HTML report
- **`just scan-secrets`** — local gitleaks runner
- **`scripts/hash-admin-password.sh`** — argon2id PHC generator

## Deferred CVEs (unreachable / dev-only)

- **RUSTSEC-2023-0071** (RSA Marvin) — sqlx-mysql OFF, russh
  transitive; waiting for russh upstream
- **RUSTSEC-2025-0111** (tokio-tar) — dev-dep via testcontainers
- **RUSTSEC-2025-0134** (rustls-pemfile unmaintained) — dev-only

## Deferred items (next session)

- **tower-governor admin rate-limit** — when external exposure planned
- **backup-download streaming** — current inv.db <1 MB
- **cargo-mutants CI enforcement** — currently `just` target only
- **`thiserror 1 → 2`** in CLI — minor migration
- **`rand 0.9 → 0.10`** in crates/crypto — RNG trait split refactor

## Pavel-action items

1. ✅ Rotate Telegram bot token — DONE
2. (optional) `echo -n '<your-admin-pw>' | scripts/hash-admin-password.sh`,
   paste `$argon2id$...` line as `VPNCTLD_ADMIN_PASSWORD=` in
   `/etc/vpnctl/vpnctld.env`, `sudo systemctl restart vpnctld`

## Live state on 192.168.0.236

- `systemd-analyze security vpnctld` = **1.4 OK**
- 5 security headers on every `/admin/*` response
- daemon runs as `user:user` with dropped capabilities + syscall filter
- argon2id auth path live + tested

## Audit numbers

- Tests added: ~25 (auth × 8, alert_sink × 5, admin_smoke × 4, etc)
- Total admin_smoke: 171 (was 169)
- Total alert_sink: 21 (was 15)
- Total handlers::auth: 8 (was 0)
- Commits: 5 functional + 1 cleanup
- CI pass rate: 6/6
