# Contract: admin UI quality

## 1. Intent & Invariants

- What: the admin UI is the operator's only surface, so it has its own
  Definition of Done beyond "tests pass". Six layers, each catching a strict
  subset the others miss.
- Invariants:
  - Every operator-facing error body in the `/admin/*` tree starts with
    `vpnctl admin: `, ends with a single `\n`, and (where applicable) includes
    the offending value + allowed alternatives so the operator can fix the
    request without consulting source.
  - Error copy never contains shell instructions (operator-action policy).
  - Every empty state quotes a literal CLI command.

## 2. The six layers

| # | Layer | Catches | Misses |
|---|---|---|---|
| 1 | `cargo clippy --workspace --all-targets -- -D warnings` | API misuse, dead code, unwrap/expect outside tests | CSS/HTML-string-only issues |
| 2 | `cargo test -p vpnctld --test admin_smoke` | DOM presence, routing, status codes, escaping, masking | visual layout |
| 3 | Copy-contract tests (subset of admin_smoke) | backend error-prefix drift, headline/deck/empty-state copy regressions | unpinned NEW copy (pin it in the same commit) |
| 4 | review-agent | logic bugs, security, library misuse | whether the page renders well |
| 5 | Live deploy + curl on the prod host | runtime + auth + DB integration | visual layout (curl never paints) |
| 6 | `scripts/visual_check.py` (headless Chrome over CDP) | panel overlap, grid overflow, font fallback, anything pixel-level | cross-browser quirks (homelab Chromium only) |

Copy contract sources of truth: `error_text()` in `daemon/src/handlers/admin`
(the basic-auth layer duplicates the literal prefix because it runs before the
admin module is reachable). Pinned by
`admin_backend_error_responses_use_unified_prefix`,
`admin_frontend_section_headlines_match_voice`,
`admin_empty_states_quote_cli_commands`.

Frontend voice: sentence-case, em-dashes, mono-font CLI inline. When adding a
screen: write headline + deck first, then add a copy-contract test in the SAME
commit.

Run order for any user-visible UI change: clippy + admin_smoke → deploy →
curl the error paths (expect the `vpnctl admin:` prefix) → `visual_check.py`
PNG of every changed page → actually look at the PNGs.

## 3. Verification Checklist

- [ ] Layers 1–3 pass locally.
- [ ] New copy pinned by a copy-contract test in the same commit.
- [ ] After deploy, error responses match the `vpnctl admin: ` prefix.
- [ ] Visual PNGs captured and inspected for changed pages.
