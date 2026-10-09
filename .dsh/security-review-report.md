# Security Review Report: Incoming GitHub PRs

**Date:** 2026-09-23
**Repository:** `PavelLizunov/vpnctl`
**Review target:** 8 open PRs against `main` at `7d85d202d333d4387b83826183ebbc270a78abff`
**Overall risk assessment:** LOW
**Merge recommendation:** CONDITIONAL — retain at most one path-boundary PR; close the duplicates. Do not merge the CSV PR as a security fix without evidence for `%`/`|` formula triggers.

## 1. Executive Summary

The eight open PRs reduce to three proposed changes: five duplicates for the same `safe_return_to` check (#249–#253), two duplicates for CSV prefix handling (#241 and #247), and one tweak-error truncation change (#248). All reported CI checks pass. No PR has an independent submitted review; the PRs have only the automated Jules welcome comment.

The `safe_return_to` prefix check does accept a same-origin path such as `/admin/servers_evil`, but the inspected flow does not establish the advertised external open redirect: the value must begin with `/admin/servers`, while `//` is rejected. A single boundary-check patch is reasonable defense in depth, but the stated impact/severity is overstated. The `%` and `|` CSV change is not supported by the OWASP formula-trigger characters reviewed and changes exported values for otherwise ordinary fields. #248 is a bounded response-reflection reduction, not a demonstrated log-DoS fix.

| Severity | Confirmed | Reasoned hypothesis | Total |
|---|---:|---:|---:|
| CRITICAL | 0 | 0 | 0 |
| HIGH | 0 | 0 | 0 |
| MEDIUM | 0 | 0 | 0 |
| LOW | 1 | 0 | 1 |

## 2. Scope and Changes Reviewed

| PR(s) | Changed surface | Review notes |
|---|---|---|
| #253, #252, #251, #250, #249 | `daemon/src/handlers/admin/server_actions/billing.rs`; each also adjusts `docs/CODEBASE_INVENTORY.md` | Five alternate implementations/tests of the same path-prefix boundary check. Current vulnerable expression is `starts_with("/admin/servers")` at `daemon/src/handlers/admin/server_actions/billing.rs:162` on reviewed `main`. |
| #248 | `daemon/src/handlers/admin/helpers.rs`; inventory doc | Truncates invalid tweak values reflected in a 400 response. |
| #247, #241 | `daemon/src/handlers/admin/audit.rs`; inventory doc | Add `%` and `|` to the CSV field's leading-character quote list. #247 is the later duplicate and has additional comma-field tests. |

All checks shown by GitHub for these PRs passed: cargo check, fmt, clippy, deny, test, gitleaks, e2e, and the two soft-fail jobs. That establishes CI status, not correctness or independent review. #241 is based on an older base SHA and GitHub currently reports it non-mergeable; the other PRs were reported mergeable. The working tree was clean and on `main`; no files were checked out or changed except this report artifact.

## 3. Security Findings

### [LOW] Return-path boundary confusion permits unexpected same-origin path

- **Status:** Confirmed (boundary mismatch); external open redirect not confirmed.
- **Location:** `daemon/src/handlers/admin/server_actions/billing.rs:159-170` on `main`; candidate fix in #249–#253.
- **Reachability:** POST billing actions (`server_set_billing`, `server_advance_billing`, currency settings, and rate refresh) read `return_to` from the form and pass it to `Redirect::to` (`billing.rs:87-88, 109-110, 145-146, 155-156`). The admin router applies same-origin CSRF middleware (`daemon/src/app/routes.rs:630-645`).
- **Test coverage:** Candidate PRs add unit tests for suffixes such as `_evil`, `.evil.com`, valid subpaths, query/fragment delimiters, and traversal-like strings.

#### Description and impact

The current validation accepts any string beginning with `/admin/servers`; therefore `/admin/servers_evil` passes and redirects to that same-origin path. This violates the apparent allowlist boundary and can cause an unexpected navigation, but the evidence does **not** support the PR titles' claim of an external open redirect: the required leading slash and rejection of `//` prevent a network-path reference in the examined input, and no other redirect sink was found in this flow. The action is behind the admin route's same-origin CSRF layer. Treat as a low-severity validation hardening issue, not a demonstrated high-severity vulnerability.

#### Recommendation

If the desired contract is to stay under `/admin/servers`, accept one of #250–#253 (all use a valid boundary condition) or equivalent minimal fix and close the other four. #250 is a compact implementation with useful negative tests; #252 has the broadest explicit CR/LF cases. Avoid carrying five copies of the same fix. Re-review the merged candidate against the live base before merge.

### Investigated claim: `%` / `|` CSV formula or DDE injection (#241, #247)

The changed `csv_field` guard is at `daemon/src/handlers/admin/audit.rs:650-667` on `main`, and is used for actor/action/target/payload and access-export fields. The checked [OWASP CSV Injection guidance](https://community.owasp.org/attacks/CSV_Injection) identifies formula-leading characters such as `=`, `+`, `-`, `@`, tab, CR/LF, and locale-dependent full-width forms; it does not establish `%` or `|` alone as formula starters. `|` can appear inside certain DDE/formula syntaxes, but that does not show that a cell starting with `|` becomes a formula. Thus the PR description's `%`/`|` DDE claim is unsubstantiated by the source reviewed. Prefixing ordinary values with an apostrophe alters exported CSV data for consumers. **Recommendation:** do not merge #241/#247 as a security fix until the behavior is reproduced benignly in the supported spreadsheet products/locales and the intended export compatibility tradeoff is accepted. Prefer closing #241 if #247 is retained for further investigation; #241 is stale/non-mergeable.

### Investigated claim: response/log denial of service (#248)

`set_tweak_cookie` reflects a rejected `value` into the 400 body (`daemon/src/handlers/admin/helpers.rs:136-160`); #248 limits that reflection to 64 Unicode scalar values. The application has an 8 KiB request-body limit (`daemon/src/app/routes.rs:94-102`), and the shared error helper replaces CR/LF before returning a plain string (`helpers.rs:113-124`). In the inspected changed path, invalid values are not logged. Consequently, the PR usefully bounds response reflection, but the claimed log-memory/log-bloat DoS is not demonstrated and the request is already bounded. This is low-risk defense in depth, not a merge blocker.

## 4. PR-by-PR Recommendation

| PR | Status / recommendation |
|---|---|
| [#253](https://github.com/PavelLizunov/vpnctl/pull/253) | Duplicate of the return-path fix. Valid boundary logic; close if another candidate is selected. |
| [#252](https://github.com/PavelLizunov/vpnctl/pull/252) | Duplicate of the return-path fix; broad explicit invalid-input tests. Close if another candidate is selected. |
| [#251](https://github.com/PavelLizunov/vpnctl/pull/251) | Duplicate of the return-path fix; close if another candidate is selected. |
| [#250](https://github.com/PavelLizunov/vpnctl/pull/250) | Recommended compact candidate if choosing one; still do normal independent review before merge. |
| [#249](https://github.com/PavelLizunov/vpnctl/pull/249) | Oldest duplicate; close if another candidate is selected. |
| [#248](https://github.com/PavelLizunov/vpnctl/pull/248) | Reasonable bounded-reflection hardening; CI green. Merge is optional after normal review; don't describe as proven DoS remediation. |
| [#247](https://github.com/PavelLizunov/vpnctl/pull/247) | Hold/close pending evidence for `%` and `|` formula-trigger behavior; semantics of normal CSV values change. Later duplicate of #241. |
| [#241](https://github.com/PavelLizunov/vpnctl/pull/241) | Close as duplicate of #247; stale base and currently non-mergeable. |

## 5. Coverage Boundaries and Limitations

- Reviewed the eight open PR diffs, PR descriptions/comments/review records, current GitHub check status, the relevant current `main` handlers/router, and the referenced request-size/CSRF controls.
- Did not run builds locally; relied on GitHub CI for these exact PR heads. Did not open generated CSVs in Excel/LibreOffice or reproduce spreadsheet-specific behavior. No harmful formula or network payload was used.
- No independent review agent was dispatched in this runtime; this report is the coordinator's read-only assessment, not an independent acceptance review.
- This review does not certify the rest of the codebase or resolve behavior on every browser, proxy, or spreadsheet application.
- External reference used: [OWASP CSV Injection](https://community.owasp.org/attacks/CSV_Injection).
