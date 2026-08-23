# Contract: agent workflow (review / test-writer / gates)

## 1. Intent & Invariants

- What: every code change passes independent review and spec-derived tests
  BEFORE commit, and the CI watch is blocking after push. Agents are isolated:
  they see only what is pasted into their prompt — brief them like a new
  colleague, never refer to "the discussion above".
- Invariants:
  - review-agent sees ONLY the diff (never the design reasoning).
  - test-writer-agent sees ONLY the spec (never the implementation). A failing
    spec-test means the implementation is wrong or the spec is ambiguous —
    never weaken the test to make it pass.
  - No commit on top of unresolved red CI.

## 2. Process contract

Pre-commit, in order:
1. **review-agent** — independent reviewer over the diff. Finds issues in
   priority order: (1) correctness — bugs, swallowed errors, races, command
   injection in exec, path traversal, unhandled panics; (2) architecture —
   Kernel×Protocol violations, stateful-where-stateless; (3) security — secrets
   logged, missing host-key verification, weak randomness; (4) duplication —
   for every new function ≥ 20 lines, grep the repo for near-duplicates, report
   HIGH if one exists (extract a shared helper, don't inline both); (5) test
   coverage — new public function without an error-path test; (6) library
   misuse vs official russh/sqlx/tokio/clap patterns. Output: a single JSON
   array `[{severity, file, issue, fix}]`, ≤ 300 words. Do NOT comment on
   style/formatting, doc completeness, naming taste, or micro-optimisations.
2. **test-writer-agent** (new public functions/APIs) — writes Rust tests from
   the spec alone: signatures + "must" rules + behavior contract; each test
   gets fresh state/tempdir; names describe the spec rule; cover happy path,
   one expected-failure path, one boundary edge per function; no "call and
   assert no panic" tests; `#[allow(clippy::unwrap_used, clippy::expect_used)]`
   on the test module only.
3. **Local gate** — `just ci` (gc + fmt-check + clippy + test + deny). Run
   `cargo fmt --all` before testing. Docs-only changes may skip steps 1–2 but
   NOT the fmt-check.

Hotfix exception (ALL three must hold): ≤ 5 lines, exactly one surface touched,
no output pinned by `*_byte_equal*` tests changes.

Post-push: `gh run watch <id> --exit-status`; red → `gh run view --log-failed`
→ fix → push. A red head commit makes the next commit either its hotfix or a
wait.

## 3. Verification Checklist

- [ ] review-agent ran on the diff; `critical` + `important` findings fixed
      (`minor` is opt-in).
- [ ] Spec-tests written for new public APIs and run in-session.
- [ ] `just ci` green with recorded exit codes.
- [ ] After push, CI watched to completion; green before the next commit.
