# Contract: agent workflow (review / test-writer / gates)

## 1. Intent & Invariants

- What: every code change passes independent review before commit and
  spec-derived tests before acceptance; CI is blocking after push. Agents are isolated:
  they see only what is pasted into their prompt — brief them like a new
  colleague, never refer to "the discussion above".
- Invariants:
  - review-agent sees ONLY the diff (never the design reasoning).
  - test-writer-agent sees ONLY the spec (never the implementation). A failing
    spec-test means the implementation is wrong or the spec is ambiguous —
    never weaken the test to make it pass.
  - No commit on top of unresolved red CI.

## 2. Process contract

Review and prepare the candidate before committing.

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
3. **Validation** — run `cargo fmt --all` before committing. Push the task
   branch and validate its exact SHA on a HomeLab worker with `just check` and
   `just ci`, or publish a draft PR for the equivalent GitHub Actions checks.
   Docs-only changes may skip steps 1–2 and still require fmt-check.

### Remote builds and tests

Run compilation, release packaging, and tests that compile Rust on a HomeLab
worker or GitHub Actions. Keep the owner's workstation and `harness-test` for
editing, formatting, non-compiling checks, and orchestration.

1. Load the `homelab` skill through `harness-test` and follow the worker
   runbook there at
   `/var/lib/dsh/Project/homelab-infra-docs/docs/workers/permanent-workers.md`.
   Acquire the pool lease for `linux-worker` (VM 101) and verify SSH, disk
   capacity, and the required toolchain.
2. Push the committed task branch to GitHub. Fetch it on the worker and
   check out the candidate SHA as a detached `HEAD` in a clean task worktree.
   Verify `git rev-parse HEAD` before building or testing.
3. Save the lease ID, checked SHA, exit codes, and required artifacts before
   releasing the lease. If the worker is unavailable or unsuitable, validate
   the candidate through GitHub Actions as described below.

### Publishing for GitHub Actions validation

GitHub Actions is the required PR gate. A draft PR can run build and test
checks that have not run on a HomeLab worker.

1. Work in a dedicated task branch and worktree. Complete independent review
   and write any required spec-tests before committing code.
2. Run `cargo fmt --all`, `cargo fmt --all -- --check`, `git diff --check`,
   generated-file checks, and gitleaks on the diff. These must pass locally.
   Record deferred build and test checks with their reasons.
3. Commit and push the candidate branch, create a **draft PR**, and link it to
   the task. The draft's validation notes must identify which checks ran and
   which were deferred.
4. GitHub Actions must pass all five canonical Cargo commands, generated-file
   checks and applicable target checks on the exact candidate. Dedicated jobs
   cover the build and test checks from `just ci`. Keep the PR in draft until
   these checks pass. A new candidate requires fresh CI results.
5. Fix red checks before adding unrelated commits. A pre-existing dependency
   failure is still a blocker to acceptance: investigate and remediate it,
   without suppressing advisories merely to make CI pass.

Publish through the task branch and keep the validation record in the linked PR.
Review and green CI are required before merge. Resume that PR on later
scheduled runs. Production releases follow the [deployment contract](deployment.md).

Hotfix exception (ALL three must hold): ≤ 5 lines, exactly one surface touched,
no output pinned by `*_byte_equal*` tests changes.

Post-push: `gh run watch <id> --exit-status`; red → `gh run view --log-failed`
→ fix → push. A red head commit makes the next commit either its hotfix or a
wait.

## 3. Verification Checklist

- [ ] Independent review ran for code and configuration changes. Critical and
      important findings were fixed.
- [ ] Spec-tests written for new public APIs and run in-session.
- [ ] The five canonical Cargo checks and applicable `just ci` checks pass on
      the exact candidate in GitHub Actions. Record HomeLab results when run.
- [ ] After push, CI watched to completion; green before the next commit.
