# Contract: scheduled PR maintenance delivery

## Intent & Invariants

Daily maintenance must deliver reviewed bot changes to GitHub and continue them
through validation and acceptance. A completed scheduler invocation is not proof
of delivery. Production deployment is outside this task.

- Preserve independent review, compatibility, secret scanning, and all gates.
- Use [draft PR validation](agent-workflow.md#publishing-for-github-actions-validation)
  to run build and test checks when a HomeLab worker is unavailable.
- Never suppress an advisory solely to unblock an unrelated change.

## Interface / Data contract

- Use the existing daily task and its existing report thread and schedule.
- Before creating work, find the existing open maintenance PR and compare its
  head and checks. Resume it; do not create duplicate patches or blocker issues.
- Publish reviewed candidates as draft PRs after local non-compiling checks.
  Record exact head SHA, deferred checks and reasons, and CI links in the PR.
- Require all five canonical Cargo gates and the dedicated jobs covering
  `just ci` in GitHub Actions, including applicable SSH and static-musl checks
  for dependency changes.
- Fix failed validation in scope before taking unrelated work. Preserve useful
  work in GitHub, not solely in a local diff or remote temporary directory.
- Mark ready and merge only after current-head validation and review pass;
  then verify `main` CI before processing another merge.
- Close duplicate proposals after their accepted replacement lands, linking it.
- Report delivered PRs/merges, current blockers, and local/main/production state.
  An unchanged blocker gets a short report, not another issue or identical comment.

## Verification checklist

- [ ] A reviewed candidate is published after checks that do not compile code.
- [ ] GitHub runs the canonical checks and applicable target jobs.
- [ ] A failed gate leaves the PR in draft; current-head green gates allow acceptance.
- [ ] The next run resumes the published PR without relying on worker artifacts.
- [ ] The existing task retains its schedule and report thread.
