# Spec: Reliable autodeploy and truthful server readiness

## 1. Intent & Invariants
- Approved by operator 2026-09-09: fix competing automatic deployments, premature quality measurement, and misleading readiness/status displays.
- Retain exclusive node writes and atomic content-revision comparison before canonical applied audit. Never clear pending on stale/failed/skipped work.
- Preserve subscription bytes/visibility, credentials, grants, and historical failure records. No new dependencies or external queue service.
- Cloud firewall, client application, and backup-service incident are out of scope. No production deployment or VPN-node changes in this task.

## 2. Interface / Data Contract
- One automatic executor per server coalesces requests and applies latest desired state. Mutation during execution schedules another pass; worker retirement cannot lose a new request.
- Bound retries. On exhaustion or SSH failure retain observable pending/failure with reason and targeted retry; restart cannot turn unfinished work into success.
- UI distinguishes saved, pending, applying, config applied, and failed. Query failure is unknown, never all-applied.
- Before first successful provisioning service quality is unknown/not measured. Preserve earlier samples but exclude them from provisioned service quality; different target sets must not be silently pooled.
- Label failed TCP connection percentage with vantage, window, and check time. Ordinary redeploy does not erase incident history or reset real failures.
- Config applied does not imply externally reachable VPN. Reuse existing quality/Protocol Assurance results; missing external evidence is not checked. Never automatically hide subscriptions as a side effect.

## 3. Verification Checklist
- [ ] Deterministic protocol/grant mutation-during-apply tests converge to latest state without parallel node writes or lost wakeup.
- [ ] Lock contention, stale input, SSH error, retry exhaustion, restart/pending semantics and independent servers covered.
- [ ] Pre-provisioning failures excluded, subsequent real failures retained, changed target populations distinguished.
- [ ] Closed external port cannot appear as verified VPN readiness; unknown query/result remains unknown.
- [ ] Independent spec-derived tests, diff review, security review, canonical local gates and GitHub CI pass.
- [ ] Publish reviewed release candidate preserving current production icons/setup; live rollout separately authorized.
