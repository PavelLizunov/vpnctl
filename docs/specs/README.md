# docs/specs — contracts and micro-specs

Two kinds of documents live here:

1. **New features.** Before writing non-trivial code, add a one-screen
   micro-spec (`<feature>.md`, ~30–50 lines, exactly 3 sections):

   ```markdown
   # Spec: <Feature Name>

   ## 1. Intent & Invariants
   - What: <1-2 sentences on what changes and why>
   - Invariants: <strict guarantees that must never break>

   ## 2. Interface / Data Contract
   // Only public structs, enums, functions, error types

   ## 3. Verification Checklist (Definition of Done)
   - [ ] Happy path: <expected behavior>
   - [ ] Edge/Failure case: <timeout, network drop, OOM guard>
   - [ ] Tests passed on the designated target
   ```

   Commit the spec alongside the code so documentation never drifts. A claimed
   fix is not proven until the relevant test fails under a planted regression
   (or equivalent mutation) and then passes with the implementation.

2. **Standing contracts** — distilled operational knowledge, enforced by tests
   wherever possible:

   | File | Subject |
   |---|---|
   | `architecture.md` | Kernel × Protocol orthogonality, statelessness, lints |
   | `agent-workflow.md` | review-agent / test-writer-agent / CI gates |
   | `admin-ui-quality.md` | six-layer UI methodology + `vpnctl admin:` copy contract |
   | `deployment.md` | prod host facts, musl build, deploy.sh, glibc constraint |
   | `abuse-detection.md` | three-layer visibility model |
   | `migration-compatibility.md` | byte-for-byte client compatibility |
   | `backup-restore.md` | backup bundle, restore drill, invariants |
