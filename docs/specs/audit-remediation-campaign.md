# Spec: Remove WgTurn & DNS Tunnel and remediate verified audit findings

## 1. Intent & Invariants
- Start from merged structural baseline and remove WgTurn and DNS Tunnel completely from active code, registry, UI, tests, and current documentation.
- Preserve historical migrations and audit rows; cleanup migrations (`0049_remove_wgturn.sql` and `0050_remove_dns_tunnel.sql`) remove active inventory bindings (`server_protocols`, `server_kernels`, `grant_protocol_overrides`) with audit-on-mutation only, but retain `wgturn:*` and `dns-tunnel:*` secrets in SQLite for rollback for one transition release. A later secret purge requires a separate verified cleanup release.
- **Production deployment gate:** this code removal must NOT be deployed to production until legacy `wgturn.service` / `wg-quick@wgturn-be` and `dns-tunnel.service` / `dns-tunnel-singbox.service` are stopped, disabled, and removed on every affected server via hoster console (strict no-SSH-instruction policy — operator uses hoster console).
- Pre-0049 and pre-0050 verified inventory snapshot must be created and verified prior to applying migrations.
- Then fix every verified critical/important finding from `docs/AUDIT_2026-08-24_COLOSSAL_SWARM.md` in isolated waves.
- Each wave uses Gemini Swarm execution, independent review, regression tests, a dedicated commit, and green GitHub CI before the next wave.
- Preserve WireGuard, AmneziaWG, subscription byte compatibility, backup/restore safety, and the web-only operator policy.
- Do not deploy production without a separate explicit user instruction.

## 2. Interface / Data Contract
```text
Wave 1: remove WgTurn & DNS Tunnel + cleanup migrations (retaining wgturn:* and dns-tunnel:* secrets for 1 release)
Wave 2: kernel installers/runtime
Wave 3: client artefacts and protocol declarations
Wave 4: inventory accounting/panic safety
Wave 5: SSH and daemon runtime
Wave 6: alerts and Boosty
Wave 7: CLI and Forgejo CI
Wave 8: verified minor backlog

Each AUD item ends as: fixed | removed-with-wgturn | removed-with-dns-tunnel | deferred-with-reason.
```

## 3. Verification Checklist / Definition of Done (DOD)
- [ ] WgTurn and DNS Tunnel are absent from active runtime code, registries, UI, tests, and current capability docs.
- [ ] Cleanup migrations (`0049_remove_wgturn.sql`, `0050_remove_dns_tunnel.sql`) unbind active `server_protocols`, `server_kernels`, and `grant_protocol_overrides` while retaining `wgturn:*` and `dns-tunnel:*` secrets for 1 transition release rollback window; tested on populated and empty databases with audit-on-mutation only (no no-op spam).
- [ ] Pre-0050 (and pre-0049) inventory snapshot verified before daemon migration startup.
- [ ] Production deployment precondition documented and enforced: legacy `wgturn.service`, `wg-quick@wgturn-be`, `dns-tunnel.service`, and `dns-tunnel-singbox.service` must be stopped/disabled/removed via hoster console on all affected nodes prior to vpnctld deployment.
- [ ] Later secret purge scheduled as a separate verified cleanup release after the transition release.
- [ ] Every defect fix has a regression test reproducing the original bug.
- [ ] Share-link/subscription changes have byte-level regression coverage.
- [ ] Kernel changes pass unit tests and Linux/Docker-backed CI.
- [ ] Every wave passes independent review and full mandatory gates.
- [ ] Audit statuses (AUD-001, AUD-007 as `removed-with-wgturn`; AUD-008, AUD-011, and DNS portion of AUD-012 as `removed-with-dns-tunnel`) and generated project map are current.
- [ ] Production remains unchanged.
