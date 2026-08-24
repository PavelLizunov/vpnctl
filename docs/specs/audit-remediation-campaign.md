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
Wave 1: remove WgTurn & DNS Tunnel + cleanup migrations (retaining wgturn:* and dns-tunnel:* secrets for 1 release) [MERGED - PR #155, PR #157]
Wave 2: kernel installers/runtime (AUD-002, AUD-010, AUD-012) [MERGED - PR #156]
Wave 3: client artefacts and protocol declarations (AUD-005, AUD-006, AUD-009, VLESS Reality XUDP) [MERGED - PR #158, PR #159]
Wave 4: inventory accounting/panic safety (AUD-013, AUD-014) [MERGED - PR #158]
Wave 5: SSH and daemon runtime (AUD-003, AUD-004, AUD-021, AUD-022, AUD-023) [MERGED - PR #160]
Wave 6: alerts (AUD-024 fixed, AUD-025 in-progress); Boosty AUD-016 deferred-with-reason
Wave 7: CLI fixed (AUD-018, AUD-019, AUD-020); AUD-026 removed-with-forgejo
Wave 8: verified minor backlog partially fixed; remaining items documented below

Each AUD item ends as: fixed | removed-with-wgturn | removed-with-dns-tunnel | removed-with-forgejo | deferred-with-reason.
```

## 3. Verification Checklist / Definition of Done (DOD)
- [x] WgTurn and DNS Tunnel are absent from active runtime code, registries, UI, tests, and current capability docs (PR #155, PR #157).
- [x] Cleanup migrations (`0049_remove_wgturn.sql`, `0050_remove_dns_tunnel.sql`) unbind active `server_protocols`, `server_kernels`, and `grant_protocol_overrides` while retaining `wgturn:*` and `dns-tunnel:*` secrets for 1 transition release rollback window; tested on populated and empty databases with audit-on-mutation only (no no-op spam).
- [ ] Pre-0050 (and pre-0049) inventory snapshot verified before daemon migration startup (unchecked / not verified: no production deploy).
- [ ] Production deployment precondition documented and enforced: legacy `wgturn.service`, `wg-quick@wgturn-be`, `dns-tunnel.service`, and `dns-tunnel-singbox.service` must be stopped/disabled/removed via hoster console on all affected nodes prior to vpnctld deployment.
- [ ] Later secret purge scheduled as a separate verified cleanup release after the transition release.
- [x] Every defect fix has a regression test reproducing the original bug (Waves 1-5).
- [x] Share-link/subscription changes have byte-level regression coverage (`spec_share_link_byte_equality.rs`).
- [x] Kernel changes pass unit tests and Linux/Docker-backed CI.
- [x] Every merged wave passes independent review and full mandatory gates.
- [x] Audit statuses (AUD-001, AUD-007 as `removed-with-wgturn`; AUD-008, AUD-011, and DNS portion of AUD-012 as `removed-with-dns-tunnel`; AUD-026 as `removed-with-forgejo`; AUD-002, AUD-003, AUD-004, AUD-005, AUD-006, AUD-009, AUD-010, AUD-012, AUD-013, AUD-014, AUD-018 through AUD-024 as `fixed`; AUD-025 as `in-progress` until code review passes; AUD-016 as `deferred-with-reason`) and campaign docs are current.
- [x] Production remains unchanged.
