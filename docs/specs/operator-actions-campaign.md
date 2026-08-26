# Spec: Operator Actions Campaign

## 1. Intent & Invariants
- What: verify every user, server, protocol and deployment operator action through Web and CLI parity.
- Invariants: mutation tests use disposable DB/SSH nodes; each real mutation has one audit row, no-op has none; failure preserves state; production remains read-only; secrets and live identifiers never enter reports.

## 2. Interface / Data Contract
```text
ActionResult = PASS | WARN | FAIL | NOT_TESTED
Evidence = state_before + action + state_after + audit_delta
           + artifact_digest_delta + remote_delta + rollback
Families = user | grant | server | protocol | deploy | artifact | backup
```

## 3. Verification Checklist
- [ ] Every actionable Web route and CLI subcommand inventoried.
- [ ] User create/edit/disable/enable/delete/rotation cases tested.
- [ ] Grants/revokes/overrides update artifacts and audits correctly.
- [ ] Subscription/QR/WireGuard/VPNRouter artifacts parse/import.
- [ ] Server bootstrap/push-key/fingerprint tested on disposable SSH nodes.
- [ ] Root and non-root passwordless-sudo paths pass.
- [ ] Deploy/redeploy/deploy-all/update-kernels and rollback paths tested.
- [ ] Protocol enable/disable/hide/secrets/conflicts tested.
- [ ] Native validators/listeners/firewall reflect enabled protocols.
- [ ] Backup/restore preserves artifacts byte-for-byte.
- [ ] Temporary entities/containers/configs removed.
- [ ] Independent review and full CI pass.
