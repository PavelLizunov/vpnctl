# Contract: backup & restore

## 1. Intent & Invariants

- What: backups are critical, not optional. If the prod host dies, every
  `sub_token` is lost and every client must re-import unless a tested restore
  path exists.
- Invariants:
  - The bundle MUST include the deploy SSH key — a restored vpnctld without it
    cannot reach ANY VPN node (silent failure).
  - A snapshot has no value without a drill: restore is self-tested in prod
    and byte-equality is CI-protected.
  - Off-site copy is best-effort but must exist (the LAN box can die with the
    prod host).

## 2. Interface / Data Contract

- Snapshot: `VACUUM INTO` of `inv.db` + hourly retention + asset bundle
  (deploy key, known_hosts, geoip mmdb, systemd units, iptables rules) —
  `scripts/vpnctl-backup.sh` under `vpnctl-backup.timer`.
- Off-site: scp copy to a remote node, 30-day retention; primary LAN archive
  stays authoritative if the copy fails.
- Restore: `vpnctl restore <bundle>` on a recovered host; web self-test
  (`POST /admin/backup/self-test`) copies a snapshot, migrates it, and checks
  invariants (tables, FKs, counts, schema version, integrity PRAGMA).
- CI: `daemon/tests/restore_e2e.rs` — seed → snapshot → mutate → restore to a
  second DB → diff `/api/v1/app/config/<id>` (pre ≠ post, pre == restored).
- Operator documentation lives in-product: `/admin/settings`
  `#disaster-recovery` (3-tier backup table + 3-step procedure; steps 1–2 run
  on a NEW host because the old one is dead, step 3 returns to the recovered
  daemon's web UI).

## 3. Verification Checklist

- [ ] Backup bundle contains the deploy key (hard invariant — verify in the
      archive listing, not just the script).
- [ ] Self-test returns PASS on prod after any backup-path change.
- [ ] `restore_e2e` green: byte-stability of the subscription endpoint after
      restore is CI-protected.
- [ ] Off-site copy freshness checked; restore procedure readable by someone
      who has never seen the codebase.
