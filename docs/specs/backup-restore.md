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
  - Off-site delivery failure preserves local and primary copies but makes
    the scheduled job fail (exit 14), rather than claiming full success.
    Explicit `OFFSITE_HOST=""` disables that stage; disabled is not verified.

## 2. Interface / Data Contract

### Daemon SQLite snapshots

- Producer: the daemon backup scheduler uses `VACUUM INTO` to create only an
  `inv.db.<timestamp>.bak` SQLite file in `VPNCTLD_BACKUP_DIR` (default
  `/var/lib/vpnctl/backups`). It starts after 60 seconds and runs hourly.
  These snapshots are plaintext, mode 0600, in a mode-0700 directory. They
  contain inventory data, not the env file, deploy key or other host files.
- Retention: 24 newest snapshots + one per day for 30 days represented in
  the directory + one per month for 12 months represented in the directory.
  These are count limits, not expiry ages. A failed or un-runnable self-test
  does not disable retention: timestamped snapshots remain bounded by those
  slots plus one protected snapshot. A healthy inventory with zero users or
  servers produces WARN, not FAIL; query/integrity failures still produce FAIL.
- After a passing self-test (OK or WARN), the scheduler atomically replaces
  `last-verified.db` with a hard link to that snapshot. Retention preserves
  both the pin and its timestamped snapshot, including across daemon restarts,
  until a newer snapshot passes. Without a pin, the scheduler first searches existing
  snapshots for the newest recoverable one (ignoring freshness alone).
  If no snapshot is recoverable, retention still bounds the failing snapshots.
  Failure to create the pin is reported and leaves existing snapshots unpruned.
  CLI pruning honours the same pin.

### Daily encrypted disaster-recovery bundles

- Producer: `scripts/vpnctl-backup.sh`, scheduled separately by
  `vpnctl-backup.timer` at **00:00 UTC daily**, with a randomized delay up to
  300 seconds and `Persistent=true`. These are repository unit defaults;
  installed overrides and actual execution must be checked separately.
- The script uses SQLite `.backup` for a consistent `inv.db`, collects the
  env file, assets, deploy key, known_hosts, GeoIP, systemd units and firewall
  rules, then compresses with `zstd -3` and encrypts with `age`. The deploy
  key must be a nonempty, readable regular file, not a symlink (exit 13 on
  failure); public key and known_hosts are included when present.
- Retention is independent of hourly snapshots: local encrypted archives in
  `BACKUP_DIR` and the primary LAN copy in `TARGET_DIR` use
  `RETENTION_DAYS` (default 14); the off-site copy in `OFFSITE_DIR` uses
  `OFFSITE_RETENTION_DAYS` (default 30). The script rotates `*.tar.zst.age`
  with `find -mtime +N` after delivery; these are age limits, not snapshot slots.
- Primary upload failure exits 11. Enabled off-site delivery failure exits 14;
  retention failure exits 15 unless a delivery failure takes precedence.
  Delivery failures preserve the local archive. `OFFSITE_HOST=""` disables
  off-site delivery and does not prove an off-site copy. Stage logs and the
  systemd job result report these failures. Validate `TimeoutStartSec=300`
  against the actual archive size; closing a timeout requires a successful
  scheduled job and verified delivery.

### Restore and self-test

- Inventory restore rejects SQLite snapshots without `_sqlx_migrations`,
  `users`, and `servers` tables before replacing the destination.
- Inventory restore: `vpnctl restore <snapshot>` takes a decrypted SQLite
  snapshot (`inv.db` or an hourly `inv.db.<timestamp>.bak`), never an encrypted
  `.tar.zst.age` bundle. For the service database, use the full command
  `vpnctl --db /var/lib/vpnctl/inv.db restore <snapshot>` (substitute the
  configured daemon DB path). Keep vpnctld stopped until recovery is complete.
  Restore preserves the existing destination file's UID, GID and mode; a
  metadata failure aborts before replacement. If there is no previous DB,
  ownership is that of the newly created file and mode comes from the snapshot.
  Run restore as the service account, or set the DB owner/group to the installed
  unit's `User=`/`Group=` before starting vpnctld (the repository unit defaults
  to `user:user`, for example `chown user:user /var/lib/vpnctl/inv.db`).
- Bundle recovery: run `scripts/vpnctl-restore.sh <archive.tar.zst.age>
  <age-private-key-file>` on the recovered host. It decrypts, unpacks and
  verifies the bundle in a scratch directory; it does not install files.
  Pass the extracted `vpnctl-snap/inv.db` to the full inventory restore command
  above, then restore env, assets, deploy key, known_hosts, GeoIP, systemd units and
  firewall rules to their configured paths, preserving ownership and
  permissions. Start vpnctld only after these files are in place.
- Web self-test (`POST /admin/backup/self-test`) copies a snapshot, runs
  `PRAGMA integrity_check` (exactly one `ok` row) and `PRAGMA foreign_key_check`
  (no rows) on that isolated copy before migration replay, then checks counts
  and schema version. Any violation or query error makes the overall result
  FAIL; the original snapshot and live inventory remain untouched.
- Opening an inventory, restoring it and self-testing a copy all prepare
  pre-0013 databases before migration replay: extra open alerts with the same
  kind/server are acknowledged in a `BEGIN IMMEDIATE` transaction, keeping
  the newest by `created_at`, then `id`. Global alerts share a NULL-server
  group. This writes one audit row only if duplicates changed; migration 0013
  and its checksum remain unchanged.
- CI: `daemon/tests/restore_e2e.rs` — seed → snapshot → mutate → restore to a
  second DB → diff `/api/v1/app/config/<id>` (pre ≠ post, pre == restored).
- Operator documentation lives in-product: `/admin/settings/backups`
  `#disaster-recovery` (3-tier backup table + 3-step procedure; steps 1–2 run
  on a NEW host because the old one is dead, step 3 returns to the recovered
  daemon's web UI).

## 3. Verification Checklist

- [ ] Failed snapshots remain bounded while the last verified snapshot survives
      retention and daemon restart; empty healthy inventories report WARN.
- [ ] Pre-0013 duplicate open alerts migrate on open/restore/self-test, with
      newest retained and no audit on a no-op.
- [ ] Restore preserves destination UID/GID/mode; the DR command targets the
      service DB explicitly.
- [ ] Backup bundle contains the deploy key (hard invariant — verify in the
      archive listing, not just the script).
- [ ] Self-test returns PASS on prod after any backup-path change.
- [ ] Broken foreign keys and integrity-check violations make self-test FAIL.
- [ ] `restore_e2e` green: byte-stability of the subscription endpoint after
      restore is CI-protected.
- [ ] Off-site copy freshness checked; restore procedure readable by someone
      who has never seen the codebase.
