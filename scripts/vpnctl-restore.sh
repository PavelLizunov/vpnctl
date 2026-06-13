#!/usr/bin/env bash
# vpnctl-restore.sh — decrypt + verify a vpnctl backup snapshot.
#
# Usage:
#   vpnctl-restore.sh <archive.tar.zst.age> <age-private-key-file>
#
# The script DOES NOT touch /var/lib/vpnctl/inv.db — restore is a
# manual step (operator decides whether to overwrite, merge, or
# inspect first). This helper just decrypts the archive into a
# scratch directory and verifies the inv.db can be opened by sqlite3.
#
# Output (on success):
#   restored to: /tmp/vpnctl-restore-<stamp>/vpnctl-snap/
#     - inv.db          ← verified openable
#     - vpnctld.env     ← basic-auth creds
#     - assets/         ← favicon + admin.css
#
# Manual steps after a successful restore (typical recovery flow):
#   sudo systemctl stop vpnctld
#   sudo cp /tmp/vpnctl-restore-XXX/vpnctl-snap/inv.db /var/lib/vpnctl/inv.db
#   sudo chown user:user /var/lib/vpnctl/inv.db
#   sudo cp /tmp/vpnctl-restore-XXX/vpnctl-snap/vpnctld.env /etc/vpnctl/
#   sudo cp -r /tmp/vpnctl-restore-XXX/vpnctl-snap/assets/. /opt/vpnctl/assets/
#   sudo systemctl start vpnctld
#   curl -sSf http://127.0.0.1:18402/api/v1/health
#
# The script is intentionally idempotent and read-only on production
# state — running it twice has no side effects beyond two scratch dirs.

set -euo pipefail

if [ $# -ne 2 ]; then
    cat >&2 <<USAGE
usage: $0 <archive.tar.zst.age> <age-private-key-file>

example:
  $0 /home/user/backups/vpnctl/2026-05-15T03-00-00Z.tar.zst.age \\
     /home/user/vpnctl-backup-key.age
USAGE
    exit 64
fi

ARCHIVE=$1
KEY=$2
STAMP=$(date -u +%Y-%m-%dT%H-%M-%SZ)
WORK="/tmp/vpnctl-restore-${STAMP}"

[ -f "$ARCHIVE" ] || { echo "missing archive: $ARCHIVE" >&2; exit 65; }
[ -f "$KEY" ]     || { echo "missing key: $KEY" >&2;       exit 66; }

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] vpnctl-restore: $*" >&2; }

mkdir -p "$WORK"
cd "$WORK"

log "decrypting $ARCHIVE → snap.tar.zst"
age -d -i "$KEY" -o snap.tar.zst "$ARCHIVE"

log "decompressing snap.tar.zst → snap.tar"
zstd -q -d -o snap.tar snap.tar.zst
rm -f snap.tar.zst

log "extracting snap.tar"
tar -xf snap.tar
rm -f snap.tar

# Locate the inv.db — the backup script puts everything under
# `vpnctl-snap/`, but absolute paths inside the tar mean some entries
# (like /etc/vpnctl/vpnctld.env) get extracted to relative paths
# stripped of the leading `/`. Tolerate either layout.
INV=$(find "$WORK" -name inv.db -type f | head -1)
[ -n "$INV" ] || { log "FAIL: no inv.db inside archive"; exit 67; }

log "verifying $INV via sqlite3 (PRAGMA integrity_check)"
INTEGRITY=$(sqlite3 "$INV" 'PRAGMA integrity_check' 2>&1)
if [ "$INTEGRITY" != "ok" ]; then
    log "FAIL: integrity_check returned: $INTEGRITY"
    exit 68
fi

# Quick sanity: row counts of the user-visible tables.
#
# PRAGMA integrity_check above is STRUCTURAL only — it validates the
# B-tree / page layout but says NOTHING about schema completeness. A
# structurally-valid SQLite file with a whole table dropped passes
# integrity_check cleanly. So we additionally probe each KNOWN/required
# table with a COUNT(*) and treat a query error (missing table, etc.)
# as a HARD failure: a backup missing `users`/`servers`/`grants`/…
# is operationally useless and must NOT be reported as "verified".
# (Mirrors the Rust self-test in crates/inventory/src/backup.rs, which
# surfaces COUNT-query failures as distinct Fail checks.)
#
# Sentinel: ✗ marks a failed COUNT. We collect every failure so the
# operator sees ALL missing tables in one pass, then exit non-zero.
count_table() {
    # echoes the row count, or "✗" on any query error (missing table,
    # locked, malformed). Captures stderr so a real sqlite error is
    # logged rather than silently swallowed.
    local table=$1 out
    if out=$(sqlite3 "$INV" "SELECT COUNT(*) FROM ${table}" 2>&1); then
        printf '%s' "$out"
    else
        log "self-test: COUNT(*) on required table '${table}' failed: ${out}"
        printf '%s' "✗"
    fi
}

# KNOWN/required core tables. A snapshot missing any of these is not a
# usable inventory backup. _sqlx_migrations is included because an
# empty/absent migration ledger means the schema itself is suspect.
REQUIRED_TABLES=(users servers grants sub_access_log _sqlx_migrations)
MISSING=()
declare -A COUNTS=()
for t in "${REQUIRED_TABLES[@]}"; do
    c=$(count_table "$t")
    COUNTS["$t"]=$c
    if [ "$c" = "✗" ]; then
        MISSING+=("$t")
    fi
done

USERS=${COUNTS[users]}
SERVERS=${COUNTS[servers]}
GRANTS=${COUNTS[grants]}
ACCESS=${COUNTS[sub_access_log]}
MIGRATIONS=${COUNTS[_sqlx_migrations]}

if [ "${#MISSING[@]}" -gt 0 ]; then
    log "FAIL: restore NOT verified — required table(s) missing or unreadable: ${MISSING[*]}"
    log "      PRAGMA integrity_check passed (structure ok) but the schema is"
    log "      incomplete; this snapshot is NOT a usable inventory backup."
    log "      scratch left for inspection: $WORK"
    exit 69
fi

cat <<DONE
✔ restore verified (structure + required tables present).

  archive:    $ARCHIVE
  scratch:    $WORK
  inv.db:     $INV (integrity_check ok)

  row counts:
    users:            $USERS
    servers:          $SERVERS
    grants:           $GRANTS
    sub_access_log:   $ACCESS
    _sqlx_migrations: $MIGRATIONS

manual cut-over (read carefully — overwrites production inventory):
  sudo systemctl stop vpnctld
  sudo cp -i $INV /var/lib/vpnctl/inv.db
  sudo chown user:user /var/lib/vpnctl/inv.db
  sudo systemctl start vpnctld
  curl -sSf http://127.0.0.1:18402/api/v1/health
DONE
