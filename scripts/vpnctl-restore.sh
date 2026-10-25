#!/usr/bin/env bash

set -euo pipefail
umask 077

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

[ -f "$ARCHIVE" ] || { echo "missing archive: $ARCHIVE" >&2; exit 65; }
[ -f "$KEY" ]     || { echo "missing key: $KEY" >&2;       exit 66; }
# Absolute paths: the work below runs inside the scratch directory.
ARCHIVE=$(realpath -- "$ARCHIVE")
KEY=$(realpath -- "$KEY")

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] vpnctl-restore: $*" >&2; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/vpnctl-restore-${STAMP}.XXXXXX")
cd "$WORK"

log "decrypting $ARCHIVE → snap.tar.zst"
age -d -i "$KEY" -o snap.tar.zst "$ARCHIVE"

log "decompressing snap.tar.zst → snap.tar"
zstd -q -d -o snap.tar snap.tar.zst
rm -f snap.tar.zst

log "extracting snap.tar"
tar -xf snap.tar
rm -f snap.tar

INV="$WORK/vpnctl-snap/inv.db"
[ ! -L "$WORK/vpnctl-snap" ] && [ ! -L "$INV" ] && [ -f "$INV" ] \
    || { log "FAIL: no regular vpnctl-snap/inv.db inside archive"; exit 67; }

log "verifying $INV via sqlite3 (PRAGMA integrity_check)"
INTEGRITY=$(sqlite3 "$INV" 'PRAGMA integrity_check' 2>&1)
if [ "$INTEGRITY" != "ok" ]; then
    log "FAIL: integrity_check returned: $INTEGRITY"
    exit 68
fi

count_table() {
    local table=$1 out
    if out=$(sqlite3 "$INV" "SELECT COUNT(*) FROM ${table}" 2>&1); then
        printf '%s' "$out"
    else
        log "self-test: COUNT(*) on required table '${table}' failed: ${out}"
        printf '%s' "✗"
    fi
}

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
