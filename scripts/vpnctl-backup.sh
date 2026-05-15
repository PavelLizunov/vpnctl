#!/usr/bin/env bash
# vpnctl-backup.sh — daily encrypted snapshot of the daemon's state.
#
# Phase C-4 (audit-fix B2). The vpnctl SQLite inventory at
# /var/lib/vpnctl/inv.db is a single point of failure: if 192.168.0.236
# burns, every sub_token is lost and every existing client has to
# re-import a fresh URL. This script (run nightly via systemd timer)
# produces an off-host, encrypted snapshot.
#
# Pipeline
# --------
#   1. SQLite hot snapshot via `.backup` (works under WAL — no need
#      to stop vpnctld; the backup API takes a consistent point-in-
#      time copy without locking writers).
#   2. Tar together: snap.db + /etc/vpnctl/vpnctld.env (basic-auth
#      creds) + /opt/vpnctl/assets/ (favicon + admin.css). zstd-19
#      gives ~10× compression on text-heavy SQLite + assets.
#   3. age-encrypt to the recipient public key in
#      /etc/vpnctl/backup-recipient.txt. Only the private key holder
#      (Pavel's laptop + 207 escrow) can decrypt.
#   4. scp to user@192.168.0.207:~/backups/vpnctl/<date>.tar.zst.age
#   5. Rotate on 207: keep last RETENTION_DAYS days; delete older.
#   6. Clean up local /tmp staging.
#
# Failure modes
# -------------
# * SQLite snapshot fails → exit 10 (likely DB corruption — operator
#   should investigate before next tick).
# * scp fails → exit 11 (network or 207-side issue — local snapshot
#   stays in place for manual recovery).
# * age fails → exit 12 (recipient key rotated or corrupted).
# Any non-zero exit triggers the systemd unit's failure handling
# (operator sees `systemctl status vpnctl-backup`).
#
# Restore
# -------
# See `vpnctl-restore.sh` in the same directory.

set -euo pipefail

## ── tunables ────────────────────────────────────────────────────────────
DB_PATH=${DB_PATH:-/var/lib/vpnctl/inv.db}
ENV_FILE=${ENV_FILE:-/etc/vpnctl/vpnctld.env}
ASSETS_DIR=${ASSETS_DIR:-/opt/vpnctl/assets}
RECIPIENT_FILE=${RECIPIENT_FILE:-/etc/vpnctl/backup-recipient.txt}
TARGET_HOST=${TARGET_HOST:-user@192.168.0.207}
TARGET_DIR=${TARGET_DIR:-/home/user/backups/vpnctl}
RETENTION_DAYS=${RETENTION_DAYS:-14}
TMPDIR=${TMPDIR:-/tmp}

## ── derived ─────────────────────────────────────────────────────────────
STAMP=$(date -u +%Y-%m-%dT%H-%M-%SZ)
WORK="${TMPDIR}/vpnctl-backup-${STAMP}"
ARCHIVE_NAME="${STAMP}.tar.zst.age"
LOCAL_PATH="${WORK}/${ARCHIVE_NAME}"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] vpnctl-backup: $*" >&2; }
fail() { log "FAIL: $*"; exit "${2:-1}"; }

mkdir -p "$WORK"
trap 'rm -rf "$WORK"' EXIT

## ── 1. SQLite hot snapshot ──────────────────────────────────────────────
log "snapshotting $DB_PATH"
sqlite3 "$DB_PATH" ".backup '${WORK}/inv.db'" \
    || fail "sqlite3 .backup failed" 10

## ── 2. tar + zstd ───────────────────────────────────────────────────────
# Use absolute paths so the tar can be inspected with `tar tjf` without
# guessing layout. zstd at level 19 is slow but the workload is small
# (single-digit MB) and the result is air-tight.
log "tarring snap + env + assets"
tar -C "$WORK" \
    --transform='s|^|vpnctl-snap/|' \
    --absolute-names \
    -cf "${WORK}/snap.tar" \
    inv.db \
    "$ENV_FILE" \
    "$ASSETS_DIR"
zstd -q -19 -o "${WORK}/snap.tar.zst" "${WORK}/snap.tar" \
    || fail "zstd compress failed" 10
rm -f "${WORK}/snap.tar"

## ── 3. age encrypt ──────────────────────────────────────────────────────
[ -f "$RECIPIENT_FILE" ] || fail "recipient file missing: $RECIPIENT_FILE" 12
RECIPIENT=$(awk '/^Public key:/ {print $3}' "$RECIPIENT_FILE")
[ -n "$RECIPIENT" ] || fail "couldn't parse Public key from $RECIPIENT_FILE" 12

log "encrypting to $RECIPIENT"
age -r "$RECIPIENT" -o "$LOCAL_PATH" "${WORK}/snap.tar.zst" \
    || fail "age encrypt failed" 12
rm -f "${WORK}/snap.tar.zst" "${WORK}/inv.db"

LOCAL_SIZE=$(stat -c%s "$LOCAL_PATH")
log "local archive: $ARCHIVE_NAME (${LOCAL_SIZE} bytes)"

## ── 4. scp to 207 ───────────────────────────────────────────────────────
log "uploading to ${TARGET_HOST}:${TARGET_DIR}/"
scp -q -o BatchMode=yes -o ConnectTimeout=10 \
    "$LOCAL_PATH" \
    "${TARGET_HOST}:${TARGET_DIR}/${ARCHIVE_NAME}" \
    || fail "scp to ${TARGET_HOST} failed (network or auth)" 11

## ── 5. rotation on 207 ──────────────────────────────────────────────────
log "rotating ${TARGET_DIR} (keep ${RETENTION_DAYS} days)"
ssh -o BatchMode=yes -o ConnectTimeout=10 "$TARGET_HOST" \
    "find '${TARGET_DIR}' -maxdepth 1 -name '*.tar.zst.age' -mtime +${RETENTION_DAYS} -delete" \
    || log "WARN: rotation step failed (non-fatal — manual cleanup possible)"

log "ok ${ARCHIVE_NAME}"
exit 0
