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
#   2. Tar together: snap.db + every CRITICAL path + every OPTIONAL
#      path that exists on this host. zstd-19 gives ~10× compression.
#
#      CRITICAL paths (script aborts if missing):
#        - inv.db (the snapshot itself)
#        - /etc/vpnctl/vpnctld.env (basic-auth + telegram + env config)
#        - /opt/vpnctl/assets (favicon + admin.css)
#
#      OPTIONAL paths (warn + skip if missing — newer install or
#      host without this surface):
#        - /var/lib/vpnctl/.ssh/id_ed25519{,.pub} (DEPLOY KEY — without
#          this, restored vpnctld can't reach any VPN node; HARD invariant
#          per CLAUDE.md "Server invariant — deploy-key authorization").
#        - /var/lib/vpnctl/.ssh/known_hosts (TOFU-pinned host keys —
#          without this, first SSH after restore prompts unknown-host).
#        - /etc/vpnctl/backup-recipient.txt (without it, the restored
#          host can't push NEW backups — chicken-and-egg).
#        - /var/lib/vpnctl/geoip (DB-IP City + ASN mmdb — re-fetchable
#          via `vpnctl geoip-update`, but bundling avoids the first-boot
#          fetch round-trip).
#        - /etc/systemd/system/vpnctld.service (so the restored host
#          knows how vpnctld is supposed to run).
#        - /etc/systemd/system/vpnctl-backup.{service,timer} (so the
#          backup loop self-bootstraps after restore).
#        - /etc/iptables/rules.v4 (without it the iptables INPUT
#          policy DROP blocks port 18402 — restored vpnctld up but
#          unreachable).
#
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
# * Required path missing → exit 13 (install-time bug or path drift).
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
DEPLOY_KEY=${DEPLOY_KEY:-/var/lib/vpnctl/.ssh/id_ed25519}
DEPLOY_KEY_PUB=${DEPLOY_KEY_PUB:-/var/lib/vpnctl/.ssh/id_ed25519.pub}
DEPLOY_KNOWN_HOSTS=${DEPLOY_KNOWN_HOSTS:-/var/lib/vpnctl/.ssh/known_hosts}
RECIPIENT_FILE=${RECIPIENT_FILE:-/etc/vpnctl/backup-recipient.txt}
GEOIP_DIR=${GEOIP_DIR:-/var/lib/vpnctl/geoip}
SYSTEMD_UNIT_VPNCTLD=${SYSTEMD_UNIT_VPNCTLD:-/etc/systemd/system/vpnctld.service}
SYSTEMD_UNIT_BACKUP_SERVICE=${SYSTEMD_UNIT_BACKUP_SERVICE:-/etc/systemd/system/vpnctl-backup.service}
SYSTEMD_UNIT_BACKUP_TIMER=${SYSTEMD_UNIT_BACKUP_TIMER:-/etc/systemd/system/vpnctl-backup.timer}
IPTABLES_RULES=${IPTABLES_RULES:-/etc/iptables/rules.v4}
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
# Strategy: build a list of "files to include" by checking each path's
# existence on this host. CRITICAL paths abort the script if missing;
# OPTIONAL paths are logged and skipped. The transform rewrites all
# absolute paths into the `vpnctl-snap/` prefix so `tar tjf <archive>`
# shows a clean tree without leading-slash surprises.
log "collecting files to archive"

REQUIRED=(
    "$ENV_FILE"
    "$ASSETS_DIR"
)
for p in "${REQUIRED[@]}"; do
    [ -e "$p" ] || fail "required path missing: $p" 13
done

OPTIONAL=(
    "$DEPLOY_KEY"
    "$DEPLOY_KEY_PUB"
    "$DEPLOY_KNOWN_HOSTS"
    "$RECIPIENT_FILE"
    "$GEOIP_DIR"
    "$SYSTEMD_UNIT_VPNCTLD"
    "$SYSTEMD_UNIT_BACKUP_SERVICE"
    "$SYSTEMD_UNIT_BACKUP_TIMER"
    "$IPTABLES_RULES"
)
TAR_PATHS=("inv.db" "${REQUIRED[@]}")
for p in "${OPTIONAL[@]}"; do
    if [ -e "$p" ]; then
        TAR_PATHS+=("$p")
    else
        log "  skip (absent on host): $p"
    fi
done

log "tarring ${#TAR_PATHS[@]} paths"
tar -C "$WORK" \
    --transform='s|^|vpnctl-snap/|' \
    --absolute-names \
    -cf "${WORK}/snap.tar" \
    "${TAR_PATHS[@]}"
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
