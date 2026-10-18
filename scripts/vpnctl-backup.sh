#!/usr/bin/env bash

set -euo pipefail
umask 077

DB_PATH=${DB_PATH:-/var/lib/vpnctl/inv.db}
ENV_FILE=${ENV_FILE:-/etc/vpnctl/vpnctld.env}
ASSETS_DIR=${ASSETS_DIR:-/opt/vpnctl/assets}
DEPLOY_KEY=${DEPLOY_KEY:-${VPNCTLD_DEPLOY_KEY:-/var/lib/vpnctl/.ssh/id_ed25519}}
DEPLOY_KEY_PUB=${DEPLOY_KEY_PUB:-${DEPLOY_KEY}.pub}
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
BACKUP_DIR=${BACKUP_DIR:-/var/lib/vpnctl/backups}
OFFSITE_HOST=${OFFSITE_HOST-root@93.95.226.167}
OFFSITE_PORT=${OFFSITE_PORT:-22}
OFFSITE_DIR=${OFFSITE_DIR:-/root/vpnctl-backups}
OFFSITE_KEY=${OFFSITE_KEY:-$DEPLOY_KEY}
OFFSITE_RETENTION_DAYS=${OFFSITE_RETENTION_DAYS:-30}
TMPDIR=${TMPDIR:-/tmp}

STAMP=$(date -u +%Y-%m-%dT%H-%M-%SZ)
ARCHIVE_NAME="${STAMP}.tar.zst.age"
LOCAL_PATH="${BACKUP_DIR}/${ARCHIVE_NAME}"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] vpnctl-backup: $*" >&2; }
fail() { log "FAIL: $*"; exit "${2:-1}"; }

mkdir -p "$TMPDIR" "$BACKUP_DIR"
WORK=$(mktemp -d "${TMPDIR}/vpnctl-backup-${STAMP}.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

log "snapshotting $DB_PATH"
sqlite3 "$DB_PATH" ".backup '${WORK}/inv.db'" \
    || fail "sqlite3 .backup failed" 10

log "collecting files to archive"

[ ! -L "$DEPLOY_KEY" ] && [ -f "$DEPLOY_KEY" ] && [ -r "$DEPLOY_KEY" ] && [ -s "$DEPLOY_KEY" ] \
    || fail "deploy key missing, empty, unreadable or symlinked: $DEPLOY_KEY" 13
REQUIRED=(
    "$ENV_FILE"
    "$ASSETS_DIR"
    "$DEPLOY_KEY"
)
for p in "${REQUIRED[@]}"; do
    [ -e "$p" ] || fail "required path missing: $p" 13
done

OPTIONAL=(
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
zstd -q -3 -o "${WORK}/snap.tar.zst" "${WORK}/snap.tar" \
    || fail "zstd compress failed" 10
rm -f "${WORK}/snap.tar"

[ -f "$RECIPIENT_FILE" ] || fail "recipient file missing: $RECIPIENT_FILE" 12
RECIPIENT=$(awk '/^Public key:/ {print $3}' "$RECIPIENT_FILE")
[ -n "$RECIPIENT" ] || fail "couldn't parse Public key from $RECIPIENT_FILE" 12

log "encrypting to $RECIPIENT"
age -r "$RECIPIENT" -o "$LOCAL_PATH" "${WORK}/snap.tar.zst" \
    || fail "age encrypt failed" 12
rm -f "${WORK}/snap.tar.zst" "${WORK}/inv.db"

LOCAL_SIZE=$(stat -c%s "$LOCAL_PATH")
log "local archive: $ARCHIVE_NAME (${LOCAL_SIZE} bytes)"

log "uploading to ${TARGET_HOST}:${TARGET_DIR}/"
scp -O -q -i "$DEPLOY_KEY" -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes \
    "$LOCAL_PATH" \
    "${TARGET_HOST}:${TARGET_DIR}/${ARCHIVE_NAME}" \
    || fail "scp to ${TARGET_HOST} failed (network or auth); local archive kept at ${LOCAL_PATH} for manual recovery" 11

RESULT=0
log "rotating ${TARGET_DIR} (keep ${RETENTION_DAYS} days)"
ssh -i "$DEPLOY_KEY" -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes "$TARGET_HOST" \
    "find '${TARGET_DIR}' -maxdepth 1 -name '*.tar.zst.age' -mtime +${RETENTION_DAYS} -delete" \
    || { log "WARN: primary rotation failed; archive preserved"; RESULT=15; }

if [ -n "${OFFSITE_HOST:-}" ]; then
    if [ ! -r "$OFFSITE_KEY" ]; then
        log "WARN: off-site SSH key not readable: $OFFSITE_KEY (skipping off-site push)"
        RESULT=14
    else
        log "off-site uploading to ${OFFSITE_HOST}:${OFFSITE_DIR}/ (port ${OFFSITE_PORT})"
        if scp -q -i "$OFFSITE_KEY" -P "$OFFSITE_PORT" \
            -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes \
            "$LOCAL_PATH" \
            "${OFFSITE_HOST}:${OFFSITE_DIR}/${ARCHIVE_NAME}"; then
            log "off-site rotating ${OFFSITE_DIR} (keep ${OFFSITE_RETENTION_DAYS} days)"
            ssh -i "$OFFSITE_KEY" -p "$OFFSITE_PORT" \
                -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes "$OFFSITE_HOST" \
                "find '${OFFSITE_DIR}' -maxdepth 1 -name '*.tar.zst.age' -mtime +${OFFSITE_RETENTION_DAYS} -delete" \
                || { log "WARN: off-site rotation failed; archive preserved"; RESULT=15; }
        else
            log "WARN: off-site scp failed; local and primary archives preserved"
            RESULT=14
        fi
    fi
else
    log "off-site push disabled (OFFSITE_HOST empty)"
fi

log "rotating local ${BACKUP_DIR} (keep ${RETENTION_DAYS} days)"
find "$BACKUP_DIR" -maxdepth 1 -name '*.tar.zst.age' -mtime +"${RETENTION_DAYS}" -delete \
    || { log "WARN: local rotation failed"; [ "$RESULT" -ne 0 ] || RESULT=15; }

[ "$RESULT" -eq 0 ] || fail "incomplete backup ${ARCHIVE_NAME}; inspect stage warnings; local archive preserved" "$RESULT"
log "ok ${ARCHIVE_NAME}"
exit 0
