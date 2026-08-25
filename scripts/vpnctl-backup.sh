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
#      (PRIMARY archive store, fast LAN access for self-test + restore).
#   5. **Off-site push (Phase 5b)**: also scp to root@<OFFSITE_HOST>
#      :OFFSITE_DIR/. Different jurisdiction + power grid + ISP from
#      the 236/207 LAN — protects against the «all-LAN-burned» mode.
#      Best-effort: failure logs WARN but does NOT fail the script,
#      because the primary 207 archive is still good. The off-site
#      step needs its own SSH key (we reuse the vpnctld deploy key
#      that's already authorised on every VPN node — see CLAUDE.md
#      «Server invariant — deploy-key authorization»).
#   6. Rotate on 207 (RETENTION_DAYS) + off-site (OFFSITE_RETENTION_DAYS,
#      longer because off-site is the «if everything else burns» tier).
#   7. Clean up local /tmp staging.
#
# Failure modes
# -------------
# * SQLite snapshot fails → exit 10 (likely DB corruption — operator
#   should investigate before next tick).
# * scp fails → exit 11 (network or 207-side issue — the encrypted
#   local snapshot stays in place under BACKUP_DIR
#   (/var/lib/vpnctl/backups by default) for manual recovery; the
#   EXIT trap only ever wipes the scratch staging dir, never the
#   deliverable archive).
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
# Durable local archive directory. The final encrypted archive
# (LOCAL_PATH) is written HERE — OUTSIDE the scratch WORK dir — so the
# EXIT trap (which cleans ONLY scratch staging) can never delete the
# deliverable. If the primary scp to 207 fails (exit 11) the local
# archive survives here for manual recovery. Local copies are pruned
# by the same RETENTION_DAYS as the primary store.
BACKUP_DIR=${BACKUP_DIR:-/var/lib/vpnctl/backups}
# Off-site target (Phase 5b). Default = `is` VPN node (Iceland), the
# geographically + jurisdictionally most-distant from RU/EU. Override
# OFFSITE_HOST="" to disable off-site push entirely.
OFFSITE_HOST=${OFFSITE_HOST:-root@93.95.226.167}
OFFSITE_PORT=${OFFSITE_PORT:-22}
OFFSITE_DIR=${OFFSITE_DIR:-/root/vpnctl-backups}
OFFSITE_KEY=${OFFSITE_KEY:-$DEPLOY_KEY}
# Off-site retention is LONGER than primary — when off-site is
# needed, primary 207 is presumed gone, so we want as deep a
# history as the off-site disk tolerates.
OFFSITE_RETENTION_DAYS=${OFFSITE_RETENTION_DAYS:-30}
TMPDIR=${TMPDIR:-/tmp}

## ── derived ─────────────────────────────────────────────────────────────
STAMP=$(date -u +%Y-%m-%dT%H-%M-%SZ)
WORK="${TMPDIR}/vpnctl-backup-${STAMP}"
ARCHIVE_NAME="${STAMP}.tar.zst.age"
# The deliverable lives in the DURABLE BACKUP_DIR, NOT in WORK. WORK
# holds only scratch/staging (the plaintext .db snapshot, .tar, .tar.zst)
# which the EXIT trap is safe to nuke. LOCAL_PATH must never sit under
# WORK or the trap would wipe the only local copy on a scp failure.
LOCAL_PATH="${BACKUP_DIR}/${ARCHIVE_NAME}"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] vpnctl-backup: $*" >&2; }
fail() { log "FAIL: $*"; exit "${2:-1}"; }

mkdir -p "$WORK"
mkdir -p "$BACKUP_DIR"
# Clean ONLY scratch staging on exit. The deliverable archive in
# BACKUP_DIR is intentionally NOT covered — it must survive an scp
# failure (exit 11) for manual recovery.
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
# VM 118 exposes the legacy scp subsystem but not SFTP. OpenSSH 9 defaults
# scp(1) to SFTP, so force the legacy SCP protocol for this LAN archive hop.
scp -O -q -i "$DEPLOY_KEY" -o BatchMode=yes -o ConnectTimeout=10 \
    "$LOCAL_PATH" \
    "${TARGET_HOST}:${TARGET_DIR}/${ARCHIVE_NAME}" \
    || fail "scp to ${TARGET_HOST} failed (network or auth); local archive kept at ${LOCAL_PATH} for manual recovery" 11

## ── 5. rotation on 207 ──────────────────────────────────────────────────
log "rotating ${TARGET_DIR} (keep ${RETENTION_DAYS} days)"
ssh -o BatchMode=yes -o ConnectTimeout=10 "$TARGET_HOST" \
    "find '${TARGET_DIR}' -maxdepth 1 -name '*.tar.zst.age' -mtime +${RETENTION_DAYS} -delete" \
    || log "WARN: rotation step failed (non-fatal — manual cleanup possible)"

## ── 6. off-site push (Phase 5b) ─────────────────────────────────────────
# Best-effort: failures here log WARN and continue. The primary 207
# archive is already safe at this point; off-site is the «if 207 also
# burns» tier. We pin the deploy key explicitly because the script
# runs as `user` (not root) and `user`'s default ~/.ssh/id_* may have
# different authorisation surfaces on the VPN nodes.
if [ -n "${OFFSITE_HOST:-}" ]; then
    if [ ! -r "$OFFSITE_KEY" ]; then
        log "WARN: off-site SSH key not readable: $OFFSITE_KEY (skipping off-site push)"
    else
        log "off-site uploading to ${OFFSITE_HOST}:${OFFSITE_DIR}/ (port ${OFFSITE_PORT})"
        if scp -q -i "$OFFSITE_KEY" -P "$OFFSITE_PORT" \
            -o BatchMode=yes -o ConnectTimeout=10 \
            "$LOCAL_PATH" \
            "${OFFSITE_HOST}:${OFFSITE_DIR}/${ARCHIVE_NAME}"; then
            log "off-site rotating ${OFFSITE_DIR} (keep ${OFFSITE_RETENTION_DAYS} days)"
            ssh -i "$OFFSITE_KEY" -p "$OFFSITE_PORT" \
                -o BatchMode=yes -o ConnectTimeout=10 "$OFFSITE_HOST" \
                "find '${OFFSITE_DIR}' -maxdepth 1 -name '*.tar.zst.age' -mtime +${OFFSITE_RETENTION_DAYS} -delete" \
                || log "WARN: off-site rotation failed (non-fatal)"
        else
            log "WARN: off-site scp failed (non-fatal — primary archive on ${TARGET_HOST} is safe)"
        fi
    fi
else
    log "off-site push disabled (OFFSITE_HOST empty)"
fi

## ── 7. rotation of the durable local store ──────────────────────────────
# BACKUP_DIR now holds the deliverable across runs, so prune it on the
# same RETENTION_DAYS as the primary 207 store. The archive written
# THIS run has mtime ~now and is far inside the window, so it is never
# pruned here. Non-fatal: a rotation failure must not lose the fresh
# archive nor mask a successful upload.
log "rotating local ${BACKUP_DIR} (keep ${RETENTION_DAYS} days)"
find "$BACKUP_DIR" -maxdepth 1 -name '*.tar.zst.age' -mtime +"${RETENTION_DAYS}" -delete \
    || log "WARN: local rotation failed (non-fatal — manual cleanup possible)"

log "ok ${ARCHIVE_NAME}"
exit 0
