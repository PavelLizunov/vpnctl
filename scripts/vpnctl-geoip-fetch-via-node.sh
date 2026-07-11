#!/usr/bin/env bash
#
# vpnctl GeoIP refresh — node-proxied fetch.
#
# WHY THIS EXISTS (2026-07-11): the homelab host (192.168.0.236) cannot
# complete downloads from db-ip.com's Cloudflare CDN — the transfer
# stalls after ~12-20 KB regardless of MSS, while large NON-Cloudflare
# downloads run at 20+ MB/s and a HEAD to db-ip returns 200. It's a
# Cloudflare-vs-homelab-WAN-IP block, not an MTU issue and not fixable on
# 236 or in vpnctl. The direct `vpnctl geoip-update` therefore fails
# every month with "Connection timed out (os error 110)", freezing the
# GeoIP DBs (they were stuck at 2026-05 until this was written).
#
# The VPN nodes CAN reach db-ip fine (23 MB/s in testing), and vpnctld
# already SSHes to them with the deploy key. So this script streams the
# DB-IP Lite `.mmdb.gz` THROUGH a node:
#
#     ssh <node> "curl -fsSL <db-ip-url>"  >  <dir>/<name>.partial.gz
#
# then decompresses, validates the MaxMind-DB metadata marker + a sane
# size, and ATOMIC-renames into VPNCTLD_GEOIP_DIR. Identical on-disk
# result to `vpnctl geoip-update`, just sourced through a node. The old
# DBs are only replaced AFTER a fetch validates, so a failed run never
# clobbers good data.
#
# It does NOT restart vpnctld (matches `vpnctl geoip-update`): vpnctld
# mmaps the DBs at startup, so the refreshed files load on its next
# restart (deploys restart it frequently).
#
# Invoked by vpnctl-geoip-update.service (monthly timer); safe to run by
# hand. Idempotent. Runs under that unit's sandbox (User=user,
# ProtectHome, ProtectSystem=strict) — reads the deploy key + inv.db
# read-only, writes only VPNCTLD_GEOIP_DIR.

set -euo pipefail

DIR="${VPNCTLD_GEOIP_DIR:-/var/lib/vpnctl/geoip}"
KEY="${VPNCTLD_DEPLOY_KEY:-/var/lib/vpnctl/.ssh/id_ed25519}"
DB="${VPNCTLD_INV_DB:-/var/lib/vpnctl/inv.db}"
# Verify node host keys against the daemon's persistent, already-pinned
# known_hosts (every deploy pins the nodes there) — restores the TOFU
# posture the rest of vpnctld uses instead of blindly re-accepting keys
# via /dev/null. Read-only under the sandbox: accept-new only needs to
# write for an UNSEEN host, and all our nodes are already pinned, so it
# just verifies; a write-blocked warning goes to stderr (suppressed at
# the call site) and the connection still proceeds.
KNOWN_HOSTS="${VPNCTLD_KNOWN_HOSTS:-/var/lib/vpnctl/.ssh/known_hosts}"
# Total wall-clock budget for all fetch attempts. `$SECONDS` counts from
# script start; when exhausted (db-ip stalling on every node in a wider
# outage) we stop so the script exits with its own rc=1 BEFORE systemd's
# TimeoutStartSec=600 SIGTERMs it — a cleaner journal signal than a kill.
DEADLINE_SECS="${VPNCTLD_GEOIP_DEADLINE_SECS:-480}"

this_month=$(date -u +%Y-%m)
# Anchor the fallback to day 1, else `date -d '1 month ago'` on days
# 29-31 collapses back to the current month (Jul-31 -> "Jun-31" ->
# normalized Jul-01), making the month-lag fallback try the same month.
prev_month=$(date -u -d "${this_month}-01 -1 month" +%Y-%m)

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }

# Nodes vpnctld can SSH to directly (skip ProxyJump-only entries — the
# jump host isn't reachable without extra plumbing this script avoids).
nodes() {
  # `immutable=1` reads the main DB file directly — no -wal/-shm access,
  # no locks — so it works even if vpnctld is down at tick time (a plain
  # `-readonly` open of a WAL DB can need to touch -shm in the read-only
  # /var/lib/vpnctl dir and silently return nothing). The server list
  # changes ~monthly, so reading a pre-checkpoint snapshot is harmless.
  sqlite3 "file:${DB}?immutable=1" \
    "SELECT ssh_user || ' ' || address || ' ' || ssh_port
       FROM servers
      WHERE (jump_via IS NULL OR jump_via = '')
      ORDER BY id"
}

ssh_node() { # user host port cmd...
  local u=$1 h=$2 p=$3
  shift 3
  ssh -i "$KEY" -o BatchMode=yes -o ConnectTimeout=8 \
    -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KNOWN_HOSTS" \
    -p "$p" "${u}@${h}" "$@"
}

# Fetch one DB (name = output filename, seg = db-ip url segment) via the
# first node that succeeds, trying the current month then the previous
# (DB-IP publishes monthly; early in a month the new file may lag).
fetch() {
  local name=$1 seg=$2
  local gz="$DIR/${name}.partial.gz" mmdb="$DIR/${name}.partial" mon url
  for mon in "$this_month" "$prev_month"; do
    url="https://download.db-ip.com/free/dbip-${seg}-lite-${mon}.mmdb.gz"
    while read -r u h p; do
      [ -n "${u:-}" ] || continue
      if [ "$SECONDS" -ge "$DEADLINE_SECS" ]; then
        log "  ${name}: time budget (${DEADLINE_SECS}s) exhausted — giving up" >&2
        return 1
      fi
      log "  ${name}: trying ${h} (${mon})"
      rm -f "$gz" "$mmdb"
      if ssh_node "$u" "$h" "$p" "curl -fsSL --max-time 180 '$url'" >"$gz" 2>/dev/null &&
        [ -s "$gz" ] &&
        gunzip -c "$gz" >"$mmdb" 2>/dev/null &&
        tail -c 200000 "$mmdb" | grep -aq "MaxMind.com" &&
        [ "$(stat -c %s "$mmdb")" -gt 1000000 ]; then
        mv -f "$mmdb" "$DIR/$name"
        rm -f "$gz"
        log "  ${name}: OK via ${h} (${mon}, $(stat -c %s "$DIR/$name") bytes)"
        return 0
      fi
    done < <(nodes)
  done
  rm -f "$gz" "$mmdb"
  log "  ${name}: FAILED on all nodes (current + previous month)" >&2
  return 1
}

log "vpnctl geoip refresh (node-proxied) — dir=$DIR"
mkdir -p "$DIR"
# Attempt BOTH DBs regardless of each other's outcome (a City-only outage
# must not skip ASN), then exit non-zero if either failed so the service
# surfaces it. Old DBs are retained on any failure.
rc=0
fetch GeoLite2-City.mmdb city || rc=1
fetch GeoLite2-ASN.mmdb asn || rc=1
log "done — restart vpnctld to load the refreshed DBs (next deploy will)."
exit "$rc"
