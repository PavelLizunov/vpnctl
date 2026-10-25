#!/usr/bin/env bash

set -euo pipefail

DIR="${VPNCTLD_GEOIP_DIR:-/var/lib/vpnctl/geoip}"
KEY="${VPNCTLD_DEPLOY_KEY:-/var/lib/vpnctl/.ssh/id_ed25519}"
DB="${VPNCTLD_INV_DB:-/var/lib/vpnctl/inv.db}"
KNOWN_HOSTS="${VPNCTLD_KNOWN_HOSTS:-/var/lib/vpnctl/.ssh/known_hosts}"
DEADLINE_SECS="${VPNCTLD_GEOIP_DEADLINE_SECS:-480}"

this_month=$(date -u +%Y-%m)
prev_month=$(date -u -d "${this_month}-01 -1 month" +%Y-%m)

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }

nodes() {
  sqlite3 "file:${DB}?mode=ro" \
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

fetch() {
  local name=$1 seg=$2
  local gz="$DIR/${name}.$$.partial.gz" mmdb="$DIR/${name}.$$.partial" mon url
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
rc=0
fetch GeoLite2-City.mmdb city || rc=1
fetch GeoLite2-ASN.mmdb asn || rc=1
log "done — restart vpnctld to load the refreshed DBs (next deploy will)."
exit "$rc"
