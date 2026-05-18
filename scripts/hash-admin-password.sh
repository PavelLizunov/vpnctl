#!/usr/bin/env bash
# scripts/hash-admin-password.sh — argon2id PHC generator for
# `VPNCTLD_ADMIN_PASSWORD=` (security audit 2026-05-18). Reads plain
# password from stdin so it doesn't land in shell history.
#
# Usage:
#   echo -n 'hunter2' | scripts/hash-admin-password.sh
#   # → $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
#
# Then paste the line into /etc/vpnctl/vpnctld.env on the daemon
# host as VPNCTLD_ADMIN_PASSWORD and `sudo systemctl restart vpnctld`.
#
# Prereq: system `argon2` CLI.
#   Debian/Ubuntu: sudo apt install argon2
#   macOS:         brew install argon2

set -euo pipefail

if ! command -v argon2 >/dev/null 2>&1; then
  echo "error: /usr/bin/argon2 not found. Install:" >&2
  echo "  Debian/Ubuntu: sudo apt install argon2" >&2
  echo "  macOS:         brew install argon2" >&2
  exit 1
fi

PW=$(cat)
if [[ -z "$PW" ]]; then
  echo "error: empty stdin. Usage: \`echo -n '<plain>' | $0\`" >&2
  exit 1
fi

# Random 16-byte salt → base64 → trim padding → 22 chars (argon2 CLI
# accepts >=8 chars).
SALT=$(head -c 16 /dev/urandom | base64 | tr -d '=' | head -c 22)

# Match the Rust crate's defaults — m=19456 KiB, t=2, p=1
# (RFC 9106 «t=2» recommended). -e = PHC encoded output.
echo -n "$PW" | argon2 "$SALT" -id -t 2 -k 19456 -p 1 -e
