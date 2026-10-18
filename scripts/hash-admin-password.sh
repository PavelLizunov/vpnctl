#!/usr/bin/env bash

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

SALT=$(head -c 16 /dev/urandom | base64 | tr -d '=' | head -c 22)

echo -n "$PW" | argon2 "$SALT" -id -t 2 -k 19456 -p 1 -e
