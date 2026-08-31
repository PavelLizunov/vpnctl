#!/usr/bin/env bash
set -euo pipefail

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT=${1:-"$HERE/bin/singbox-stats-helper"}
mkdir -p "$(dirname -- "$OUT")"
OUT=$(cd "$(dirname -- "$OUT")" && pwd)/$(basename -- "$OUT")
cd "$HERE"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=readonly -trimpath \
    -ldflags='-s -w' -o "$OUT" .
printf 'built %s\n' "$OUT"
