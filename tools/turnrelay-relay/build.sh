#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <output-directory>" >&2
    exit 2
fi
mkdir -p "$1"
out=$(realpath "$1")
cd "$(dirname "${BASH_SOURCE[0]}")"
export GOTOOLCHAIN=auto GOWORK=off

for arch in amd64 arm64 armv7; do
    goarch=$arch
    if [ "$arch" = armv7 ]; then goarch=arm; fi
    CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" GOARM=7 \
        go build -trimpath -ldflags='-s -w -buildid=' -o "$out/turnrelay-relay-$arch" .
    (cd "$out" && sha256sum "turnrelay-relay-$arch" > "turnrelay-relay-$arch.sha256")
done
cd "$out"
cat turnrelay-relay-{amd64,arm64,armv7}.sha256 > turnrelay-relay.sha256
