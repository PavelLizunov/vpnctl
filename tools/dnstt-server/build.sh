#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <output-directory>" >&2
    exit 2
fi
mkdir -p "$1"
out=$(realpath "$1")
export GOTOOLCHAIN=go1.26.11 GOWORK=off
module=www.bamsoftware.com/git/dnstt.git@v1.20260501.0
source_dir=$(go mod download -json "$module" | python3 -c '
import json
import sys

source = json.load(sys.stdin)
if source.get("Sum") != "h1:8i4tQWwBCrhsn6+c8fpjSIyaa+u0MOvdOa1FIxNOz6M=":
    sys.exit("DNSTT module checksum mismatch")
print(source["Dir"])
')
cd "$source_dir"
for arch in amd64 arm64 armv7; do
    goarch="$arch"
    if [ "$arch" = armv7 ]; then goarch=arm; fi
    CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" GOARM=7 \
        go build -trimpath -ldflags='-s -w -buildid=' \
        -o "$out/dnstt-server-$arch" ./dnstt-server
done
cd "$out"
sha256sum -c <<'SHA256'
8ad795cd9bd862b3c5bd9fa358c6ae889987c8b52c6bddeb4d5c67d86bfb97f0  dnstt-server-amd64
ffbc3f00e9d480dc153f62132bfc0f47d67970f9136eed347ec8e6e25d00064e  dnstt-server-arm64
82eb7763f6e58d86ac9fbe8dad428d4a5937dedb6e33ae4d04233bf01adb9db0  dnstt-server-armv7
SHA256
