#!/usr/bin/env bash
# Build vpnctl's managed sing-box node binary. It retains the tiny
# clash-api `metadata.user` patch for live metadata and enables the otherwise
# optional V2Ray Stats API used for exact cumulative per-user accounting.
#
# Requirements: Go >= 1.25.x, git, internet (or a proxy via HTTPS_PROXY).
# Output: a static (CGO-free) linux/amd64 binary `sing-box-<ver>-vpnctl`.
set -euo pipefail

VERSION="${SINGBOX_VERSION:-1.13.19}"
TAG="v${VERSION}"
WORK="${WORK:-/tmp/sb-vpnctl-build}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-${HERE}/sing-box-${VERSION}-vpnctl}"

# Feature tags MATCH the SagerNet release binary's `sing-box version`
# output, MINUS:
#   * with_naive_outbound — pulls cronet-go which REQUIRES CGO; no node
#     uses a naive outbound, so it is safe to drop and keeps the build
#     fully static (CGO_ENABLED=0).
#   * with_musl — only relevant to the CGO+musl static link; irrelevant
#     at CGO_ENABLED=0.
# `-checklinkname=0` is required: common/badtls uses //go:linkname into
# crypto/tls internals, which Go >=1.23 rejects without it.
TAGS="with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_v2ray_api,with_tailscale,with_ccm,with_ocm,badlinkname,tfogo_checklinkname0"

rm -rf "$WORK"
git clone --depth 1 -b "$TAG" https://github.com/SagerNet/sing-box "$WORK"
git -C "$WORK" apply "${HERE}/clash-user.patch"

cd "$WORK"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -tags "$TAGS" \
  -ldflags "-s -w -checklinkname=0 -X github.com/sagernet/sing-box/constant.Version=${VERSION}-vpnctl" \
  -o "$OUT" ./cmd/sing-box

echo "built: $OUT"
"$OUT" version
