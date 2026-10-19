#!/usr/bin/env bash
set -euo pipefail

VERSION="${SINGBOX_VERSION:-1.14.2-vpnctl.2}"
TARGET_ARCH="${TARGET_ARCH:-$(uname -m)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-${HERE}/sing-box-${VERSION}-${TARGET_ARCH}}"
FORCE_BUILD="${FORCE_BUILD:-0}"

case "$TARGET_ARCH" in
    x86_64|amd64)
        ASSET="sing-box-${VERSION}-linux-amd64.tar.gz"
        EXPECTED_SHA="095a575fb412e5520b5c16449002073a5ba587646b96e3dddd2c59473d5be2d8"
        GOARCH="amd64"
        ;;
    aarch64|arm64)
        ASSET="sing-box-${VERSION}-linux-arm64.tar.gz"
        EXPECTED_SHA="2758b44eda76465281e3c6d14b91dd5e6b5e9d50f549f8e3205cdc0a31c577d3"
        GOARCH="arm64"
        ;;
    armv7*|armhf)
        ASSET="sing-box-${VERSION}-linux-armv7.tar.gz"
        EXPECTED_SHA="85567a8809bed3abc0b385faa04c51c3edf976445f30dc0ef935bd4cb1f08c6f"
        GOARCH="arm"
        ;;
    *)
        echo "unsupported arch '$TARGET_ARCH' for sing-box-vpnctl" >&2
        exit 1
        ;;
esac

RELEASE_URL="https://github.com/PavelLizunov/sing-box-vpnctl/releases/download/v${VERSION}/${ASSET}"
mkdir -p "$(dirname "$OUT")"

verify_or_skip_exec() {
    local host_arch
    host_arch=$(uname -m)
    local can_execute=0
    if [ "$TARGET_ARCH" = "$host_arch" ] || \
       { [ "$TARGET_ARCH" = "amd64" ] && [ "$host_arch" = "x86_64" ]; } || \
       { [ "$TARGET_ARCH" = "x86_64" ] && [ "$host_arch" = "amd64" ]; } || \
       { [ "$TARGET_ARCH" = "arm64" ] && [ "$host_arch" = "aarch64" ]; } || \
       { [ "$TARGET_ARCH" = "aarch64" ] && [ "$host_arch" = "arm64" ]; }; then
        can_execute=1
    fi

    if [ "$can_execute" = "1" ]; then
        "$OUT" version
    else
        echo "acquired binary for $TARGET_ARCH (execution check skipped on host $host_arch)"
    fi
}

if [ "$FORCE_BUILD" != "1" ]; then
    echo "downloading sing-box-vpnctl release ${VERSION} (${TARGET_ARCH})..."
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT
    curl -fsSL -o "$TMPDIR/$ASSET" "$RELEASE_URL"
    echo "$EXPECTED_SHA  $TMPDIR/$ASSET" | sha256sum -c -
    tar -xzf "$TMPDIR/$ASSET" -C "$TMPDIR"
    BIN=$(find "$TMPDIR" -type f -name sing-box)
    install -m 0755 "$BIN" "$OUT"
    echo "installed: $OUT"
    verify_or_skip_exec
    exit 0
fi

TAG="v${VERSION}"
WORK="${WORK:-/tmp/sb-vpnctl-build}"
TAGS="with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_clash_api,with_v2ray_api,with_naive_outbound,with_purego,badlinkname,tfogo_checklinkname0,with_xhttp,with_awg"

rm -rf "$WORK"
git clone --depth 1 -b "$TAG" https://github.com/PavelLizunov/sing-box-vpnctl "$WORK"

cd "$WORK"
CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" go build -trimpath \
  -tags "$TAGS" \
  -ldflags "-s -w -checklinkname=0 -X github.com/sagernet/sing-box/constant.Version=${VERSION}" \
  -o "$OUT" ./cmd/sing-box

echo "built: $OUT"
verify_or_skip_exec
