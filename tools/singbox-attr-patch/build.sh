#!/usr/bin/env bash
set -euo pipefail

FORCE_BUILD="${FORCE_BUILD:-0}"
VERSION="1.14.5-vpnctl.1"
TARGET_ARCH="${TARGET_ARCH:-$(uname -m)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-${HERE}/sing-box-${VERSION}-${TARGET_ARCH}}"
SOURCE_REV="74153cb4e936af1b846cfa26053981daedd61f81"
SOURCE_URL="https://github.com/PavelLizunov/sing-box-vpnctl.git"

case "$TARGET_ARCH" in
    x86_64|amd64)
        ASSET="sing-box-${VERSION}-linux-amd64.tar.gz"
        EXPECTED_SHA="72a65339089f9f41a05d746f03c2ee0105878a91a373295a0fae2af07cd2b7d4"
        GOARCH="amd64"
        ;;
    aarch64|arm64)
        ASSET="sing-box-${VERSION}-linux-arm64.tar.gz"
        EXPECTED_SHA="4e8963ca3400238938948dc730e081923d07ed24152653981f6604d73db0888e"
        GOARCH="arm64"
        ;;
    armv7*|armhf)
        ASSET="sing-box-${VERSION}-linux-armv7.tar.gz"
        EXPECTED_SHA="fe2d91bebf34d4f6d2bc3b60ab1a3f8b43d47b172eed496cb3dc0d2b00abfea3"
        GOARCH="arm"
        export GOARM=7
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
        local version_output tags feature
        version_output=$("$OUT" version)
        printf '%s\n' "$version_output"
        if ! grep -Fxq "Revision: $SOURCE_REV" <<<"$version_output"; then
            echo "managed sing-box revision does not match $SOURCE_REV" >&2
            return 1
        fi
        tags=$(sed -n 's/^Tags: //p' <<<"$version_output")
        for feature in with_v2ray_api with_trusttunnel with_mieru; do
            if ! grep -Fxq "$feature" < <(tr ',' '\n' <<<"$tags"); then
                echo "managed sing-box lacks required build tag $feature" >&2
                return 1
            fi
        done
        if grep -Eq '(^|,)(with_naive_outbound|with_purego)(,|$)' <<<"$tags"; then
            echo "managed sing-box includes with_naive_outbound or with_purego" >&2
            return 1
        fi
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

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
TAGS="with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_clash_api,with_v2ray_api,badlinkname,tfogo_checklinkname0,with_xhttp,with_awg,with_turnrelay,with_trusttunnel,with_mieru"

git -C "$WORK" init -q
git -C "$WORK" fetch --depth 1 "$SOURCE_URL" "$SOURCE_REV"
git -C "$WORK" checkout --quiet --detach FETCH_HEAD
test "$(git -C "$WORK" rev-parse HEAD)" = "$SOURCE_REV"
OUT="$(realpath -m "$OUT")"
cd "$WORK"
CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" go build -mod=readonly -trimpath -buildvcs=true \
  -tags "$TAGS" \
  -ldflags "-s -w -checklinkname=0 -X github.com/sagernet/sing-box/constant.Version=${VERSION}+${SOURCE_REV:0:8}" \
  -o "$OUT" ./cmd/sing-box

revision=$(go version -m "$OUT" | awk -F= '/^[[:space:]]*build[[:space:]]+vcs.revision=/{print $2}')
if [ "$revision" != "$SOURCE_REV" ]; then
    echo "sing-box binary revision mismatch: expected $SOURCE_REV, got $revision" >&2
    exit 1
fi

echo "built: $OUT"
verify_or_skip_exec
