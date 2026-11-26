#!/usr/bin/env bash
# Build the three pinned TurnRelay exit-server artifacts.
#
# The source tree is the upstream romanrublev/turnrelay repository at the
# commit pinned below. The sibling `sing-box-vpnctl` checkout carries the
# patched upstream files under `protocol/turnrelay/internal/upstream/` and
# lists them in `protocol/turnrelay/UPSTREAM`; every listed file is copied
# into the fetched tree, replacing its upstream counterpart, and its
# sing-box import path is rewritten to the standalone module. Set
# SING_BOX_VPNCTL_DIR to point at a different checkout. The controller
# verifies each artifact against the `.sha256` sidecar written here before
# installing it on a node.
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <output-directory>" >&2
    exit 2
fi
mkdir -p "$1"
out=$(realpath "$1")

repo=https://github.com/romanrublev/turnrelay.git
commit=4c3dc7ad19f564bf6a1e82ab53038cb85a835420
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

fail() {
    echo "turnrelay-server build: $*" >&2
    exit 1
}

if [ -n "${SING_BOX_VPNCTL_DIR:-}" ]; then
    sing_box_dir=$SING_BOX_VPNCTL_DIR
    [ -d "$sing_box_dir" ] || fail "SING_BOX_VPNCTL_DIR is not a directory: $sing_box_dir"
else
    sing_box_dir=""
    for candidate in "$repo_root/../sing-box-vpnctl" "/var/lib/dsh/Project/sing-box-vpnctl"; do
        if [ -f "$candidate/protocol/turnrelay/UPSTREAM" ]; then
            sing_box_dir=$candidate
            break
        fi
    done
    [ -n "$sing_box_dir" ] || fail \
        "no sing-box-vpnctl checkout with protocol/turnrelay/UPSTREAM; set SING_BOX_VPNCTL_DIR"
fi

manifest="$sing_box_dir/protocol/turnrelay/UPSTREAM"
upstream_dir="$sing_box_dir/protocol/turnrelay/internal/upstream"
[ -f "$manifest" ] || fail "missing patched-file manifest: $manifest"
[ -d "$upstream_dir" ] || fail "missing patched-file directory: $upstream_dir"

listed=$(sed -n '/^Patched files:$/,/^$/s/^  //p' "$manifest")
[ -n "$listed" ] || fail "no 'Patched files:' entries in $manifest"

patched_files=()
while IFS= read -r relative; do
    [ -n "$relative" ] || continue
    case $relative in
        /* | .. | ../* | */.. | */../*)
            fail "unsafe patched-file path in $manifest: $relative"
            ;;
    esac
    [ -f "$upstream_dir/$relative" ] || fail \
        "patched file listed in $manifest is missing: $upstream_dir/$relative"
    patched_files+=("$relative")
done <<< "$listed"
[ "${#patched_files[@]}" -gt 0 ] || fail "no patched files listed in $manifest"

src=$(mktemp -d "${TMPDIR:-/tmp}/turnrelay-src.XXXXXXXX")
trap 'rm -rf -- "$src"' EXIT

git init -q "$src"
git -C "$src" remote add origin "$repo"
git -C "$src" fetch -q --depth=1 origin "$commit"
git -C "$src" checkout -q --detach FETCH_HEAD
test "$(git -C "$src" rev-parse HEAD)" = "$commit"

for relative in "${patched_files[@]}"; do
    source_file="$upstream_dir/$relative"
    destination="$src/$relative"
    mkdir -p "$(dirname "$destination")"
    sed 's|github.com/sagernet/sing-box/protocol/turnrelay/internal/upstream|github.com/romanrublev/turnrelay|g' \
        "$source_file" > "$destination"
done
echo "copied ${#patched_files[@]} patched TurnRelay file(s) from $upstream_dir" >&2

# Upstream 4c3dc7ad requires Go 1.27.0; let the toolchain directive select it.
export GOTOOLCHAIN=auto GOWORK=off
cd "$src"
go get github.com/pion/turn/v5@v5.1.3
go mod tidy

for arch in amd64 arm64 armv7; do
    goarch="$arch"
    if [ "$arch" = armv7 ]; then goarch=arm; fi
    CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" GOARM=7 \
        go build -trimpath -ldflags='-s -w -buildid=' \
        -o "$out/turnrelay-server-$arch" ./cmd/turnrelay-server
    (
        cd "$out"
        sha256sum "turnrelay-server-$arch" > "turnrelay-server-$arch.sha256"
    )
done

cd "$out"
cat "turnrelay-server-amd64.sha256" \
    "turnrelay-server-arm64.sha256" \
    "turnrelay-server-armv7.sha256" > turnrelay-server.sha256
cat turnrelay-server.sha256
