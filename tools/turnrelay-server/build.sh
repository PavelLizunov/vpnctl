#!/usr/bin/env bash
# Build the three pinned TurnRelay exit-server artifacts.
#
# The source tree is the upstream romanrublev/turnrelay repository at the
# commit pinned below. When the sibling `sing-box-vpnctl` checkout carries a
# `patches/turnrelay-server/` directory, its *.patch files are applied on top
# in lexical order before building; set TURNRELAY_PATCH_DIR to point at a
# different patch set. The controller verifies each artifact against the
# `.sha256` sidecar written here before installing it on a node.
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <output-directory>" >&2
    exit 2
fi
mkdir -p "$1"
out=$(realpath "$1")

repo=https://github.com/romanrublev/turnrelay.git
commit=4c3dc7ad19f564bf6a1e82ab53038cb85a835420
patch_dir=${TURNRELAY_PATCH_DIR:-"$(cd "$(dirname "$0")/../.." && pwd)/../sing-box-vpnctl/patches/turnrelay-server"}

src=$(mktemp -d "${TMPDIR:-/tmp}/turnrelay-src.XXXXXXXX")
trap 'rm -rf -- "$src"' EXIT

git init -q "$src"
git -C "$src" remote add origin "$repo"
git -C "$src" fetch -q --depth=1 origin "$commit"
git -C "$src" checkout -q --detach FETCH_HEAD
test "$(git -C "$src" rev-parse HEAD)" = "$commit"

if [ -d "$patch_dir" ]; then
    shopt -s nullglob
    patches=("$patch_dir"/*.patch)
    shopt -u nullglob
    for patch in "${patches[@]}"; do
        git -C "$src" apply --check "$patch"
        git -C "$src" apply "$patch"
    done
    if [ "${#patches[@]}" -ne 0 ]; then
        echo "applied ${#patches[@]} TurnRelay patch(es) from $patch_dir" >&2
    fi
else
    echo "no TurnRelay patch directory at $patch_dir; building upstream $commit" >&2
fi

export GOTOOLCHAIN=go1.26.11 GOWORK=off
cd "$src"
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
