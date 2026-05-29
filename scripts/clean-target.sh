#!/usr/bin/env bash
# clean-target.sh — threshold-guarded `cargo clean`.
#
# Why this exists: the vpnctl dev/deploy loop runs many
# `cargo build` / `cargo zigbuild` / `cargo test` cycles, and the
# claude-chat container's 40G disk has filled to >70% from a 14G
# `target/` more than once (we keep forgetting to clean it). There is
# NO cron / systemd in the container to clean on a timer, so disk
# hygiene is wired into the build pipeline instead: `just ci` (and an
# explicit `just gc`) call this first.
#
# It deletes `target/` ONLY when it exceeds THRESHOLD_GB, so a normal
# warm-cache build is never thrown away — the guard fires only after
# stale cross-compile / debug / test artifacts have genuinely piled up,
# at which point a one-off rebuild is a fair price for not filling the
# disk.
#
# Usage: clean-target.sh [THRESHOLD_GB]   (default 8)
set -euo pipefail

threshold_gb="${1:-8}"

# Workspace root = parent of this script's dir (scripts/ lives at the
# workspace root). Resolves regardless of the caller's cwd.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace_dir="$(dirname "$script_dir")"
target_dir="$workspace_dir/target"

if [ ! -d "$target_dir" ]; then
    echo "gc: no target/ dir — nothing to clean"
    exit 0
fi

# Size in KB (-s summarize → one number; -k → KiB blocks, portable).
size_kb="$(du -sk "$target_dir" | cut -f1)"
threshold_kb=$(( threshold_gb * 1024 * 1024 ))
size_gb_disp=$(( size_kb / 1024 / 1024 ))

if [ "$size_kb" -lt "$threshold_kb" ]; then
    echo "gc: target/ is ${size_gb_disp}G (< ${threshold_gb}G threshold) — keeping warm cache"
    exit 0
fi

echo "gc: target/ is ${size_gb_disp}G (>= ${threshold_gb}G threshold) — cleaning…"
if command -v cargo >/dev/null 2>&1; then
    ( cd "$workspace_dir" && cargo clean )
else
    # cargo not on PATH (container lost the toolchain on restart) —
    # `rm -rf target` is exactly what `cargo clean` does for the space.
    rm -rf "$target_dir"
fi
echo "gc: freed ${size_gb_disp}G"
