#!/usr/bin/env bash
set -euo pipefail

threshold_gb="${1:-8}"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace_dir="$(dirname "$script_dir")"
target_dir="$workspace_dir/target"

if [ ! -d "$target_dir" ]; then
    echo "gc: no target/ dir — nothing to clean"
    exit 0
fi

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
    rm -rf "$target_dir"
fi
echo "gc: freed ${size_gb_disp}G"
