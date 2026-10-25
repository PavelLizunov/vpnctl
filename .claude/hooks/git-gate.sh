#!/usr/bin/env bash

set -uo pipefail

cmd=$(python3 -c '
import json, sys
try:
    print(json.load(sys.stdin).get("tool_input", {}).get("command", ""))
except Exception:
    print("")
' 2>/dev/null)

case "$cmd" in
    *'git commit'*|*'git push'*) ;;
    *) exit 0 ;;
esac

if [[ "$cmd" == *'--no-verify'* ]]; then
    cat >&2 <<'BYPASS'
⚠ vpnctl git-gate: --no-verify bypassed local gate.
   GitHub CI will still run (cargo fmt + clippy + test + deny).
BYPASS
    exit 0
fi

script_dir=$(dirname -- "$(readlink -f -- "$0")")
repo_root=$(dirname -- "$(dirname -- "$script_dir")")

gate_root="$repo_root"
cd_line=$(printf '%s\n' "$cmd" | grep -m1 -E '^[[:space:]]*cd[[:space:]]+' || true)
if [[ -n "$cd_line" ]]; then
    cd_dir=$(printf '%s\n' "$cd_line" \
        | sed -E 's/^[[:space:]]*cd[[:space:]]+//; s/[[:space:]]*(&&|;|\|).*$//; s/[[:space:]]+$//')
    cd_dir=${cd_dir#\"}; cd_dir=${cd_dir%\"}
    cd_dir=${cd_dir#\'}; cd_dir=${cd_dir%\'}
    if [[ -n "$cd_dir" && -f "$cd_dir/Cargo.toml" ]]; then
        gate_root="$cd_dir"
    fi
fi

if [[ ! -f "$gate_root/Cargo.toml" ]]; then
    exit 0
fi

export PATH="$HOME/.cargo/bin:$PATH"
if ! command -v cargo >/dev/null 2>&1; then
    cat >&2 <<'NOCARGO'
⚠ vpnctl git-gate: cargo not on PATH; gate skipped.
   Re-install with:
     curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
       --default-toolchain stable --profile minimal --component rust-analyzer
NOCARGO
    exit 0
fi

cd "$gate_root" || exit 0

run_or_block() {
    local label="$1"; shift
    local out
    if ! out=$("$@" 2>&1); then
        echo "" >&2
        echo "🛑 vpnctl git-gate: $label FAILED (tree: $gate_root)" >&2
        echo "$out" | tail -n 30 >&2
        cat >&2 <<EOF

→ Fix the issue above and re-commit, or bypass with --no-verify if intentional WIP.
EOF
        exit 2
    fi
}

run_or_block "cargo fmt --check" cargo fmt --all -- --check

run_or_block "cargo clippy --workspace --all-targets -- -D warnings" \
    cargo clippy --workspace --all-targets -- -D warnings

case "$cmd" in
    *'git push'*)
        run_or_block "cargo test --workspace" cargo test --workspace --all-targets
        ;;
esac

cat >&2 <<GREEN

🤖 vpnctl git-gate green (tree: $gate_root).
   Reminders (AGENTS.md → Change review workflow):
  1. review-agent on the diff?              (Agent / general-purpose)
  2. test-writer-agent for new public APIs? (spec only, no impl)
  3. After push: gh run watch <id> --exit-status to verify CI.
GREEN

exit 0
