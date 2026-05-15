#!/usr/bin/env bash
# vpnctl git-gate hook — runs as PreToolUse on Bash tool.
#
# WHY THIS EXISTS
# ---------------
# The previous PostToolUse hook was a REMINDER (printed text after the
# tool ran). It did not block. Commit `1e33e29` (2026-05-14) shipped
# with `cargo clippy` red because tests passed and the operator (me)
# committed without re-running clippy after `cargo fmt`.
#
# This script is the GATE: PreToolUse runs BEFORE the bash tool
# executes; exit code 2 blocks the tool, exit 0 lets it through.
# The blocked-tool path shows our stderr to the operator, who can
# either fix the underlying issue or bypass with `--no-verify`.
#
# CONTRACT
# --------
# stdin: JSON like {"tool_input":{"command":"git commit -m foo"}}
# stdout: ignored
# stderr: shown to the operator on block (exit 2)
# exit  : 0 = allow tool, 2 = block tool with stderr shown
#
# WHAT IT GATES
# -------------
#  • `git commit` → cargo fmt --check + cargo clippy --workspace -D warnings
#  • `git push`   → above + cargo test --workspace
#  • `--no-verify` flag in the command → bypass with a warning
#  • Anything that's not a git commit/push → instant exit 0 (no overhead)
#  • Outside the vpnctl repo (no Cargo.toml here) → exit 0 (skip)
#  • Cargo not installed → exit 0 + warn (the container loses ~/.cargo
#    on restart per CLAUDE.md "Грабли"; we don't want the gate to brick
#    every commit just because rustup wasn't restored that session)
#
# WHY NOT JUST `just ci`
# ----------------------
# `just ci` runs fmt+clippy+test+deny — ~30s. On EVERY commit that's
# annoying. We split: fast checks (fmt+clippy ~5s) on commit, full
# test on push (~15s). `cargo deny` only runs in CI (it network-fetches
# the RustSec advisory DB, which adds latency without catching anything
# that wouldn't also fail in CI a minute later).
#
# ACTIVATION
# ----------
# Per CLAUDE.md "Гочи методологии": after editing settings.json or
# this script, settings watcher does NOT pick it up mid-session.
# Restart Claude Code or open the /hooks UI for changes to fire.

set -uo pipefail

# Read the JSON tool_input.command from stdin.
cmd=$(python3 -c '
import json, sys
try:
    print(json.load(sys.stdin).get("tool_input", {}).get("command", ""))
except Exception:
    print("")
' 2>/dev/null)

# Bail-fast: not a git commit/push? Let the tool through.
case "$cmd" in
    *'git commit'*|*'git push'*) ;;
    *) exit 0 ;;
esac

# Operator explicit bypass.
if [[ "$cmd" == *'--no-verify'* ]]; then
    cat >&2 <<'BYPASS'
⚠ vpnctl git-gate: --no-verify bypassed local gate.
   GitHub CI will still run (cargo fmt + clippy + test + deny).
BYPASS
    exit 0
fi

# Find the vpnctl repo root. The hook may be invoked from any cwd
# (Claude session might be elsewhere). We anchor by the path the hook
# itself lives in: $0 is .../vpnctl/.claude/hooks/git-gate.sh, so
# repo_root = .../vpnctl.
script_dir=$(dirname -- "$(readlink -f -- "$0")")
repo_root=$(dirname -- "$(dirname -- "$script_dir")")

if [[ ! -f "$repo_root/Cargo.toml" ]]; then
    # Hook lives in a non-Rust repo somehow — silently allow.
    exit 0
fi

# Cargo discovery: claude-chat container loses ~/.cargo on restart.
# Don't brick commits when cargo isn't installed; warn and allow.
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

cd "$repo_root" || exit 0

# Common helper: run a step, capture combined output, on failure print
# the last 30 lines to stderr and exit 2 (block).
run_or_block() {
    local label="$1"; shift
    local out
    if ! out=$("$@" 2>&1); then
        echo "" >&2
        echo "🛑 vpnctl git-gate: $label FAILED" >&2
        echo "$out" | tail -n 30 >&2
        cat >&2 <<EOF

→ Fix the issue above and re-commit, or bypass with --no-verify if intentional WIP.
EOF
        exit 2
    fi
}

# Step 1: formatting (fast — < 1s).
run_or_block "cargo fmt --check" cargo fmt --all -- --check

# Step 2: clippy with workspace + all-targets + warnings as errors.
# Same invocation as `just clippy` and the GitHub CI clippy job.
run_or_block "cargo clippy --workspace --all-targets -- -D warnings" \
    cargo clippy --workspace --all-targets -- -D warnings

# Step 3: tests, but ONLY on push. Commits stay snappy; tests run when
# the change is about to leave the local machine.
case "$cmd" in
    *'git push'*)
        run_or_block "cargo test --workspace" cargo test --workspace --all-targets
        ;;
esac

# Reminder (was the old PostToolUse content — keep it as a nudge after
# the gate passes, when the operator can still see the message before
# the actual commit/push runs).
cat >&2 <<'GREEN'

🤖 vpnctl git-gate green. Reminders (CLAUDE.md → Workflow rules):
  1. review-agent on the diff?              (Agent / general-purpose)
  2. test-writer-agent for new public APIs? (spec only, no impl)
  3. After push: gh run watch <id> --exit-status to verify CI.
GREEN

exit 0
