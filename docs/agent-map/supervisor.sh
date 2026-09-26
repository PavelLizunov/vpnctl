#!/usr/bin/env bash
# docs/agent-map/supervisor.sh — Supervisor script for vpnctl agent-map generation
# Ensures resumption from the exact last unanalyzed file/domain if interrupted.

set -euo pipefail

STATE_FILE="docs/agent-map/.state.json"

if [ ! -f "$STATE_FILE" ]; then
    echo "[-] Error: $STATE_FILE not found. Run state initialization first."
    exit 1
fi

python3 - << 'EOF'
import json, sys

with open("docs/agent-map/.state.json", "r") as f:
    state = json.load(f)

pending = [k for k, v in state["domains"].items() if v["status"] == "pending"]
in_progress = [k for k, v in state["domains"].items() if v["status"] == "in_progress"]
completed = [k for k, v in state["domains"].items() if v["status"] == "completed"]

total_files = state["total_files"]
done_files = sum(v["file_count"] for k, v in state["domains"].items() if v["status"] == "completed")
done_loc = sum(v["loc"] for k, v in state["domains"].items() if v["status"] == "completed")

print(f"[STATUS] Domains completed: {len(completed)}/{len(state['domains'])}, In-progress: {len(in_progress)}, Pending: {len(pending)}")
print(f"[PROGRESS] Files audited: {done_files}/{total_files} ({(done_files/total_files*100):.1f}%), Lines: {done_loc}/{state['total_lines']}")

if in_progress:
    print(f"[NEXT ACTION] Resuming in-progress domain: {in_progress[0]}")
elif pending:
    print(f"[NEXT ACTION] Starting next pending domain: {pending[0]}")
else:
    print("[NEXT ACTION] All domains completed! Ready for master INDEX.md synthesis.")
EOF
