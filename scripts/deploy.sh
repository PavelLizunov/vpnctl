#!/usr/bin/env bash
# deploy.sh — build (or accept) vpnctld, vpnctl, and the two managed sing-box
# node artifacts from the SAME source revision and install all atomically,
# preserving live paths and systemd units.
#
# Why both binaries together
# --------------------------
# Production used to refresh ONLY /opt/vpnctl/vpnctld, leaving
# /usr/local/bin/vpnctl stale. The weekly vpnctl-update-kernels.service
# (ExecStart=/usr/local/bin/vpnctl update-kernels …) then ran an OLD CLI
# whose embedded inventory migrations lagged the live DB written by the
# newer daemon → the updater failed. Installing daemon + CLI from one
# revision keeps their schema expectations in lockstep.
#
# Build provenance
# ----------------
# In build mode (no arguments) the current git SHA is exported as
# VPNCTL_BUILD_SHA BEFORE `cargo build`, so the binaries embed it via
# `option_env!("VPNCTL_BUILD_SHA")` in `vpnctl_core::build_version()`.
# The daemon health endpoint, admin footer/masthead and `vpnctl --version`
# then all report `<semver>+<sha>` for the exact deployed commit. No git is
# ever invoked at application runtime.
#
# Atomicity
# ---------
# Each binary is `install`-ed to a temp name in the TARGET directory, then
# `mv -f` (rename(2), atomic within one filesystem) over the live path.
# A failed or interrupted copy can therefore never leave a partial
# executable at the live path — it is either the old complete binary or
# the new complete one. ALL sources are validated before any install,
# so a missing/failed build can never leave a half-upgraded host. Temp
# litter is removed on failure.
#
# This script only swaps the binaries. It does NOT edit systemd units and
# does NOT restart anything; restart the daemon afterwards so it picks up
# the new code:
#     sudo systemctl restart vpnctld
#
# Usage (on the production host, via sudo):
#   Build + install from the current checkout:
#     sudo scripts/deploy.sh
#   Install pre-built binaries (built elsewhere, e.g. build-1 → scp):
#     sudo scripts/deploy.sh <vpnctld> <vpnctl> <sing-box> <stats-helper>
#
# Env overrides (non-standard layouts + the regression test):
#     VPNCTL_DAEMON_DST       default /opt/vpnctl/vpnctld
#     VPNCTL_CLI_DST          default /usr/local/bin/vpnctl
#     VPNCTL_SING_BOX_ARTIFACT   default /opt/vpnctl/node-artifacts/sing-box
#     VPNCTL_STATS_HELPER_ARTIFACT default /opt/vpnctl/node-artifacts/singbox-stats-helper
#     VPNCTL_INSTALL_OWNER  default "root:root"; set empty to skip chown
#                           (e.g. an unprivileged test into a tempdir)
#     VPNCTL_BUILD_TARGET   default x86_64-unknown-linux-musl (build mode)

set -euo pipefail

DAEMON_DST=${VPNCTL_DAEMON_DST:-/opt/vpnctl/vpnctld}
CLI_DST=${VPNCTL_CLI_DST:-/usr/local/bin/vpnctl}
SING_BOX_DST=${VPNCTL_SING_BOX_ARTIFACT:-/opt/vpnctl/node-artifacts/sing-box}
STATS_HELPER_DST=${VPNCTL_STATS_HELPER_ARTIFACT:-/opt/vpnctl/node-artifacts/singbox-stats-helper}
INSTALL_OWNER=${VPNCTL_INSTALL_OWNER-root:root}
BUILD_TARGET=${VPNCTL_BUILD_TARGET:-x86_64-unknown-linux-musl}

log() { echo "[deploy] $*" >&2; }

# Resolve all revision-coupled artifacts before installing any of them.
if [ "$#" -eq 4 ]; then
    DAEMON_SRC=$1
    CLI_SRC=$2
    SING_BOX_SRC=$3
    STATS_HELPER_SRC=$4
elif [ "$#" -eq 0 ]; then
    # Build mode: all artifacts from THIS checkout. Export the provenance
    # SHA BEFORE cargo build so option_env!("VPNCTL_BUILD_SHA") picks it
    # up; best-effort — a checkout without git falls back to "unknown".
    VPNCTL_BUILD_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
    export VPNCTL_BUILD_SHA
    log "building vpnctl artifacts from checkout $VPNCTL_BUILD_SHA (target $BUILD_TARGET)"
    cargo build --release --target "$BUILD_TARGET" -p vpnctld -p vpnctl
    DAEMON_SRC=target/$BUILD_TARGET/release/vpnctld
    CLI_SRC=target/$BUILD_TARGET/release/vpnctl
    mkdir -p target/node-artifacts
    OUT="$PWD/target/node-artifacts/sing-box" \
        tools/singbox-attr-patch/build.sh
    tools/singbox-stats-helper/build.sh \
        "$PWD/target/node-artifacts/singbox-stats-helper"
    SING_BOX_SRC=target/node-artifacts/sing-box
    STATS_HELPER_SRC=target/node-artifacts/singbox-stats-helper
else
    log "usage: deploy.sh [<vpnctld> <vpnctl> <sing-box> <stats-helper>]"
    exit 2
fi

# Validate every source before staging or changing a destination.
[ -f "$DAEMON_SRC" ] || { log "FAIL: daemon binary not found: $DAEMON_SRC"; exit 1; }
[ -f "$CLI_SRC" ] || { log "FAIL: cli binary not found: $CLI_SRC"; exit 1; }
[ -f "$SING_BOX_SRC" ] || { log "FAIL: sing-box artifact not found: $SING_BOX_SRC"; exit 1; }
[ -f "$STATS_HELPER_SRC" ] || { log "FAIL: stats helper not found: $STATS_HELPER_SRC"; exit 1; }

# Node artifacts land first; the daemon is the final compatibility switch.
SOURCES=("$SING_BOX_SRC" "$STATS_HELPER_SRC" "$CLI_SRC" "$DAEMON_SRC")
DESTINATIONS=("$SING_BOX_DST" "$STATS_HELPER_DST" "$CLI_DST" "$DAEMON_DST")
STAGED=()
BACKUPS=()
EXISTED=()
SWAPPED=0
SUCCESS=0

rollback() {
    local status=$? i
    trap - EXIT HUP INT TERM
    if [ "$SUCCESS" -eq 0 ]; then
        set +e
        for ((i=SWAPPED-1; i>=0; i--)); do
            if [ "${EXISTED[$i]}" -eq 1 ]; then
                mv -f "${BACKUPS[$i]}" "${DESTINATIONS[$i]}"
            else
                rm -f "${DESTINATIONS[$i]}"
            fi
        done
        log "rolled back interrupted artifact install"
    fi
    rm -f "${STAGED[@]}" "${BACKUPS[@]}"
    if [ "$SUCCESS" -eq 0 ] && [ "$status" -eq 0 ]; then
        status=1
    fi
    exit "$status"
}
trap rollback EXIT HUP INT TERM

# Stage all four complete files and preserve every previous destination before
# the first rename. Backups live beside their destination, so rollback renames
# stay on one filesystem.
for i in "${!SOURCES[@]}"; do
    dst=${DESTINATIONS[$i]}
    dir=$(dirname "$dst")
    mkdir -p "$dir"
    staged=$(mktemp "${dir}/.$(basename "$dst").stage.XXXXXX")
    if [ -n "$INSTALL_OWNER" ]; then
        install -o "${INSTALL_OWNER%%:*}" -g "${INSTALL_OWNER##*:}" \
            -m 0755 "${SOURCES[$i]}" "$staged"
    else
        install -m 0755 "${SOURCES[$i]}" "$staged"
    fi
    STAGED+=("$staged")
    backup="${dir}/.$(basename "$dst").rollback.$$"
    BACKUPS+=("$backup")
    if [ -e "$dst" ] || [ -L "$dst" ]; then
        cp -a "$dst" "$backup"
        EXISTED+=(1)
    else
        EXISTED+=(0)
    fi
done

for i in "${!STAGED[@]}"; do
    mv -f "${STAGED[$i]}" "${DESTINATIONS[$i]}"
    SWAPPED=$((i + 1))
    log "installed ${DESTINATIONS[$i]}"
    if [ "${VPNCTL_FAIL_AFTER_SWAP:-0}" -eq "$SWAPPED" ]; then
        log "injected failure after swap $SWAPPED"
        exit 99
    fi
done

SUCCESS=1
trap - EXIT HUP INT TERM
rm -f "${BACKUPS[@]}"
log "ok: control-plane and node artifacts installed from the same revision"
log "next: sudo systemctl restart vpnctld"
