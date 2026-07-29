#!/usr/bin/env bash
# deploy.sh — build (or accept) vpnctld (daemon) + vpnctl (CLI) from the SAME
# source revision and install both atomically, preserving the live paths and
# systemd units.
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
# the new complete one. BOTH sources are validated before EITHER install,
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
#     sudo scripts/deploy.sh <path-to-vpnctld> <path-to-vpnctl>
#
# Env overrides (non-standard layouts + the regression test):
#     VPNCTL_DAEMON_DST     default /opt/vpnctl/vpnctld
#     VPNCTL_CLI_DST        default /usr/local/bin/vpnctl
#     VPNCTL_INSTALL_OWNER  default "root:root"; set empty to skip chown
#                           (e.g. an unprivileged test into a tempdir)
#     VPNCTL_BUILD_TARGET   default x86_64-unknown-linux-musl (build mode)

set -euo pipefail

DAEMON_DST=${VPNCTL_DAEMON_DST:-/opt/vpnctl/vpnctld}
CLI_DST=${VPNCTL_CLI_DST:-/usr/local/bin/vpnctl}
INSTALL_OWNER=${VPNCTL_INSTALL_OWNER-root:root}
BUILD_TARGET=${VPNCTL_BUILD_TARGET:-x86_64-unknown-linux-musl}

log() { echo "[deploy] $*" >&2; }

# Resolve the two binaries to install into DAEMON_SRC / CLI_SRC.
if [ "$#" -eq 2 ]; then
    # Install mode: caller supplies pre-built binaries (already stamped
    # with their own build SHA when they were compiled).
    DAEMON_SRC=$1
    CLI_SRC=$2
elif [ "$#" -eq 0 ]; then
    # Build mode: daemon + CLI from THIS checkout. Export the provenance
    # SHA BEFORE cargo build so option_env!("VPNCTL_BUILD_SHA") picks it
    # up; best-effort — a checkout without git falls back to "unknown".
    VPNCTL_BUILD_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
    export VPNCTL_BUILD_SHA
    log "building daemon + CLI from checkout $VPNCTL_BUILD_SHA (target $BUILD_TARGET)"
    cargo build --release --target "$BUILD_TARGET" -p vpnctld -p vpnctl
    DAEMON_SRC=target/$BUILD_TARGET/release/vpnctld
    CLI_SRC=target/$BUILD_TARGET/release/vpnctl
else
    log "usage: deploy.sh [<vpnctld-binary> <vpnctl-binary>]"
    exit 2
fi

# install_atomic <src> <dst> — copy to a temp sibling in <dst>'s directory,
# then atomic-rename over <dst>. Cleans the temp file if the copy fails so
# the live path is never left partial.
install_atomic() {
    local src=$1 dst=$2 dir tmp
    dir=$(dirname "$dst")
    mkdir -p "$dir"
    tmp=$(mktemp "${dir}/.$(basename "$dst").XXXXXX")
    if [ -n "$INSTALL_OWNER" ]; then
        install -o "${INSTALL_OWNER%%:*}" -g "${INSTALL_OWNER##*:}" \
            -m 0755 "$src" "$tmp" || { rm -f "$tmp"; return 1; }
    else
        install -m 0755 "$src" "$tmp" || { rm -f "$tmp"; return 1; }
    fi
    mv -f "$tmp" "$dst"
    log "installed $dst"
}

# Validate BOTH sources up front so a missing CLI binary can never leave a
# half-upgraded host (daemon swapped, CLI still stale — the exact bug).
[ -f "$DAEMON_SRC" ] || { log "FAIL: daemon binary not found: $DAEMON_SRC"; exit 1; }
[ -f "$CLI_SRC" ] || { log "FAIL: cli binary not found: $CLI_SRC"; exit 1; }

install_atomic "$DAEMON_SRC" "$DAEMON_DST"
install_atomic "$CLI_SRC" "$CLI_DST"

log "ok: daemon ($DAEMON_DST) + CLI ($CLI_DST) installed from the same revision"
log "next: sudo systemctl restart vpnctld"
