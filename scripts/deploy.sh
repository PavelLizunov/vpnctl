#!/usr/bin/env bash

set -euo pipefail

DAEMON_DST=${VPNCTL_DAEMON_DST:-/opt/vpnctl/vpnctld}
CLI_DST=${VPNCTL_CLI_DST:-/usr/local/bin/vpnctl}
SING_BOX_DST=${VPNCTL_SING_BOX_ARTIFACT:-/opt/vpnctl/node-artifacts/sing-box}
STATS_HELPER_DST=${VPNCTL_STATS_HELPER_ARTIFACT:-/opt/vpnctl/node-artifacts/singbox-stats-helper}
INSTALL_OWNER=${VPNCTL_INSTALL_OWNER-root:root}
BUILD_TARGET=${VPNCTL_BUILD_TARGET:-x86_64-unknown-linux-musl}

log() { echo "[deploy] $*" >&2; }

if [ "$#" -eq 4 ]; then
    DAEMON_SRC=$1
    CLI_SRC=$2
    SING_BOX_SRC=$3
    STATS_HELPER_SRC=$4
elif [ "$#" -eq 0 ]; then
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

[ -f "$DAEMON_SRC" ] || { log "FAIL: daemon binary not found: $DAEMON_SRC"; exit 1; }
[ -f "$CLI_SRC" ] || { log "FAIL: cli binary not found: $CLI_SRC"; exit 1; }
[ -f "$SING_BOX_SRC" ] || { log "FAIL: sing-box artifact not found: $SING_BOX_SRC"; exit 1; }
[ -f "$STATS_HELPER_SRC" ] || { log "FAIL: stats helper not found: $STATS_HELPER_SRC"; exit 1; }

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

ASSETS_DIR=${VPNCTL_ASSETS_DST:-/opt/vpnctl/assets}
if [ -d "$ASSETS_DIR" ]; then
    chmod -R a+rX "$ASSETS_DIR"
fi

log "ok: control-plane and node artifacts installed from the same revision"
log "next: sudo systemctl restart vpnctld"
