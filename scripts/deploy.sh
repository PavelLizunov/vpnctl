#!/usr/bin/env bash

set -euo pipefail

DAEMON_DST=${VPNCTL_DAEMON_DST:-/opt/vpnctl/vpnctld}
CLI_DST=${VPNCTL_CLI_DST:-/usr/local/bin/vpnctl}
SING_BOX_DST=${VPNCTL_SING_BOX_ARTIFACT:-/opt/vpnctl/node-artifacts/sing-box}
STATS_HELPER_DST=${VPNCTL_STATS_HELPER_ARTIFACT:-/opt/vpnctl/node-artifacts/singbox-stats-helper}
TURNRELAY_DST=${VPNCTL_TURNRELAY_ARTIFACT_DIR:-/opt/vpnctl/node-artifacts}
TURNRELAY_SRC=${VPNCTL_TURNRELAY_SRC:-}
INSTALL_OWNER=${VPNCTL_INSTALL_OWNER-root:root}
BUILD_TARGET=${VPNCTL_BUILD_TARGET:-x86_64-unknown-linux-musl}

log() { echo "[deploy] $*" >&2; }

# Keep the lock inode in place so waiting runs cannot lock a different file.
LOCK_FILE=${VPNCTL_DEPLOY_LOCK:-${DAEMON_DST}.deploy.lock}
mkdir -p "$(dirname "$LOCK_FILE")"
exec 9>"$LOCK_FILE"
flock -x 9

# Admin UI assets are served from disk, so they ship with the binaries. A
# checkout build installs its own daemon/assets; prebuilt artifacts must name
# theirs in VPNCTL_ASSETS_SRC, or set VPNCTL_SKIP_ASSETS=1 to keep the live ones.
DEFAULT_ASSETS_SRC=""

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
    turnrelay_checkout=${SING_BOX_VPNCTL_DIR:-}
    if [ -z "$turnrelay_checkout" ]; then
        for candidate in "$PWD/../sing-box-vpnctl" /var/lib/dsh/Project/sing-box-vpnctl; do
            if [ -f "$candidate/protocol/turnrelay/UPSTREAM" ]; then
                turnrelay_checkout=$candidate
                break
            fi
        done
    fi
    if [ -z "$TURNRELAY_SRC" ] && [ -n "$turnrelay_checkout" ] && [ -f "$turnrelay_checkout/protocol/turnrelay/UPSTREAM" ]; then
        TURNRELAY_SRC=target/node-artifacts/turnrelay-server
        SING_BOX_VPNCTL_DIR=$turnrelay_checkout \
            tools/turnrelay-server/build.sh "$TURNRELAY_SRC"
    elif [ -z "$TURNRELAY_SRC" ]; then
        log "TurnRelay exit-server artifacts skipped (set SING_BOX_VPNCTL_DIR to a sing-box-vpnctl checkout with protocol/turnrelay/UPSTREAM)"
    fi
    DEFAULT_ASSETS_SRC=daemon/assets
else
    log "usage: deploy.sh [<vpnctld> <vpnctl> <sing-box> <stats-helper>]"
    log "TurnRelay artifacts: set VPNCTL_TURNRELAY_SRC to a directory with turnrelay-server-{amd64,arm64,armv7} and .sha256 sidecars (optional)"
    exit 2
fi

[ -f "$DAEMON_SRC" ] || { log "FAIL: daemon binary not found: $DAEMON_SRC"; exit 1; }
[ -f "$CLI_SRC" ] || { log "FAIL: cli binary not found: $CLI_SRC"; exit 1; }
[ -f "$SING_BOX_SRC" ] || { log "FAIL: sing-box artifact not found: $SING_BOX_SRC"; exit 1; }
[ -f "$STATS_HELPER_SRC" ] || { log "FAIL: stats helper not found: $STATS_HELPER_SRC"; exit 1; }
if [ -n "$TURNRELAY_SRC" ]; then
    [ -d "$TURNRELAY_SRC" ] || { log "FAIL: TurnRelay artifact dir not found: $TURNRELAY_SRC"; exit 1; }
    for arch in amd64 arm64 armv7; do
        [ -f "$TURNRELAY_SRC/turnrelay-server-$arch" ] || {
            log "FAIL: TurnRelay $arch binary not found: $TURNRELAY_SRC/turnrelay-server-$arch"
            exit 1
        }
        [ -f "$TURNRELAY_SRC/turnrelay-server-$arch.sha256" ] || {
            log "FAIL: TurnRelay $arch checksum not found: $TURNRELAY_SRC/turnrelay-server-$arch.sha256"
            exit 1
        }
    done
fi

ASSETS_DIR=${VPNCTL_ASSETS_DST:-/opt/vpnctl/assets}
ASSETS_SRC=${VPNCTL_ASSETS_SRC:-$DEFAULT_ASSETS_SRC}
if [ -n "$ASSETS_SRC" ]; then
    [ -d "$ASSETS_SRC" ] || { log "FAIL: assets dir not found: $ASSETS_SRC"; exit 1; }
elif [ "${VPNCTL_SKIP_ASSETS:-0}" != 1 ]; then
    log "FAIL: prebuilt artifacts need their admin UI assets: set VPNCTL_ASSETS_SRC (or VPNCTL_SKIP_ASSETS=1 to keep the live assets)"
    exit 1
fi

SOURCES=("$SING_BOX_SRC" "$STATS_HELPER_SRC" "$CLI_SRC" "$DAEMON_SRC")
DESTINATIONS=("$SING_BOX_DST" "$STATS_HELPER_DST" "$CLI_DST" "$DAEMON_DST")
MODES=(0755 0755 0755 0755)
if [ -n "$TURNRELAY_SRC" ]; then
    turnrelay_sources=()
    turnrelay_destinations=()
    turnrelay_modes=()
    for arch in amd64 arm64 armv7; do
        for suffix in "" ".sha256"; do
            turnrelay_sources+=("$TURNRELAY_SRC/turnrelay-server-$arch$suffix")
            turnrelay_destinations+=("$TURNRELAY_DST/turnrelay-server-$arch$suffix")
            if [ -z "$suffix" ]; then
                turnrelay_modes+=(0755)
            else
                turnrelay_modes+=(0644)
            fi
        done
    done
    SOURCES=("${SOURCES[@]:0:2}" "${turnrelay_sources[@]}" "${SOURCES[@]:2}")
    DESTINATIONS=("${DESTINATIONS[@]:0:2}" "${turnrelay_destinations[@]}" "${DESTINATIONS[@]:2}")
    MODES=("${MODES[@]:0:2}" "${turnrelay_modes[@]}" "${MODES[@]:2}")
fi
STAGED=()
BACKUPS=()
EXISTED=()
SWAPPED=0
SUCCESS=0
ASSETS_STAGED=""
ASSETS_BACKUP="${ASSETS_DIR}.rollback.$$"
ASSETS_HAD_PREV=0
ASSETS_SWAPPED=0

rollback() {
    local status=$? i
    trap - EXIT HUP INT TERM
    if [ "$SUCCESS" -eq 0 ]; then
        set +e
        for ((i=SWAPPED-1; i>=0; i--)); do
            if [ "${EXISTED[$i]}" -eq 1 ]; then
                [ -e "${BACKUPS[$i]}" ] || [ -L "${BACKUPS[$i]}" ] || continue
                mv -f "${BACKUPS[$i]}" "${DESTINATIONS[$i]}"
            else
                rm -f "${DESTINATIONS[$i]}"
            fi
        done
        if [ "$ASSETS_SWAPPED" -eq 1 ]; then
            if [ -e "$ASSETS_BACKUP" ]; then
                rm -rf "$ASSETS_DIR"
                mv -f "$ASSETS_BACKUP" "$ASSETS_DIR"
            elif [ "$ASSETS_HAD_PREV" -eq 0 ]; then
                rm -rf "$ASSETS_DIR"
            fi
        fi
        log "rolled back interrupted artifact install"
    fi
    rm -f "${STAGED[@]}" "${BACKUPS[@]}"
    [ -z "$ASSETS_STAGED" ] || rm -rf "$ASSETS_STAGED"
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
            -m "${MODES[$i]}" "${SOURCES[$i]}" "$staged"
    else
        install -m "${MODES[$i]}" "${SOURCES[$i]}" "$staged"
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

if [ -n "$ASSETS_SRC" ]; then
    mkdir -p "$(dirname "$ASSETS_DIR")"
    ASSETS_STAGED="${ASSETS_DIR}.stage.$$"
    rm -rf "$ASSETS_STAGED"
    cp -R "$ASSETS_SRC" "$ASSETS_STAGED"
    chmod -R a+rX "$ASSETS_STAGED"
    if [ -e "$ASSETS_DIR" ]; then
        ASSETS_HAD_PREV=1
    fi
fi

for i in "${!STAGED[@]}"; do
    SWAPPED=$((i + 1))
    mv -f "${STAGED[$i]}" "${DESTINATIONS[$i]}"
    log "installed ${DESTINATIONS[$i]}"
    if [ "${VPNCTL_FAIL_AFTER_SWAP:-0}" -eq "$SWAPPED" ]; then
        log "injected failure after swap $SWAPPED"
        exit 99
    fi
done

if [ -n "$ASSETS_STAGED" ]; then
    ASSETS_SWAPPED=1
    if [ "$ASSETS_HAD_PREV" -eq 1 ]; then
        mv "$ASSETS_DIR" "$ASSETS_BACKUP"
    fi
    mv "$ASSETS_STAGED" "$ASSETS_DIR"
    ASSETS_STAGED=""
    log "installed $ASSETS_DIR"
    if [ "${VPNCTL_FAIL_AFTER_ASSETS:-0}" -eq 1 ]; then
        log "injected failure after assets swap"
        exit 99
    fi
elif [ -d "$ASSETS_DIR" ]; then
    log "assets kept as they are (VPNCTL_SKIP_ASSETS=1)"
    chmod -R a+rX "$ASSETS_DIR"
fi

SUCCESS=1
trap - EXIT HUP INT TERM
rm -f "${BACKUPS[@]}"
rm -rf "$ASSETS_BACKUP"

log "ok: control-plane and node artifacts installed from the same revision"
log "next: sudo systemctl restart vpnctld"
