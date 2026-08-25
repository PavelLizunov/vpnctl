#!/bin/sh
set -eu

RUNNER_SRC=${1:-scripts/protocol-assurance-runner.py}
SING_BOX_SRC=${2:-}
XRAY_SRC=${3:-}
LIBEXEC=${VPNCTL_ASSURANCE_LIBEXEC:-/usr/local/libexec/vpnctl}
CONFIG_DIR=${VPNCTL_ASSURANCE_CONFIG_DIR:-/etc/vpnctl/protocol-assurance.d}
RUNNER_DST=${VPNCTL_ASSURANCE_RUNNER_DST:-/usr/local/libexec/vpnctl/protocol-assurance-runner}
ASSURANCE_USER=${VPNCTL_ASSURANCE_USER:-user}

[ -f "$RUNNER_SRC" ] || { echo "runner source missing" >&2; exit 1; }
install -d -o root -g root -m 0755 "$LIBEXEC"
install -d -o "$ASSURANCE_USER" -g "$ASSURANCE_USER" -m 0700 "$CONFIG_DIR"
install -o root -g root -m 0755 "$RUNNER_SRC" "$RUNNER_DST"

if [ -n "$SING_BOX_SRC" ]; then
    [ -f "$SING_BOX_SRC" ] || { echo "sing-box source missing" >&2; exit 1; }
    install -o root -g root -m 0755 "$SING_BOX_SRC" "$LIBEXEC/sing-box"
fi
if [ -n "$XRAY_SRC" ]; then
    [ -f "$XRAY_SRC" ] || { echo "xray source missing" >&2; exit 1; }
    install -o root -g root -m 0755 "$XRAY_SRC" "$LIBEXEC/xray"
fi

python3 -m py_compile "$RUNNER_DST"
find "$CONFIG_DIR" -maxdepth 1 -type f -name '*.json' -exec chmod 0600 {} +
find "$CONFIG_DIR" -maxdepth 1 -type f -name '*.json' -exec chown "$ASSURANCE_USER:$ASSURANCE_USER" {} +

echo "installed $RUNNER_DST"
