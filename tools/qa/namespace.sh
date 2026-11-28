#!/usr/bin/env bash
# Called inside a subordinate UID/GID, PID and network namespace.
set -euo pipefail
exec 3<&0
cat <&3 >/dev/null &
exec 3<&-
state=$1
bundle=$2
ip link set lo up
[[ $(ip -o link | wc -l) -eq 1 && -z $(ip route show default) ]]
base=(bwrap --die-with-parent --unshare-pid --unshare-ipc --unshare-uts --new-session
      --clearenv --setenv PATH /usr/sbin:/usr/bin:/sbin:/bin --setenv HOME /root
      --ro-bind /usr /usr --dev /dev --proc /proc --tmpfs /tmp --dir /run --dir /root)
for path in /bin /sbin /lib /lib64; do
    if [[ -L $path ]]; then base+=(--symlink "$(readlink "$path")" "$path")
    elif [[ -d $path ]]; then base+=(--ro-bind "$path" "$path"); fi
done
caps=()
for cap in CHOWN DAC_OVERRIDE FOWNER KILL SETGID SETUID SYS_CHROOT; do caps+=(--cap-add "CAP_$cap"); done
node=("${base[@]}" --hostname qa-node "${caps[@]}" --dir /run/sshd --dir /var/empty
      --bind "$state/node-etc" /etc --ro-bind "$state/authorized_keys" /root/.ssh/authorized_keys)
if [[ -d /usr/share/empty.sshd ]]; then node+=(--tmpfs /usr/share/empty.sshd); fi
"${node[@]}" "$(command -v sshd)" -De -f /etc/sshd_config &
controller=("${base[@]}" --hostname qa-controller --ro-bind "$state/passwd" /etc/passwd
            --ro-bind "$bundle" /app --chdir /app --bind "$state/controller" /state
            --setenv XDG_DATA_HOME /state --setenv VPNCTL_DB /state/inv.db
            --setenv VPNCTLD_DEPLOY_KEY /state/id_ed25519
            --setenv VPNCTLD_BACKUP_DIR /state/backups)
fingerprint=$(ssh-keygen -lf "$state/node-etc/host_key.pub" | awk '{print $2}')
"${controller[@]}" /bin/sh -ec '
    bin/vpnctl server add qa-node --address 127.0.0.1 --ssh-port 2222 --trusted-fingerprint "$1"
    bin/vpnctl server add qa-offline --address 127.0.0.2 --ssh-port 2223 --trusted-fingerprint "$1"
    bin/vpnctl user add qa-alice
    bin/vpnctl user add qa-bob
    bin/vpnctl user traffic-limit qa-bob --limit-gib 0.048828125
' sh "$fingerprint" >/dev/null
"${controller[@]}" /app/bin/vpnctld --addr 127.0.0.1:18402 &
"${base[@]}" --bind "$state/relay" /relay /usr/bin/socat UNIX-LISTEN:/relay/http.sock,fork,mode=0600 TCP4:127.0.0.1:18402 &
wait -n
exit 1
