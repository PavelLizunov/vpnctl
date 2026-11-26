set -eu
umask 077
base=/etc/vpnctl-turnrelay
binary=/usr/local/libexec/vpnctl-turnrelay/turnrelay-relay
service=vpnctl-turnrelay-relay.service
unit=/etc/systemd/system/$service
env_file=$base/relay.env
exec 9>"$base/.relay-apply.lock"
flock -x 9
stage=$(mktemp -d "$base/.relay-apply.XXXXXXXX")
changed=0
was_active=0
was_enabled=0

finish() {
    result=$?
    trap - EXIT
    if [ "$result" != 0 ] && [ "$changed" = 1 ]; then
        systemctl stop "$service" || true
        if [ "$was_enabled" = 0 ]; then systemctl disable "$service" || true; fi
        for file in "$binary" "$env_file" "$unit"; do
            backup="$stage/previous/${file##*/}"
            if [ -f "$backup" ]; then cp -p "$backup" "$file" || true; else rm -f -- "$file"; fi
        done
        systemctl daemon-reload || true
        if [ "$was_active" = 1 ]; then systemctl start "$service" || true; fi
    fi
    rm -rf -- "$stage"
    exit "$result"
}
trap finish EXIT
trap 'exit 1' HUP INT TERM
mkdir "$stage/previous"
for file in "$binary" "$env_file" "$unit"; do
    if [ -f "$file" ]; then cp -p "$file" "$stage/previous/"; fi
done
if systemctl is-active --quiet "$service"; then was_active=1; fi
if systemctl is-enabled --quiet "$service"; then was_enabled=1; fi
printf '%s' "$relay_env" > "$stage/relay.env"
printf '%s' "$relay_unit" > "$stage/$service"
changed=1
install -m 0755 "$binary.candidate" "$binary.new"
mv -f "$binary.new" "$binary"
install -m 0600 "$stage/relay.env" "$env_file.new"
mv -f "$env_file.new" "$env_file"
install -m 0644 "$stage/$service" "$unit.new"
mv -f "$unit.new" "$unit"
systemd-analyze verify "$unit" 2>/dev/null
systemctl daemon-reload
systemctl enable "$service"
systemctl restart "$service"

for attempt in 1 2 3 4 5 6 7 8 9 10; do
    relay_pid=$(systemctl show "$service" -p MainPID --value)
    if [ "$relay_pid" != 0 ] &&
        ss -H -lntp sport = :"$relay_port" | grep -Fq "pid=$relay_pid," &&
        ss -H -lnup sport = :"$relay_port" | grep -Fq "pid=$relay_pid,"; then
        if command -v ufw >/dev/null 2>&1 && LC_ALL=C ufw status 2>/dev/null | grep -qx 'Status: active'; then
            ufw allow "$relay_port/tcp" comment 'vpnctl managed ingress' || true
            ufw allow "$relay_port/udp" comment 'vpnctl managed ingress' || true
        elif command -v iptables >/dev/null 2>&1; then
            for transport in tcp udp; do
                iptables -w -C INPUT -p "$transport" --dport "$relay_port" -j ACCEPT 2>/dev/null ||
                    iptables -w -I INPUT -p "$transport" --dport "$relay_port" -j ACCEPT || true
            done
        fi
        exit 0
    fi
    sleep 0.2
done
echo 'TurnRelay entry did not bind both TCP and UDP' >&2
exit 1
