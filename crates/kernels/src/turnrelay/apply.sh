set -eu
umask 077
base=/etc/vpnctl-turnrelay
cert=/var/lib/vpnctl-turnrelay/cert.pem
exec 9>"$base/.apply.lock"
flock -x 9
stage=$(mktemp -d "$base/.apply.XXXXXXXX")
previous="$stage/previous"
changed=0
files="/etc/vpnctl-turnrelay/server.env /etc/vpnctl-turnrelay/applied /usr/local/libexec/vpnctl-turnrelay/turnrelay-server /etc/systemd/system/vpnctl-turnrelay.service"
units="vpnctl-turnrelay.service"
finish() {
    result=$?
    trap - EXIT
    if [ "$result" != 0 ] && [ "$changed" = 1 ]; then
        systemctl stop $units || true
        for unit in $units; do
            if [ ! -e "$previous/enabled-$unit" ]; then systemctl disable "$unit" || true; fi
        done
        for file in $files; do
            saved="$previous/${file##*/}"
            if [ -f "$saved" ]; then cp -p "$saved" "$file" || true; else rm -f -- "$file"; fi
        done
        systemctl daemon-reload || true
        for unit in $units; do
            if [ -e "$previous/active-$unit" ]; then systemctl start "$unit" || true; fi
        done
    fi
    rm -rf -- "$stage"
    exit "$result"
}
trap finish EXIT
trap 'exit 1' HUP INT TERM
install -d -m 0755 /usr/local/libexec/vpnctl-turnrelay
install -d -m 0700 /var/lib/vpnctl-turnrelay
command -v nft >/dev/null
command -v openssl >/dev/null
if ! systemctl is-active --quiet vpnctl-turnrelay.service; then
    if ss -H -lnu sport = :"$turnrelay_port" | awk -v want=":$turnrelay_port" \
        '$4 ~ /^(0\.0\.0\.0|\*|\[::\])/ && substr($4, length($4)-length(want)+1) == want { found=1 } END { exit !found }'; then
        echo 'TurnRelay UDP port is already occupied on the node' >&2
        exit 1
    fi
fi
printf 'TURNRELAY_LISTEN=%s\nTURNRELAY_MODE=%s\nTURNRELAY_PASSWORD=%s\nTURNRELAY_CERT=%s\n' \
    "$turnrelay_listen" "$turnrelay_mode" "$turnrelay_password" "$cert" > "$stage/server.env"
printf '%s\n' "$turnrelay_applied" > "$stage/applied"
printf '%s\n' "$turnrelay_unit" > "$stage/vpnctl-turnrelay.service"
mkdir -m 0700 "$previous"
for file in $files; do
    if [ -f "$file" ]; then cp -p "$file" "$previous/${file##*/}"; fi
done
for unit in $units; do
    if systemctl is-enabled --quiet "$unit"; then touch "$previous/enabled-$unit"; fi
    if systemctl is-active --quiet "$unit"; then touch "$previous/active-$unit"; fi
done
changed=1
install -m 0755 /usr/local/libexec/vpnctl-turnrelay/turnrelay-server.candidate /usr/local/libexec/vpnctl-turnrelay/.turnrelay-server.new
mv -f /usr/local/libexec/vpnctl-turnrelay/.turnrelay-server.new /usr/local/libexec/vpnctl-turnrelay/turnrelay-server
install -m 0600 "$stage/server.env" "$base/server.env.new"
mv -f "$base/server.env.new" "$base/server.env"
install -m 0644 "$stage/applied" "$base/applied.new"
mv -f "$base/applied.new" "$base/applied"
install -m 0644 "$stage/vpnctl-turnrelay.service" /etc/systemd/system/vpnctl-turnrelay.service
systemd-analyze verify "$stage/vpnctl-turnrelay.service" 2>/dev/null
systemctl daemon-reload
systemctl enable vpnctl-turnrelay.service
systemctl restart vpnctl-turnrelay.service
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    relay_pid=$(systemctl show vpnctl-turnrelay.service -p MainPID --value)
    if [ "$relay_pid" != 0 ] && [ -s "$cert" ] &&
        ss -H -lnup sport = :"$turnrelay_port" | grep -Fq "pid=$relay_pid,"; then
        exit 0
    fi
    sleep 0.2
done
echo 'TurnRelay service did not bind its UDP listener' >&2
exit 1
