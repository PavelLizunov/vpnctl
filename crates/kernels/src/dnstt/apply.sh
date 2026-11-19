set -eu
umask 077
base=/etc/vpnctl-dnstt
exec 9>"$base/.apply.lock"
flock -x 9
stage=$(mktemp -d "$base/.apply.XXXXXXXX")
previous="$stage/previous"
changed=0
files="/etc/vpnctl-dnstt/sshd_config /etc/vpnctl-dnstt/authorized_keys /etc/vpnctl-dnstt/noise.key /etc/vpnctl-dnstt/server.env /usr/local/libexec/vpnctl-dnstt/egress-init /usr/local/libexec/vpnctl-dnstt/dnstt-server /etc/systemd/system/vpnctl-dnstt.service /etc/systemd/system/vpnctl-dnstt-sshd.service"
units="vpnctl-dnstt-sshd.service vpnctl-dnstt.service"
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
install -d -m 0755 /usr/local/libexec/vpnctl-dnstt
command -v nft >/dev/null
command -v ssh-keygen >/dev/null
if ! id vpnctldnstt >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin vpnctldnstt
fi
pilot_uid=$(id -u vpnctldnstt)
[ "$pilot_uid" -ne 0 ]
[ "$(getent passwd vpnctldnstt | cut -d: -f7)" = /usr/sbin/nologin ]
if ! systemctl is-active --quiet vpnctl-dnstt-sshd.service; then
    if [ -n "$(ss -H -lnt sport = :22054)" ]; then
        echo 'DNSTT SSH backend port 22054 is already occupied' >&2
        exit 1
    fi
fi
if ! systemctl is-active --quiet vpnctl-dnstt.service; then
    if ss -H -lnu sport = :53 | awk -v address="$dnstt_address" \
        '$4 == address ":53" || $4 == "0.0.0.0:53" || $4 == "*:53" || $4 == "[::]:53" { conflict = 1 } END { exit !conflict }'; then
        echo 'DNSTT UDP port 53 is already occupied on the node address' >&2
        exit 1
    fi
fi
if [ ! -s "$base/ssh_host_ed25519_key" ]; then
    printf '%s\n' "$dnstt_ssh_host_private" > "$stage/ssh_host_ed25519_key"
    ssh-keygen -y -f "$stage/ssh_host_ed25519_key" >/dev/null
    install -m 0600 "$stage/ssh_host_ed25519_key" "$base/ssh_host_ed25519_key"
fi
printf '%s\n' "$dnstt_sshd" > "$stage/sshd_config"
/usr/sbin/sshd -t -f "$stage/sshd_config"
printf '%s\n' "$dnstt_authorized_keys" > "$stage/authorized_keys"
printf '%s\n' "$dnstt_private" > "$stage/noise.key"
printf 'DNSTT_LISTEN=%s:53\nDNSTT_DOMAIN=%s\n' "$dnstt_address" "$dnstt_domain" > "$stage/server.env"
printf '%s\n' "$dnstt_unit" > "$stage/vpnctl-dnstt.service"
printf '%s\n' "$dnstt_ssh_unit" > "$stage/vpnctl-dnstt-sshd.service"
cat > "$stage/egress-init" <<RULES
#!/bin/sh
set -eu
nft -f - <<NFT
add table inet vpnctl_dnstt
delete table inet vpnctl_dnstt
table inet vpnctl_dnstt {
 chain output {
  type filter hook output priority filter; policy accept;
  meta skuid $pilot_uid fib daddr type local reject
  meta skuid $pilot_uid ip daddr { $dnstt_ipv4_deny } reject
  meta skuid $pilot_uid ip6 daddr { $dnstt_ipv6_deny } reject
 }
}
NFT
RULES
mkdir -m 0700 "$previous"
for file in $files; do
    if [ -f "$file" ]; then cp -p "$file" "$previous/${file##*/}"; fi
done
for unit in $units; do
    if systemctl is-enabled --quiet "$unit"; then touch "$previous/enabled-$unit"; fi
    if systemctl is-active --quiet "$unit"; then touch "$previous/active-$unit"; fi
done
changed=1
install -m 0755 /usr/local/libexec/vpnctl-dnstt/dnstt-server.candidate /usr/local/libexec/vpnctl-dnstt/.dnstt-server.new
mv -f /usr/local/libexec/vpnctl-dnstt/.dnstt-server.new /usr/local/libexec/vpnctl-dnstt/dnstt-server
for file in sshd_config authorized_keys noise.key server.env; do
    if [ "$file" = noise.key ]; then mode=0600; else mode=0644; fi
    install -m "$mode" "$stage/$file" "$base/$file.new"
    mv -f "$base/$file.new" "$base/$file"
done
install -m 0755 "$stage/egress-init" /usr/local/libexec/vpnctl-dnstt/egress-init
install -m 0644 "$stage/vpnctl-dnstt.service" "$stage/vpnctl-dnstt-sshd.service" /etc/systemd/system/
systemd-analyze verify "$stage/vpnctl-dnstt.service" "$stage/vpnctl-dnstt-sshd.service" 2>/dev/null
systemctl daemon-reload
systemctl enable vpnctl-dnstt-sshd.service vpnctl-dnstt.service
systemctl restart vpnctl-dnstt-sshd.service vpnctl-dnstt.service
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    ssh_pid=$(systemctl show vpnctl-dnstt-sshd.service -p MainPID --value)
    dns_pid=$(systemctl show vpnctl-dnstt.service -p MainPID --value)
    if [ "$ssh_pid" != 0 ] && [ "$dns_pid" != 0 ] &&
        ss -H -lntp sport = :22054 | grep -Fq "pid=$ssh_pid," &&
        ss -H -lnup sport = :53 | grep -Fq "pid=$dns_pid,"; then
        exit 0
    fi
    sleep 0.2
done
echo 'DNSTT services did not bind both listeners' >&2
exit 1
