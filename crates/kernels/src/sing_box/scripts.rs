pub(super) const SING_BOX_MIN_VERSION: &str = "1.13.19";
pub(super) const DEFAULT_SING_BOX_ARTIFACT: &str = "/opt/vpnctl/node-artifacts/sing-box";
pub(super) const DEFAULT_STATS_HELPER_ARTIFACT: &str =
    "/opt/vpnctl/node-artifacts/singbox-stats-helper";
pub(super) const REMOTE_SING_BOX_ARTIFACT_PREFIX: &str = "/tmp/vpnctl-sing-box";
pub(super) const REMOTE_STATS_HELPER_ARTIFACT_PREFIX: &str = "/tmp/vpnctl-singbox-stats-helper";
pub(super) static REMOTE_ARTIFACT_SEQUENCE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub(super) fn remote_artifact_paths() -> (String, String) {
    let sequence = REMOTE_ARTIFACT_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let suffix = format!("{}.{}", std::process::id(), sequence);
    (
        format!("{REMOTE_SING_BOX_ARTIFACT_PREFIX}.{suffix}"),
        format!("{REMOTE_STATS_HELPER_ARTIFACT_PREFIX}.{suffix}"),
    )
}

pub(super) fn cleanup_remote_artifacts_script(sing_box: &str, helper: &str) -> String {
    format!("rm -f {sing_box} {helper}")
}

pub(super) fn install_managed_artifacts_script(sing_box: &str, helper: &str) -> String {
    format!(
        "set -eu\nUPLOADED_SB={sing_box}\nUPLOADED_HELPER={helper}\n\
         {INSTALL_MANAGED_ARTIFACTS_SCRIPT_BODY}"
    )
}

pub(super) const INSTALL_MANAGED_ARTIFACTS_SCRIPT_BODY: &str = r#"STAGE_DIR=/usr/local/libexec/vpnctl
MANAGED_SB="$STAGE_DIR/.sing-box-stage.$$"
STATS_HELPER="$STAGE_DIR/.singbox-stats-helper-stage.$$"
LIVE_HELPER="$STAGE_DIR/singbox-stats-helper"
PREV_SB=/usr/bin/sing-box.vpnctl-prev
PREV_HELPER="$STAGE_DIR/singbox-stats-helper.prev"

# Hardened nodes mount /tmp noexec. Copy uploads onto an executable filesystem
# before invoking either artifact, and clean every staging path on early exit.
cleanup_stages() {
    rm -f "$MANAGED_SB" "$STATS_HELPER" "$UPLOADED_SB" "$UPLOADED_HELPER"
}
cleanup_on_signal() {
    trap - EXIT HUP INT TERM
    cleanup_stages
    exit 1
}
trap cleanup_stages EXIT
trap cleanup_on_signal HUP INT TERM
exec 9>/run/lock/vpnctl-singbox-install.lock
flock -w 300 9
install -d -m 0755 "$STAGE_DIR"
install -m 0755 "$UPLOADED_SB" "$MANAGED_SB"
install -m 0755 "$UPLOADED_HELPER" "$STATS_HELPER"

"$MANAGED_SB" version | grep -q 'with_v2ray_api'
"$MANAGED_SB" check -D /var/lib/sing-box -C /etc/sing-box
if [ ! -e /usr/bin/sing-box.vpnctl-stock ]; then
    cp -a /usr/bin/sing-box /usr/bin/sing-box.vpnctl-stock.new
    mv -f /usr/bin/sing-box.vpnctl-stock.new /usr/bin/sing-box.vpnctl-stock
fi
cp -a /usr/bin/sing-box "$PREV_SB.new"
mv -f "$PREV_SB.new" "$PREV_SB"
had_helper=0
if [ -e "$LIVE_HELPER" ]; then
    cp -a "$LIVE_HELPER" "$PREV_HELPER.new"
    mv -f "$PREV_HELPER.new" "$PREV_HELPER"
    had_helper=1
else
    rm -f "$PREV_HELPER" "$PREV_HELPER.new"
fi
success=0
rollback() {
    status=$?
    trap - EXIT HUP INT TERM
    set +e
    if [ "$success" -eq 0 ]; then
        restored=1
        install -m 0755 "$PREV_SB" /usr/bin/sing-box.rollback-new && \
            mv -f /usr/bin/sing-box.rollback-new /usr/bin/sing-box || restored=0
        if [ "$had_helper" -eq 1 ]; then
            install -m 0755 "$PREV_HELPER" "$LIVE_HELPER.rollback-new" && \
                mv -f "$LIVE_HELPER.rollback-new" "$LIVE_HELPER" || restored=0
        else
            rm -f "$LIVE_HELPER" || restored=0
        fi
        rm -f /usr/bin/sing-box.rollback-new "$LIVE_HELPER.rollback-new"
        if [ "$restored" -eq 1 ]; then
            systemctl restart sing-box >/dev/null 2>&1 || true
        fi
    fi
    cleanup_stages
    if [ "$success" -eq 0 ] && [ "$status" -eq 0 ]; then
        status=1
    fi
    exit "$status"
}
trap rollback EXIT HUP INT TERM

install -m 0755 "$STATS_HELPER" "$LIVE_HELPER.new"
mv -f "$LIVE_HELPER.new" "$LIVE_HELPER"
changed=0
if ! cmp -s "$MANAGED_SB" /usr/bin/sing-box; then
    install -m 0755 "$MANAGED_SB" /usr/bin/sing-box.vpnctl-new
    mv -f /usr/bin/sing-box.vpnctl-new /usr/bin/sing-box
    changed=1
fi
if [ "$changed" -eq 1 ]; then
    systemctl restart sing-box
fi
systemctl is-active --quiet sing-box
apt-mark hold sing-box >/dev/null
success=1
cleanup_stages
trap - EXIT HUP INT TERM
"#;

/// Idempotent node-setup script run by [`SingBox::ensure_installed`] on
/// EVERY deploy — both the CLI (`vpnctl deploy`) and the daemon web/SSE
/// paths call `ensure_installed` before render/apply. Installs (or
/// upgrades, when below [`SING_BOX_MIN_VERSION`]) sing-box + its APT
/// prereqs, pre-creates the sing-box-owned log file, wires logrotate,
/// and provisions the shared self-signed TLS cert/key.
///
/// Built once via `LazyLock`: only the version-gate prelude is
/// interpolated (the floor from [`SING_BOX_MIN_VERSION`]); the rest is a
/// static raw string. The composed script can be asserted directly in
/// tests (`SING_BOX_SETUP_SCRIPT.as_str()` yields `&str`).
pub(super) static SING_BOX_SETUP_SCRIPT: std::sync::LazyLock<String> = std::sync::LazyLock::new(
    || {
        // VERSION-AWARE INSTALL GATE. Install/upgrade only when sing-box package
        // state is not 'install ok installed', /usr/bin/sing-box is absent, or
        // its version is BELOW SING_BOX_MIN_VERSION; no-op at/above.
        // The node has dpkg, so `dpkg --compare-versions` does the comparison.
        // `$CUR` is quoted (it can be empty if `sing-box version` ever changes
        // its output) — an empty CUR compares LOWER than any real floor, so
        // `ge` fails and NEED=1 (reinstall), which is the safe default. The
        // `|| NEED=1` keeps the non-zero compare from tripping `set -e`.
        // `apt-get install -y sing-box` installs the repo CANDIDATE (newest in
        // the SagerNet channel), which is ≥ the floor.
        let head = format!(
            r#"
    set -eu
    export DEBIAN_FRONTEND=noninteractive
    NEED=0
    REINSTALL=0
    if [ "$(dpkg-query -W -f='${{Status}}' sing-box 2>/dev/null || true)" != "install ok installed" ]; then
        NEED=1
    elif [ ! -x /usr/bin/sing-box ]; then
        NEED=1
        REINSTALL=1
    else
        CUR=$(/usr/bin/sing-box version 2>/dev/null | awk '/version/{{print $3; exit}}')
        # Upgrade when the installed version is BELOW the declared floor.
        dpkg --compare-versions "$CUR" ge "{min}" || NEED=1
    fi
    if [ "$NEED" = 1 ]; then
        apt-mark unhold sing-box >/dev/null 2>&1 || true
        apt-get update -qq
        apt-get install -y --no-install-recommends \
            curl gpg ca-certificates
        install -d -m 0755 /usr/share/keyrings
        KEYRING_TMP="/usr/share/keyrings/sagernet.gpg.tmp.$$"
        trap 'rm -f "$KEYRING_TMP"' EXIT
        curl -fsSL https://sing-box.app/gpg.key \
            | gpg --dearmor --yes -o "$KEYRING_TMP"
        test -s "$KEYRING_TMP"
        gpg --no-default-keyring --keyring "$KEYRING_TMP" --list-keys >/dev/null 2>&1
        chmod 0644 "$KEYRING_TMP"
        mv "$KEYRING_TMP" /usr/share/keyrings/sagernet.gpg
        trap - EXIT
        echo "deb [signed-by=/usr/share/keyrings/sagernet.gpg] https://deb.sagernet.org/ * *" \
            > /etc/apt/sources.list.d/sagernet.list
        apt-get update -qq
        if [ "$REINSTALL" = 1 ]; then
            apt-get install -y --reinstall sing-box
        else
            apt-get install -y sing-box
        fi
        # Post-install floor verification on canonical /usr/bin/sing-box.
        CUR=$(/usr/bin/sing-box version 2>/dev/null | awk '/version/{{print $3; exit}}')
        dpkg --compare-versions "$CUR" ge "{min}" || {{
            echo "sing-box still <{min} after install (have '$CUR') — floor unreachable from this repo" >&2
            exit 1
        }}
    fi
"#,
            min = SING_BOX_MIN_VERSION,
        );
        format!("{head}{SING_BOX_SETUP_SCRIPT_TAIL}")
    },
);

/// Static remainder of the node-setup script (everything after the
/// version-aware install gate). Kept as a separate raw string — it
/// carries literal `{`/`}` (logrotate fragment, fail2ban heredoc
/// `${F2B_SSH_PORT}`) that must NOT pass through `format!`. UNCHANGED
/// from before the version-gate refactor.
pub(super) const SING_BOX_SETUP_SCRIPT_TAIL: &str = r#"    # Pre-create log file with sing-box ownership ONLY IF ABSENT.
    # Otherwise the service crash-loops with "open /var/log/sing-box.log:
    # permission denied" — observed live on the staging deploy.
    # CRITICAL: must be conditional. `install /dev/null <log>` replaces the
    # file's inode; re-running it on an EXISTING log orphans sing-box's open
    # fd (the live log goes 0-byte until the service restarts), silently
    # breaking the log-scrape per-user attribution. ensure_installed runs on
    # every deploy AND every `update-kernels` (which does NOT restart
    # sing-box), so an unconditional re-create = fleet-wide attribution loss.
    [ -f /var/log/sing-box.log ] || install -o sing-box -g sing-box -m 0640 /dev/null /var/log/sing-box.log
    chown -R sing-box:sing-box /etc/sing-box
    systemctl enable sing-box >/dev/null
    # Self-signed TLS cert/key shared by EVERY TLS-bearing inbound
    # (tuic-v5, hysteria2, trojan, anytls — all render
    # tls.certificate_path = /etc/sing-box/cert.pem + key.pem).
    # Provisioned HERE in the kernel so BOTH the CLI deploy and the
    # web/SSE deploy paths get it idempotently. Previously only the CLI
    # generated it, and only when tuic-v5 was enabled — so a
    # hy2/trojan/anytls-only node (or ANY web/SSE-deployed node)
    # crash-looped sing-box on the missing cert files. Self-signed +
    # clients use insecure:true, so the CN is irrelevant; the `test -f`
    # guard never rotates an existing cert out from under live clients.
    if [ ! -f /etc/sing-box/cert.pem ] || [ ! -f /etc/sing-box/key.pem ]; then
        apt-get install -y --no-install-recommends openssl
        openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
            -keyout /etc/sing-box/key.pem -out /etc/sing-box/cert.pem \
            -subj '/CN=sing-box'
    fi
    chown sing-box:sing-box /etc/sing-box/cert.pem /etc/sing-box/key.pem
    chmod 600 /etc/sing-box/key.pem
    chmod 644 /etc/sing-box/cert.pem
    # logrotate fragment for sing-box's main log file. `daily` check
    # with size-based trigger at 100 MB. `copytruncate` alone
    # (truncate-in-place) so sing-box's open file descriptor stays
    # valid (no SIGHUP needed); `create` removed because it triggers
    # the rename path that orphans sing-box's open fd (no SIGHUP
    # reopen) — the two models must not coexist. Keep 14 rotations
    # = ~14 days at most under idle load.
    # Run as root explicitly. Ubuntu permits group `syslog` to write
    # /var/log (0775), so logrotate refuses the directory unless a
    # `su` directive is present. `su sing-box sing-box` is still wrong:
    # that user cannot create the rotated copy in root-owned /var/log.
    apt-get install -y --no-install-recommends logrotate
    # Remove stale backup files that logrotate's `include /etc/logrotate.d`
    # would parse as duplicate configs (dpkg conffile backups, editor
    # turds). Our own fragment is written via `cat >` (overwrite, no
    # backup), so these can only come from external tooling.
    rm -f /etc/logrotate.d/sing-box.bak /etc/logrotate.d/sing-box.bak.* \
          /etc/logrotate.d/sing-box~ \
          /etc/logrotate.d/sing-box.dpkg-old /etc/logrotate.d/sing-box.dpkg-new \
          /etc/logrotate.d/sing-box.dpkg-dist
    cat > /etc/logrotate.d/sing-box <<'LR'
/var/log/sing-box.log {
    daily
    rotate 14
    size 100M
    missingok
    notifempty
    compress
    compressoptions -1
    copytruncate
    su root root
}
LR
    # Verify the GLOBAL include graph parses — validating only the
    # single fragment would miss duplicates hidden behind the include.
    # stderr is NOT suppressed so a parse failure surfaces in the log.
    logrotate -d /etc/logrotate.conf >/dev/null
    # Apply the repaired fragment immediately. This is a no-op below
    # 100 MiB; an oversized log is copy-truncated without restarting
    # sing-box, then the system timer keeps handling future rotations.
    logrotate /etc/logrotate.d/sing-box
    # fail2ban — SSH brute-force protection. The add-server wizard UI
    # promises it and the Phase-G health monitor alerts on
    # `server.fail2ban.down`, but NO deploy path actually installed it
    # (CLAUDE.md Known-gaps). Provisioned HERE so BOTH the CLI and the
    # web/SSE deploy harden every node idempotently. (Scope: every node
    # runs the sing-box kernel today; a kernel-independent bootstrap home
    # for host-hardening is the longer-term fix for amneziawg/caddy-only
    # nodes — same orthogonality note as the cert provisioning above.)
    #
    # Gate on BOTH fail2ban and python3-systemd: a node where fail2ban is
    # missing/half-installed or python3-systemd is missing (e.g. installed with
    # --no-install-recommends or prior to Debian 12 journald requirements) must
    # run apt-get to install/repair before fail2ban restarts with backend=systemd.
    # Package detection requires exact status 'install ok installed' for both.
    if [ "$(dpkg-query -W -f='${Status}' fail2ban 2>/dev/null || true)" != "install ok installed" ] \
        || [ "$(dpkg-query -W -f='${Status}' python3-systemd 2>/dev/null || true)" != "install ok installed" ]; then
        # `apt-get update` here too: the sing-box block above only runs it
        # when sing-box is ABSENT, so on a re-deploy (sing-box present,
        # fail2ban or python3-systemd absent) the cache could be stale → 'Unable to locate'.
        apt-get update -qq
        apt-get install -y --no-install-recommends fail2ban python3-systemd
    fi
    # Bind the ban action to the EFFECTIVE sshd listen port (a node may
    # set a custom Port via a systemd drop-in / -p, not just sshd_config).
    # `sshd -T` dumps the resolved config; fall back to parsing sshd_config,
    # then 22. Each step exits 0 on no-match (awk/head) — safe under set -e
    # without pipefail.
    SSHD_BIN=$(command -v sshd || echo /usr/sbin/sshd)
    F2B_SSH_PORT=$("$SSHD_BIN" -T 2>/dev/null | awk '$1=="port"{print $2; exit}')
    [ -n "$F2B_SSH_PORT" ] || F2B_SSH_PORT=$(grep -oiE '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config 2>/dev/null | grep -oE '[0-9]+' | head -1)
    F2B_SSH_PORT=${F2B_SSH_PORT:-22}
    # backend=systemd is REQUIRED on Debian 12+ (journald only — there's
    # no /var/log/auth.log for the default `auto` backend to tail).
    # Unquoted heredoc so ${F2B_SSH_PORT} expands.
    cat > /etc/fail2ban/jail.local <<F2B
[DEFAULT]
bantime  = 86400
findtime = 600
maxretry = 5
ignoreip = 127.0.0.1/8 ::1
backend  = systemd

[sshd]
enabled  = true
port     = ${F2B_SSH_PORT}
maxretry = 3
F2B
    systemctl enable fail2ban >/dev/null 2>&1 || true
    # `|| true` so a synchronous start failure still reaches the
    # journalctl diagnostic + fail-closed assertion below.
    systemctl restart fail2ban || true
    # Don't report success on a crash-loop (staging-deploy lesson #3).
    for i in 1 2 3 4 5; do
        state=$(systemctl is-active fail2ban || true)
        [ "$state" = "active" ] && break
        sleep 1
    done
    [ "$(systemctl is-active fail2ban)" = "active" ] \
        || { journalctl -u fail2ban -n 20 >&2; exit 1; }
    test -x /usr/bin/sing-box  # final assertion — fails the exec on regression
    command -v logrotate
    command -v fail2ban-client
"#;

pub(super) fn sing_box_apply_script() -> &'static str {
    // Атомарная замена + валидация перед перезагрузкой + ВЕРИФИКАЦИЯ
    // что сервис реально поднялся, + откат к последнему рабочему конфигу.
    // Без верификации deploy'и молча «succeed» когда sing-box crash-loop'ит
    // (живой пример: permission denied на /var/log/sing-box.log на свежей
    // ноде); без отката нода остаётся в crash-loop'е с уже стёртым
    // прошлым-рабочим конфигом.
    r#"
            set -eu
            /usr/bin/sing-box check -c /etc/sing-box/config.json.new
            # Snapshot the current live config so a runtime-failed restart
            # can roll back. Only if a live config exists (first deploy has
            # none); -a preserves owner/mode.
            if [ -f /etc/sing-box/config.json ]; then
                cp -a /etc/sing-box/config.json /etc/sing-box/config.json.bak 2>/dev/null || true
            fi
            mv /etc/sing-box/config.json.new /etc/sing-box/config.json
            chown sing-box:sing-box /etc/sing-box/config.json
            chmod 0640 /etc/sing-box/config.json
            systemctl reload-or-restart sing-box

            # Wait up to 8 seconds for the service and loopback Stats API.
            # An active service without Stats means the managed binary/helper
            # pair is incompatible and must not be accepted.
            stats_failed=0
            for i in 1 2 3 4 5 6 7 8; do
                state=$(systemctl is-active sing-box || true)
                if [ "$state" = "active" ]; then
                    if /usr/local/libexec/vpnctl/singbox-stats-helper --timeout 2s >/dev/null 2>&1; then
                        rm -f /etc/sing-box/config.json.bak
                        exit 0
                    fi
                    stats_failed=1
                fi
                sleep 1
            done

            # Failed to come up. Dump diagnostics, then ROLL BACK to the
            # snapshot so the node returns to its last-good config instead of
            # crash-looping on the new one. Each restore step is `|| true`-
            # guarded so a failing step still reaches `exit 1`.
            echo "sing-box did not become active. Last 20 log lines:" >&2
            journalctl -u sing-box --no-pager -n 20 >&2 || true
            if [ -f /etc/sing-box/config.json.bak ]; then
                echo "rolling back to previous sing-box config" >&2
                mv /etc/sing-box/config.json.bak /etc/sing-box/config.json || true
                chown sing-box:sing-box /etc/sing-box/config.json || true
                chmod 0640 /etc/sing-box/config.json || true
                systemctl reload-or-restart sing-box || true
            fi
            if [ "$stats_failed" -eq 1 ] && [ -x /usr/bin/sing-box.vpnctl-prev ]; then
                set +e
                restored=1
                install -m 0755 /usr/bin/sing-box.vpnctl-prev \
                    /usr/bin/sing-box.rollback-new && \
                    mv -f /usr/bin/sing-box.rollback-new /usr/bin/sing-box || restored=0
                if [ -x /usr/local/libexec/vpnctl/singbox-stats-helper.prev ]; then
                    install -m 0755 \
                        /usr/local/libexec/vpnctl/singbox-stats-helper.prev \
                        /usr/local/libexec/vpnctl/singbox-stats-helper.rollback-new && \
                        mv -f /usr/local/libexec/vpnctl/singbox-stats-helper.rollback-new \
                            /usr/local/libexec/vpnctl/singbox-stats-helper || restored=0
                else
                    rm -f /usr/local/libexec/vpnctl/singbox-stats-helper || restored=0
                fi
                rm -f /usr/bin/sing-box.rollback-new \
                    /usr/local/libexec/vpnctl/singbox-stats-helper.rollback-new
                if [ "$restored" -eq 1 ]; then
                    systemctl restart sing-box || true
                fi
            fi
            exit 1
        "#
}

/// Build the idempotent, ufw-guarded shell snippet that opens every
/// `(transport, port)` in `ports` (deduplicated; sorted for stable output).
/// Returns `None` when `ports` is empty. Mirrors the Caddy kernel's
/// best-effort posture: the `command -v ufw` guard makes it a clean no-op on
/// hosts with no ufw (e.g. DigitalOcean droplets, where an upstream Cloud
/// Firewall — not local ufw — governs ingress), `ufw allow` is idempotent
/// (skips an existing rule) and opens both IPv4 + IPv6. `port` is `u16` and
/// `transport` is a `"tcp"`/`"udp"` `&'static str` from the protocol's
/// `effective_listen_ports()`, so the interpolation carries no injection
/// surface.
pub(super) fn firewall_open_script(ports: &[(&str, u16)]) -> Option<String> {
    let uniq: std::collections::BTreeSet<(&str, u16)> = ports.iter().copied().collect();
    if uniq.is_empty() {
        return None;
    }
    let mut s = String::from("if command -v ufw >/dev/null 2>&1; then\n");
    for (transport, port) in &uniq {
        s.push_str(&format!(
            "  ufw allow {port}/{transport} >/dev/null 2>&1 || true\n"
        ));
    }
    s.push_str("fi\n");
    Some(s)
}
