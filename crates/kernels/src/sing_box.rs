use async_trait::async_trait;
use serde_json::json;
use vpnctl_core::{
    CoreError, Kernel, KernelId, KernelStatus, Protocol, ProtocolId, RenderCtx, Result,
    SshTransport, User,
};

/// sing-box 1.13.x из официального APT-репо SagerNet.
///
/// **Optional features that need a newer sing-box than what's in the
/// SagerNet stable APT channel:**
///
/// | Feature | Required | Activation |
/// |---|---|---|
/// | `experimental.clash_api` block | sing-box ≥ 1.10 | always rendered (Track-3 prep) |
/// | Hysteria2 `realm` (NAT-traversal via rendezvous + STUN) | sing-box ≥ 1.14 | only when `hysteria2.realm.server_url` is set in `RenderCtx::secrets` |
///
/// On a stale node (1.13.x without the rendered key support), the
/// `sing-box check -c …` step in `apply_config` rejects the config
/// before `mv` swaps it in — so the deploy fails loud rather than
/// silently dropping the directive. To unlock 1.14+, switch the APT
/// repo from `*/*` to a channel that ships 1.14, or pull a release
/// `.deb` from sing-box GitHub releases.
#[derive(Debug, Default)]
pub struct SingBox;

impl SingBox {
    pub fn new() -> Self {
        Self
    }
}

/// Declared MINIMUM sing-box version the rendered config requires. The
/// node-setup script installs/upgrades sing-box when it is ABSENT or
/// BELOW this floor, and no-ops when at/above it. Bump this one line to
/// require a newer sing-box; the next `vpnctl deploy` of each node
/// converges the fleet upward (the SagerNet apt CANDIDATE — newest in
/// the channel — satisfies the floor, so de/is on 1.13.7 get pulled to
/// 1.13.12+).
///
/// History: before the version gate the install was gated purely on
/// PRESENCE (`if ! command -v sing-box`), so once ANY sing-box was on
/// PATH `deploy` never upgraded it — the fleet drifted (de/is 1.13.7 vs
/// cdn/nl 1.13.12). Same class as the caddy / dns-tunnel cache-binary
/// presence gates. The floor is a MINIMUM, not an exact pin — we don't
/// attempt exact-version apt pinning (SagerNet version strings are
/// brittle), the repo candidate (≥ floor) is acceptable.
const SING_BOX_MIN_VERSION: &str = "1.13.12";

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
static SING_BOX_SETUP_SCRIPT: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    // VERSION-AWARE INSTALL GATE. Install/upgrade only when sing-box is
    // ABSENT or its version is BELOW SING_BOX_MIN_VERSION; no-op at/above.
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
    if ! command -v sing-box >/dev/null 2>&1; then
        NEED=1
    else
        CUR=$(sing-box version 2>/dev/null | awk '/version/{{print $3; exit}}')
        # Upgrade when the installed version is BELOW the declared floor.
        dpkg --compare-versions "$CUR" ge "{min}" || NEED=1
    fi
    if [ "$NEED" = 1 ]; then
        apt-get update -qq
        apt-get install -y --no-install-recommends \
            curl gpg ca-certificates
        install -d -m 0755 /usr/share/keyrings
        curl -fsSL https://sing-box.app/gpg.key \
            | gpg --dearmor -o /usr/share/keyrings/sagernet.gpg
        echo "deb [signed-by=/usr/share/keyrings/sagernet.gpg] https://deb.sagernet.org/ * *" \
            > /etc/apt/sources.list.d/sagernet.list
        apt-get update -qq
        apt-get install -y sing-box
        # Post-install floor verification. `CUR` above is read from the
        # RUNNING binary on PATH, which the apt install may NOT have
        # changed: (a) a manually-installed /usr/local/bin/sing-box ahead
        # of /usr/bin on PATH shadows the apt binary — PATH still resolves
        # the stale one, so the gate stays unsatisfied and EVERY deploy
        # re-runs apt forever (never converges); (b) MIN bumped past the
        # SagerNet channel candidate — apt installs an older-than-MIN
        # version and the deploy would otherwise report success while the
        # floor is unreachable. Re-read the version that PATH now resolves
        # and abort LOUD if it's STILL below MIN — a clear abort beats
        # silent churn / shadow-install. (set -eu is active; the explicit
        # `|| {{ … exit 1; }}` keeps the failing compare from being a bare
        # non-zero that trips set -e before we print the diagnostic.)
        CUR=$(sing-box version 2>/dev/null | awk '/version/{{print $3; exit}}')
        dpkg --compare-versions "$CUR" ge "{min}" || {{
            echo "sing-box still <{min} after install (have '$CUR') — floor unreachable from this repo, or a non-apt binary shadows PATH at $(command -v sing-box)" >&2
            exit 1
        }}
    fi
"#,
        min = SING_BOX_MIN_VERSION,
    );
    format!("{head}{SING_BOX_SETUP_SCRIPT_TAIL}")
});

/// Static remainder of the node-setup script (everything after the
/// version-aware install gate). Kept as a separate raw string — it
/// carries literal `{`/`}` (logrotate fragment, fail2ban heredoc
/// `${F2B_SSH_PORT}`) that must NOT pass through `format!`. UNCHANGED
/// from before the version-gate refactor.
const SING_BOX_SETUP_SCRIPT_TAIL: &str = r#"    # Pre-create log file with sing-box ownership ONLY IF ABSENT.
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
    # NO `su sing-box sing-box`: with copytruncate logrotate must
    # create the rotated copy in root-owned /var/log — running as
    # the sing-box user fails with EACCES. Root can read the
    # sing-box-owned log and truncate it without issue.
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
    delaycompress
    copytruncate
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
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        # `apt-get update` here too: the sing-box block above only runs it
        # when sing-box is ABSENT, so on a re-deploy (sing-box present,
        # fail2ban absent) the cache could be stale → 'Unable to locate'.
        apt-get update -qq
        apt-get install -y --no-install-recommends fail2ban
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
    command -v sing-box  # final assertion — fails the exec on regression
    command -v logrotate
    command -v fail2ban-client
"#;

#[async_trait]
impl Kernel for SingBox {
    fn id(&self) -> KernelId {
        KernelId("sing-box".to_string())
    }

    fn supported_protocols(&self) -> Vec<ProtocolId> {
        vec![
            ProtocolId("vless+reality".to_string()),
            ProtocolId("tuic-v5".to_string()),
            ProtocolId("hysteria2".to_string()),
            ProtocolId("shadowsocks-2022".to_string()),
            // AnyTLS — sing-box ≥ 1.12. ensure_installed pulls the
            // SagerNet stable channel which currently ships 1.13.x;
            // on a stale-version node `sing-box check` would reject
            // an `anytls` inbound and apply_config fails loud.
            ProtocolId("anytls".to_string()),
            // Trojan — in sing-box since v0.1, no version concern.
            ProtocolId("trojan".to_string()),
        ]
    }

    async fn ensure_installed(&self, ssh: &dyn SshTransport) -> Result<()> {
        // Idempotent node setup — see [`SING_BOX_SETUP_SCRIPT`] for the
        // full rationale (sing-box install on minimal Debian, log-file
        // ownership, logrotate, and the shared self-signed TLS cert that
        // tuic/hy2/trojan/anytls all need). Runs in BOTH the CLI and the
        // web/SSE deploy paths.
        ssh.exec(SING_BOX_SETUP_SCRIPT.as_str()).await?;
        Ok(())
    }

    fn render_config(
        &self,
        ctx: &RenderCtx<'_>,
        users: &[User],
        protocols: &[&dyn Protocol],
    ) -> Result<Vec<u8>> {
        let mut inbounds = Vec::with_capacity(protocols.len());
        for p in protocols {
            inbounds.push(p.server_inbound(ctx, users)?);
        }
        let cfg = json!({
            "log": { "level": "info", "output": "/var/log/sing-box.log", "timestamp": true },
            "inbounds": inbounds,
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "block", "tag": "block" }
            ],
            // Phase Track-3 prep: clash-api on loopback so the daemon
            // can poll active connections + traffic counters in a
            // future iteration. Bound to 127.0.0.1 (no external
            // exposure); no secret needed because nothing on the node
            // is allowed to bind 9090 except sing-box itself.
            //
            // No `external_ui` set — we don't need a clash dashboard.
            // The future poller talks the JSON API directly.
            //
            // sing-box ≥ 1.10 accepts this top-level key; on older
            // builds the `sing-box check` step would reject the
            // config, so the deploy fails loudly on a stale node.
            "experimental": {
                "clash_api": {
                    "external_controller": "127.0.0.1:9090"
                }
            }
        });
        serde_json::to_vec_pretty(&cfg).map_err(CoreError::from)
    }

    async fn apply_config(&self, ssh: &dyn SshTransport, config: &[u8]) -> Result<()> {
        // ── PRE-APPLY DIFF GUARD (post-2026-05-19 incident) ───────
        //
        // Compare the LIVE /etc/sing-box/config.json with the new
        // rendered one. If the new config REMOVES any user UUID
        // from inbounds[*].users[*] AND the operator has not
        // explicitly set VPNCTLD_ALLOW_USER_REMOVAL=1, REFUSE the
        // deploy with the lost UUIDs spelled out.
        //
        // Why this exists: 2026-05-18 deploy on vps-de-01 silently
        // dropped UUID `b25684c3-…` (the claude-chat-proxy service
        // user that wasn't in vpnctld's inventory). Result: every
        // outbound HTTPS request from .142 containers — including
        // the entire claude-chat → api.anthropic.com path —
        // started failing tcpdump-silent at Reality handshake.
        // Pavel had to manually patch the live config back.
        //
        // The fix: vpnctld now reads the existing config before
        // rewriting it. If reconciling inventory → live would lose
        // any UUID, the operator sees a precise list with the
        // remediation paths (add to inventory OR override).
        //
        // Guard runs ONLY when the file already exists (fresh-node
        // first deploy has nothing to lose). Parse failures on
        // the OLD config are non-fatal — we log + proceed (the
        // file might be hand-edited into a non-standard shape;
        // refusing forever would itself be a footgun).
        if let Ok(old_bytes) = ssh.read_file("/etc/sing-box/config.json").await {
            match user_uuid_diff(&old_bytes, config) {
                Ok(removed) if !removed.is_empty() => {
                    let allow = std::env::var("VPNCTLD_ALLOW_USER_REMOVAL")
                        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                        .unwrap_or(false);
                    if !allow {
                        let preview: Vec<&String> = removed.iter().take(5).collect();
                        return Err(CoreError::Render(format!(
                            "sing-box apply_config: refusing to deploy a config that would \
                             REMOVE {} user UUID(s) from inbounds[*].users[]: {:?}{}. \
                             These users exist on the LIVE server but are missing from vpnctld's \
                             inventory. Either:\n  \
                             1. Add the missing user(s) to inventory (admin UI → Add user with \
                                the SAME UUID, then grant on this server), OR\n  \
                             2. Set VPNCTLD_ALLOW_USER_REMOVAL=1 in /etc/vpnctl/vpnctld.env and \
                                restart vpnctld to bypass this gate for this deploy cycle.",
                            removed.len(),
                            preview,
                            if removed.len() > preview.len() {
                                format!(" (+{} more)", removed.len() - preview.len())
                            } else {
                                String::new()
                            },
                        )));
                    }
                }
                Ok(_) => { /* no removals, proceed */ }
                Err(e) => {
                    // Defensive — old config is hand-edited / malformed.
                    // We don't fail closed here because that'd brick
                    // deploys forever on any node with a non-standard
                    // /etc/sing-box/config.json. Operator's signal is
                    // this stderr warn that journald captures into
                    // `journalctl -u vpnctld`. (Can't use `tracing!`
                    // — the kernels crate intentionally has zero
                    // logging deps; daemon-side logging happens at
                    // the handler layer.)
                    eprintln!(
                        "WARN vpnctl::kernels::sing_box: pre-apply diff guard could not \
                         parse old /etc/sing-box/config.json ({e}); skipping guard \
                         (deploy proceeds)"
                    );
                }
            }
        }

        ssh.upload("/etc/sing-box/config.json.new", config).await?;
        ssh.exec(sing_box_apply_script()).await?;
        Ok(())
    }

    async fn open_firewall(
        &self,
        ssh: &dyn SshTransport,
        protocols: &[&dyn Protocol],
    ) -> Result<()> {
        // Source of truth = each `Protocol::listen_ports()` (the SAME data
        // the cross-protocol port-conflict guard reads), so the firewall
        // opens EXACTLY what sing-box binds — never a stale hardcoded list,
        // and it grows automatically when a new protocol is enabled.
        let ports: Vec<(&str, u16)> = protocols
            .iter()
            .flat_map(|p| p.listen_ports().iter().copied())
            .collect();
        if let Some(script) = firewall_open_script(&ports) {
            ssh.exec(&script).await?;
        }
        Ok(())
    }

    async fn restart(&self, ssh: &dyn SshTransport) -> Result<()> {
        ssh.exec("systemctl restart sing-box").await?;
        Ok(())
    }

    async fn status(&self, ssh: &dyn SshTransport) -> Result<KernelStatus> {
        let active = ssh
            .exec("systemctl is-active sing-box")
            .await?
            .trim()
            .eq("active");
        let version = ssh.exec("sing-box version 2>&1 | head -1").await.ok();
        Ok(KernelStatus {
            active,
            version,
            uptime_seconds: None,
        })
    }
}

/// The atomic-swap + verify + ROLLBACK script run after the new sing-box
/// config has been uploaded to `…/config.json.new`.
///
/// `sing-box check` only validates STATIC syntax — it can't see runtime
/// failures (a log-file the service-user can't open — the live precedent
/// quoted above; a port a co-tenant already bound; a missing cert path).
/// So a config that passes `check` can still crash-loop the service. The
/// previous version `mv`'d `.new → config.json` and, on a failed restart,
/// left the node WORSE than before: the last-good config already gone,
/// nothing to roll back to.
///
/// This script snapshots the live config to `config.json.bak` BEFORE the
/// swap (only if a live config exists — a fresh node's first deploy has
/// none), and on the is-active-failed branch restores the `.bak` and
/// reload-or-restarts so the node returns to its last-good config instead
/// of crash-looping. The `.bak` is removed on success.
///
/// Shell-correctness note on `set -e`: the failure branch is reached by
/// FALLING THROUGH the poll loop (each `is-active` is `|| true`, so a
/// failing probe never trips `set -e`), NOT by `set -e` aborting — so the
/// restore block below the loop always runs. Inside the restore block,
/// `[ -f … ]`, the restore `mv`, and `reload-or-restart` are individually
/// `|| true`-guarded so one failing step can't short-circuit the rest
/// before the final `exit 1`.
fn sing_box_apply_script() -> &'static str {
    // Атомарная замена + валидация перед перезагрузкой + ВЕРИФИКАЦИЯ
    // что сервис реально поднялся, + откат к последнему рабочему конфигу.
    // Без верификации deploy'и молча «succeed» когда sing-box crash-loop'ит
    // (живой пример: permission denied на /var/log/sing-box.log на свежей
    // ноде); без отката нода остаётся в crash-loop'е с уже стёртым
    // прошлым-рабочим конфигом.
    r#"
            set -eu
            sing-box check -c /etc/sing-box/config.json.new
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

            # Wait up to 8 seconds for the service to settle. systemd's
            # auto-restart back-off kicks in every 10s, so 8s is past the
            # first attempt — if we're not "active" by then, we're in a
            # crash loop.
            for i in 1 2 3 4 5 6 7 8; do
                state=$(systemctl is-active sing-box || true)
                if [ "$state" = "active" ]; then
                    rm -f /etc/sing-box/config.json.bak
                    exit 0
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
/// `transport` is a compile-time `"tcp"`/`"udp"` literal from
/// `listen_ports()`, so the interpolation carries no injection surface.
fn firewall_open_script(ports: &[(&str, u16)]) -> Option<String> {
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

/// Read helper: the set of user UUIDs declared in a *live* sing-box
/// config, returned in sorted order (`BTreeSet`) for a deterministic
/// caller-side diff render.
///
/// Used by the daemon's drift-detail card to compare the UUIDs the node
/// is actually serving against the UUIDs inventory expects, so the
/// operator can see *which* user accounts drifted, not just that a
/// count differs. Parse failures (truncated SSH read, non-JSON blob)
/// collapse to an empty set rather than an error — the card degrades to
/// "no on-node users observed" instead of failing the whole page.
///
/// This is a pure read over already-parsed bytes: it adds no new
/// kernel/protocol coupling, it just re-exposes the same extraction the
/// pre-apply diff guard already does internally.
pub fn live_config_user_uuids(config_bytes: &[u8]) -> std::collections::BTreeSet<String> {
    extract_user_uuids(config_bytes)
        .map(|set| set.into_iter().collect())
        .unwrap_or_default()
}

/// Extract every `uuid` value found in `inbounds[*].users[*]` of a
/// sing-box JSON config. Tolerant of non-VLESS inbounds (which don't
/// carry a `users` array) and of inbounds whose users use a different
/// auth shape — only entries with a real `"uuid"` string key are
/// returned. Used by the pre-apply diff guard.
fn extract_user_uuids(config_bytes: &[u8]) -> Result<std::collections::HashSet<String>> {
    let v: serde_json::Value = serde_json::from_slice(config_bytes).map_err(CoreError::from)?;
    let mut out = std::collections::HashSet::new();
    let Some(inbounds) = v.get("inbounds").and_then(|x| x.as_array()) else {
        return Ok(out);
    };
    for inbound in inbounds {
        let Some(users) = inbound.get("users").and_then(|x| x.as_array()) else {
            continue;
        };
        for u in users {
            if let Some(uuid) = u.get("uuid").and_then(|x| x.as_str()) {
                out.insert(uuid.to_string());
            }
        }
    }
    Ok(out)
}

/// Compute the set of user UUIDs that are present in the OLD config
/// but absent from the NEW config — i.e. would be REMOVED if we
/// proceeded with the apply. Empty result = safe to proceed.
fn user_uuid_diff(old: &[u8], new: &[u8]) -> Result<std::collections::HashSet<String>> {
    let old_uuids = extract_user_uuids(old)?;
    let new_uuids = extract_user_uuids(new)?;
    Ok(old_uuids.difference(&new_uuids).cloned().collect())
}

/// Reserved-ports pre-apply guard (post-2026-05-26, Pavel:
/// «важно конкретно для этого сервера заблокировать часть
/// функционала, чтоб через админку нельзя было что-то перетереть»).
///
/// Returns `Err` with the offending port(s) if `config_bytes` (a
/// rendered sing-box JSON) declares any `inbounds[].listen_port`
/// that intersects `reserved`. Empty `reserved` is a no-op — most
/// servers in the fleet stay byte-equivalent to pre-0028.
///
/// The fence is **fail-CLOSED**: parse failures of `config_bytes`
/// also return Err. This is the opposite policy from
/// `user_uuid_diff` — there we fail-OPEN because the OLD config
/// might be hand-edited; here the NEW config is what *we* render,
/// so a parse failure means our own renderer produced malformed
/// JSON and the safest move is to refuse to upload it.
///
/// Called from every `apply_config` site (CLI deploy, daemon
/// deploy, wizard bootstrap). The trait signature itself is not
/// changed — the validator is a free function so kernels other
/// than sing-box don't have to opt in.
pub fn validate_config_excludes_ports(config_bytes: &[u8], reserved: &[u16]) -> Result<()> {
    if reserved.is_empty() {
        return Ok(());
    }
    let parsed: serde_json::Value = serde_json::from_slice(config_bytes).map_err(|e| {
        CoreError::Render(format!(
            "sing-box config: reserved-ports guard could not parse rendered JSON ({e}); \
             refusing to apply"
        ))
    })?;
    let Some(inbounds) = parsed.get("inbounds").and_then(|v| v.as_array()) else {
        // No inbounds[] at all — vacuously safe (the renderer may
        // produce a config with only outbounds for some future
        // route-only role). Don't false-flag.
        return Ok(());
    };
    let reserved_set: std::collections::HashSet<u16> = reserved.iter().copied().collect();
    let mut collisions: Vec<u16> = Vec::new();
    for inbound in inbounds {
        let Some(port_value) = inbound.get("listen_port") else {
            continue;
        };
        let Some(port_u64) = port_value.as_u64() else {
            continue;
        };
        let Ok(port) = u16::try_from(port_u64) else {
            continue;
        };
        if reserved_set.contains(&port) {
            collisions.push(port);
        }
    }
    if collisions.is_empty() {
        return Ok(());
    }
    collisions.sort_unstable();
    collisions.dedup();
    Err(CoreError::Render(format!(
        "sing-box config: refusing to apply — rendered inbounds[] bind reserved port(s) {:?} \
         on this server (full reserved list: {:?}). These ports are protected by the operator \
         (typically a co-tenant service like a legacy 3x-ui panel on :443). Reconfigure the \
         offending protocol to a non-reserved port via /admin/servers/<id> → Enabled protocols, \
         or drop the reservation via the Reserved-ports section if you truly want to overwrite \
         the co-tenant.",
        collisions, reserved
    )))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::collections::HashMap;
    use vpnctl_core::{Server, ServerId};

    fn dummy_ctx<'a>(server: &'a Server, secrets: &'a HashMap<String, String>) -> RenderCtx<'a> {
        RenderCtx::new(server, secrets)
    }

    fn dummy_server() -> Server {
        Server {
            id: ServerId("srv".into()),
            address: "10.0.0.1".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    /// Track-3 prep: render_config must include the
    /// `experimental.clash_api.external_controller` block bound to
    /// loopback so a future daemon-side poller can talk to sing-box's
    /// JSON API for active connections + traffic counters.
    #[test]
    fn render_config_includes_clash_api_on_loopback() {
        let s = dummy_server();
        let secrets = HashMap::new();
        let ctx = dummy_ctx(&s, &secrets);
        let bytes = SingBox::new().render_config(&ctx, &[], &[]).unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            v["experimental"]["clash_api"]["external_controller"],
            Value::String("127.0.0.1:9090".into()),
            "clash_api must bind to 127.0.0.1:9090 (loopback only — no external exposure)"
        );
    }

    /// `ensure_installed` must provision the shared self-signed TLS cert
    /// that every TLS-bearing inbound (tuic-v5, hysteria2, trojan, anytls)
    /// references at `/etc/sing-box/{cert,key}.pem`. It runs in BOTH the
    /// CLI and web/SSE deploy paths, so doing it here closes the gap where
    /// a hy2/trojan/anytls-only node (or any web-deployed node) crash-
    /// looped sing-box on the missing files.
    #[test]
    fn setup_script_provisions_shared_tls_cert() {
        let s = SING_BOX_SETUP_SCRIPT.as_str();
        assert!(s.contains("/etc/sing-box/cert.pem"), "cert path missing");
        assert!(s.contains("/etc/sing-box/key.pem"), "key path missing");
        assert!(
            s.contains("openssl req -x509"),
            "self-signed cert generation missing"
        );
        // Idempotent: never regenerate (→ never rotate a live cert out).
        assert!(
            s.contains("[ ! -f /etc/sing-box/cert.pem ]"),
            "cert generation must be guarded on absence (idempotent)"
        );
        assert!(
            s.contains("chmod 600 /etc/sing-box/key.pem"),
            "private key must be mode 0600"
        );
    }

    #[test]
    fn setup_script_installs_and_configures_fail2ban() {
        let s = SING_BOX_SETUP_SCRIPT.as_str();
        assert!(
            s.contains("--no-install-recommends fail2ban"),
            "fail2ban package install missing"
        );
        assert!(
            s.contains("/etc/fail2ban/jail.local"),
            "jail.local provisioning missing"
        );
        // Debian 12+ ships journald only (no /var/log/auth.log) — the
        // default `auto` backend would silently never ban. systemd
        // backend is mandatory.
        assert!(
            s.contains("backend  = systemd"),
            "fail2ban must use the systemd backend on Debian 12+"
        );
        assert!(s.contains("[sshd]"), "sshd jail missing");
        assert!(s.contains("enabled  = true"), "sshd jail must be enabled");
        // Pin the jail PORT LINE itself (a nearby comment also carries the
        // bareword `${F2B_SSH_PORT}`, so assert the full line — deleting it
        // must fail the test).
        assert!(
            s.contains("port     = ${F2B_SSH_PORT}"),
            "jail must bind the detected sshd port"
        );
        // The crash-loop guard must not be silently dropped.
        assert!(
            s.contains("systemctl is-active fail2ban") && s.contains("exit 1"),
            "must fail the deploy on a fail2ban crash-loop"
        );
        assert!(
            s.contains("command -v fail2ban-client"),
            "final assertion must verify fail2ban-client present"
        );
    }

    #[test]
    fn firewall_open_script_opens_each_port_idempotently_guarded() {
        // vless tcp/443 + tuic udp/8443 + hysteria2 udp/8444, with a dup to
        // prove de-duplication.
        let script =
            firewall_open_script(&[("tcp", 443), ("udp", 8443), ("udp", 8444), ("udp", 8444)])
                .expect("non-empty ports yield a script");
        // ufw-guarded → clean no-op on a host with no ufw (cloud-firewall).
        assert!(
            script.contains("command -v ufw"),
            "must guard on ufw presence: {script}"
        );
        for line in [
            "ufw allow 443/tcp",
            "ufw allow 8443/udp",
            "ufw allow 8444/udp",
        ] {
            assert!(script.contains(line), "missing `{line}` in: {script}");
        }
        // De-dup: 8444/udp appears exactly once despite being passed twice.
        assert_eq!(
            script.matches("ufw allow 8444/udp").count(),
            1,
            "duplicate ports must collapse: {script}"
        );
        // Idempotent + non-fatal on an already-present rule.
        assert!(
            script.contains("|| true"),
            "must not fail on an existing rule: {script}"
        );
    }

    #[test]
    fn firewall_open_script_empty_ports_is_none() {
        assert!(
            firewall_open_script(&[]).is_none(),
            "no declared ports => no firewall step"
        );
    }

    /// The setup script keeps doing its prior jobs (sing-box install +
    /// log-file ownership + logrotate) — the cert addition must not have
    /// dropped any of them.
    #[test]
    fn setup_script_retains_install_log_and_logrotate_steps() {
        let s = SING_BOX_SETUP_SCRIPT.as_str();
        assert!(
            s.contains("apt-get install -y sing-box"),
            "sing-box install"
        );
        assert!(
            s.contains("install -o sing-box -g sing-box -m 0640 /dev/null /var/log/sing-box.log"),
            "log-file pre-create"
        );
        assert!(
            s.contains("[ -f /var/log/sing-box.log ] || install -o sing-box -g sing-box -m 0640 /dev/null /var/log/sing-box.log"),
            "log-file pre-create MUST be conditional (only-if-absent) — an unconditional `install /dev/null` re-create orphans sing-box's open log fd on every ensure_installed/update-kernels, breaking attribution"
        );
        assert!(
            s.contains("/etc/logrotate.d/sing-box"),
            "logrotate fragment"
        );
        assert!(s.contains("set -eu"), "fail-fast shell flags");
    }

    /// The sing-box install must be gated on a MINIMUM VERSION, not on
    /// bare presence. Before this gate, `if ! command -v sing-box` wrapped
    /// the apt install directly, so once ANY sing-box was on PATH `deploy`
    /// never upgraded it (fleet skew: de/is 1.13.7 vs cdn/nl 1.13.12).
    /// Companion to `setup_script_retains_install_log_and_logrotate_steps`.
    #[test]
    fn sing_box_setup_script_gates_install_on_min_version() {
        let s = SING_BOX_SETUP_SCRIPT.as_str();
        // The version comparison is present and uses the node's dpkg.
        assert!(
            s.contains("dpkg --compare-versions"),
            "install must be gated on a dpkg version comparison, not bare presence: {s}"
        );
        // The declared floor is injected literally (no hard-coded copy).
        assert!(
            s.contains(SING_BOX_MIN_VERSION),
            "the SING_BOX_MIN_VERSION floor ({SING_BOX_MIN_VERSION}) must appear in the rendered script: {s}"
        );
        // …and it is the right-hand side of the `ge` comparison.
        assert!(
            s.contains(&format!("ge \"{SING_BOX_MIN_VERSION}\"")),
            "the floor must be the `ge` operand of the version compare: {s}"
        );
        // The bare-presence-only gate is GONE: the old wording wrapped the
        // apt install directly in `if ! command -v sing-box …; then`. Its
        // absence proves the apt path is no longer skipped whenever any
        // sing-box is on PATH.
        assert!(
            !s.contains("if ! command -v sing-box >/dev/null; then"),
            "the bare-presence-only install gate must be gone: {s}"
        );
        // The apt install is now reached via the version-aware NEED gate.
        assert!(
            s.contains(r#"if [ "$NEED" = 1 ]; then"#),
            "apt install must be reached via the version-aware NEED gate: {s}"
        );
        // The SagerNet repo/key setup and the final assertion are retained.
        assert!(
            s.contains("https://sing-box.app/gpg.key")
                && s.contains("deb.sagernet.org")
                && s.contains("apt-get install -y sing-box"),
            "SagerNet repo setup + apt install must be retained inside the gate: {s}"
        );
        assert!(
            s.contains("command -v sing-box  # final assertion"),
            "the final `command -v sing-box` assertion must remain: {s}"
        );
    }

    /// After the apt install, the script must RE-VERIFY that the version
    /// PATH now resolves actually satisfies the floor — otherwise two
    /// silent failure modes survive: (a) a non-apt /usr/local/bin/sing-box
    /// shadowing PATH keeps `CUR < MIN` forever → apt re-runs EVERY deploy
    /// and never converges; (b) MIN bumped past the SagerNet candidate →
    /// apt installs an older-than-MIN version and the deploy reports
    /// success while the floor is unreachable. The fix re-reads the
    /// version and aborts loud (`exit 1`) when it's still below MIN.
    /// Companion to `sing_box_setup_script_gates_install_on_min_version`.
    #[test]
    fn sing_box_setup_script_verifies_floor_after_install() {
        let s = SING_BOX_SETUP_SCRIPT.as_str();
        // The post-install re-check is a SECOND `dpkg --compare-versions`
        // (the gate has one before apt; verification adds one after).
        assert!(
            s.matches("dpkg --compare-versions").count() >= 2,
            "must re-compare the installed version against the floor AFTER apt install: {s}"
        );
        // The re-check uses the same `ge MIN` floor operand.
        assert!(
            s.matches(&format!("ge \"{SING_BOX_MIN_VERSION}\"")).count() >= 2,
            "the post-install re-check must compare against the same floor: {s}"
        );
        // The re-check lives AFTER the apt install line (verification, not
        // the pre-install gate) and aborts loud on a miss.
        let apt_at = s
            .find("apt-get install -y sing-box")
            .expect("apt install of sing-box must be present");
        let tail = &s[apt_at..];
        assert!(
            tail.contains("dpkg --compare-versions"),
            "the floor re-check must come AFTER the apt install: {s}"
        );
        assert!(
            tail.contains("exit 1"),
            "a failed post-install floor check must abort the deploy with exit 1: {s}"
        );
        // The diagnostic names the unreachable-floor + shadowed-PATH causes
        // and points at the resolved binary path.
        assert!(
            s.contains("floor unreachable") && s.contains("command -v sing-box)"),
            "the abort diagnostic must explain the floor-unreachable / shadowed-PATH causes: {s}"
        );
    }

    /// The rendered logrotate fragment must use `copytruncate`
    /// (truncate-in-place keeps sing-box's open fd valid) and MUST
    /// NOT carry a `create` directive — `create` triggers the
    /// rename+create path that orphans sing-box's fd (sing-box never
    /// reopens its log on SIGHUP), which silently zeroes the live log
    /// and breaks per-user attribution.
    #[test]
    fn logrotate_fragment_uses_copytruncate_without_create() {
        // Isolate the `/etc/logrotate.d/sing-box` heredoc body so the
        // assertion is scoped to the fragment, not unrelated `create`
        // mentions elsewhere in the setup script (e.g. the "Pre-create
        // log file" comment).
        let s = SING_BOX_SETUP_SCRIPT.as_str();
        let start = s
            .find("/var/log/sing-box.log {")
            .expect("logrotate heredoc opening brace not found");
        let fragment = &s[start..];
        let end = fragment
            .find('}')
            .expect("logrotate heredoc closing brace not found");
        let fragment = &fragment[..end];
        assert!(
            fragment.contains("copytruncate"),
            "logrotate fragment must use copytruncate: {fragment}"
        );
        assert!(
            !fragment.contains("create "),
            "logrotate fragment must NOT carry a `create` directive (orphans sing-box's fd): {fragment}"
        );
    }

    /// The logrotate fragment must NOT carry `su sing-box sing-box`:
    /// with `copytruncate`, logrotate creates the rotated copy in
    /// root-owned `/var/log` — running as the unprivileged sing-box
    /// user fails with EACCES on every node. Root can read the
    /// sing-box-owned log and truncate it without issue.
    ///
    /// Additionally: the validation step must NOT suppress stderr
    /// (a parse failure must surface in the deploy log), and stale
    /// backup files must be cleaned from `/etc/logrotate.d/` so
    /// logrotate's `include` doesn't parse them as duplicate configs.
    #[test]
    fn logrotate_fragment_no_su_and_visible_errors() {
        let s = SING_BOX_SETUP_SCRIPT.as_str();
        // Isolate the heredoc body.
        let start = s
            .find("/var/log/sing-box.log {")
            .expect("logrotate heredoc opening brace not found");
        let fragment = &s[start..];
        let end = fragment
            .find('}')
            .expect("logrotate heredoc closing brace not found");
        let fragment = &fragment[..end];
        assert!(
            !fragment.contains("su "),
            "logrotate fragment must NOT carry `su` (root runs copytruncate): {fragment}"
        );
        // Validation targets the GLOBAL include graph, not just the
        // single fragment, so duplicates cannot remain hidden.
        assert!(
            s.contains("logrotate -d /etc/logrotate.conf >/dev/null\n"),
            "must validate the global logrotate.conf include graph: {s}"
        );
        assert!(
            s.contains("logrotate /etc/logrotate.d/sing-box\n"),
            "deploy must immediately rotate an already-oversized log: {s}"
        );
        assert!(
            !s.contains("logrotate -d /etc/logrotate.conf >/dev/null 2>&1"),
            "validation must NOT suppress stderr: {s}"
        );
        // Stale backup cleanup — exact .bak AND the dateext family.
        assert!(
            s.contains("rm -f /etc/logrotate.d/sing-box.bak"),
            "must clean stale .bak backups from the parsed logrotate dir: {s}"
        );
        assert!(
            s.contains("sing-box.bak.*"),
            "must clean dateext-style sing-box.bak.<date> duplicates: {s}"
        );
        assert!(
            s.contains("sing-box.dpkg-old"),
            "must clean dpkg conffile backups: {s}"
        );
    }

    /// Pre-existing keys (log, inbounds, outbounds) must still render
    /// — adding `experimental` shouldn't accidentally drop them.
    #[test]
    fn render_config_keeps_existing_top_level_keys() {
        let s = dummy_server();
        let secrets = HashMap::new();
        let ctx = dummy_ctx(&s, &secrets);
        let bytes = SingBox::new().render_config(&ctx, &[], &[]).unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v["log"].is_object(), "log block missing");
        assert!(v["inbounds"].is_array(), "inbounds array missing");
        let out = v["outbounds"].as_array().unwrap();
        assert_eq!(out.len(), 2, "outbounds should be [direct, block]");
        assert_eq!(out[0]["type"], "direct");
        assert_eq!(out[1]["type"], "block");
    }

    // ── Pre-apply diff guard (post-2026-05-19 vps-de-01 incident) ──
    //
    // Pavel reported: «Все Anthropic API запросы из claude-chat
    // падали тихо». Root cause: a sing-box deploy on vps-de-01
    // dropped the `claude-chat-proxy` service user UUID
    // (b25684c3-…) from `inbounds[0].users[]` because it wasn't in
    // vpnctld's inventory. The pre-apply diff guard refuses any
    // apply that would REMOVE a live UUID (unless the operator
    // explicitly opts in via VPNCTLD_ALLOW_USER_REMOVAL=1).

    fn make_config(uuids: &[&str]) -> Vec<u8> {
        let users: Vec<Value> = uuids
            .iter()
            .map(|u| {
                serde_json::json!({
                    "name": "u",
                    "uuid": u,
                    "flow": "xtls-rprx-vision",
                })
            })
            .collect();
        let cfg = serde_json::json!({
            "inbounds": [
                { "type": "vless", "users": users }
            ]
        });
        serde_json::to_vec(&cfg).unwrap()
    }

    #[test]
    fn extract_user_uuids_finds_every_uuid_across_inbounds() {
        let cfg = serde_json::json!({
            "inbounds": [
                { "type": "vless", "users": [
                    {"uuid": "aaa", "name": "a"},
                    {"uuid": "bbb", "name": "b"},
                ]},
                { "type": "tuic", "users": [{"uuid": "ccc", "password": "x"}] },
                { "type": "trojan", "users": [{"password": "no-uuid-here"}] },
            ]
        });
        let bytes = serde_json::to_vec(&cfg).unwrap();
        let got = extract_user_uuids(&bytes).unwrap();
        let expected: std::collections::HashSet<String> = ["aaa", "bbb", "ccc"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn extract_user_uuids_returns_empty_on_no_inbounds() {
        let bytes = b"{}".to_vec();
        let got = extract_user_uuids(&bytes).unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn extract_user_uuids_returns_err_on_invalid_json() {
        let bytes = b"not json".to_vec();
        assert!(extract_user_uuids(&bytes).is_err());
    }

    // ─── PR-Q — public drift-detail read helper ────────────────────

    #[test]
    fn live_config_user_uuids_returns_sorted_set() {
        let cfg = serde_json::json!({
            "inbounds": [
                { "type": "vless", "users": [
                    {"uuid": "ccc"},
                    {"uuid": "aaa"},
                    {"uuid": "bbb"},
                ]},
            ]
        });
        let bytes = serde_json::to_vec(&cfg).unwrap();
        let got = live_config_user_uuids(&bytes);
        // BTreeSet iterates in sorted order.
        let order: Vec<&String> = got.iter().collect();
        assert_eq!(order, vec!["aaa", "bbb", "ccc"]);
    }

    #[test]
    fn live_config_user_uuids_empty_on_unparseable_bytes() {
        // Truncated SSH read / non-JSON blob collapses to empty set,
        // NOT a panic or error — the drift card degrades gracefully.
        assert!(live_config_user_uuids(b"not json").is_empty());
        assert!(live_config_user_uuids(b"{}").is_empty());
    }

    #[test]
    fn user_uuid_diff_empty_when_new_is_superset() {
        let old = make_config(&["a", "b"]);
        let new = make_config(&["a", "b", "c"]);
        assert!(user_uuid_diff(&old, &new).unwrap().is_empty());
    }

    #[test]
    fn user_uuid_diff_lists_only_removed_uuids() {
        let old = make_config(&["a", "b", "c"]);
        let new = make_config(&["a", "c"]);
        let lost = user_uuid_diff(&old, &new).unwrap();
        assert_eq!(lost.len(), 1, "lost: {lost:?}");
        assert!(lost.contains("b"));
    }

    #[test]
    fn user_uuid_diff_lists_the_pavel_2026_05_19_case() {
        // The exact incident: live config has claude-chat-proxy's
        // UUID; new rendered config (built from inventory that didn't
        // include the service user) lacks it.
        let live = make_config(&[
            "af6f36aa-2a51-45c7-82dd-5cd362ed970b",
            "b25684c3-90d6-454a-a911-4e0abba568b0", // claude-chat-proxy
        ]);
        let rendered = make_config(&["af6f36aa-2a51-45c7-82dd-5cd362ed970b"]);
        let lost = user_uuid_diff(&live, &rendered).unwrap();
        assert_eq!(lost.len(), 1);
        assert!(lost.contains("b25684c3-90d6-454a-a911-4e0abba568b0"));
    }

    #[test]
    fn user_uuid_diff_empty_when_old_has_no_users() {
        // Fresh node: no /etc/sing-box/config.json yet → empty old set
        // → cannot lose anyone. (In production this path is the
        // ssh.read_file `Err` branch which skips the guard entirely;
        // this test pins the empty-set semantics.)
        let old = b"{\"inbounds\":[]}".to_vec();
        let new = make_config(&["a", "b"]);
        assert!(user_uuid_diff(&old, &new).unwrap().is_empty());
    }

    // ── reserved-ports guard (migration 0028, 2026-05-26) ───────────

    fn cfg_with_inbound_ports(ports: &[u16]) -> Vec<u8> {
        let inbounds: Vec<serde_json::Value> = ports
            .iter()
            .map(|p| serde_json::json!({"type": "vless", "listen_port": p}))
            .collect();
        serde_json::to_vec(&serde_json::json!({"inbounds": inbounds})).unwrap()
    }

    #[test]
    fn reserved_ports_empty_list_is_noop() {
        // Most servers in the fleet have no reserved ports — the
        // guard must short-circuit, never parse, never allocate.
        let cfg = cfg_with_inbound_ports(&[443, 8443]);
        assert!(validate_config_excludes_ports(&cfg, &[]).is_ok());
    }

    #[test]
    fn reserved_ports_disjoint_passes() {
        // Reserved [443], rendered uses [8443] — no collision.
        let cfg = cfg_with_inbound_ports(&[8443, 2083]);
        assert!(validate_config_excludes_ports(&cfg, &[443]).is_ok());
    }

    #[test]
    fn reserved_ports_intersection_blocks() {
        // The 3x-ui scenario: 443 is reserved, the renderer (mistake
        // or accident) wants to bind 443. Guard must refuse, the
        // error must name the offending port.
        let cfg = cfg_with_inbound_ports(&[443, 8443]);
        let err = validate_config_excludes_ports(&cfg, &[443])
            .expect_err("reserved-port collision must error");
        let msg = err.to_string();
        assert!(msg.contains("443"), "error must mention port 443: {msg}");
    }

    #[test]
    fn reserved_ports_multiple_collisions_listed() {
        // Renderer somehow tries TWO reserved ports — error must list
        // both so operator doesn't have to retry to discover the
        // second one. Order is sorted-ascending; dedup applied.
        let cfg = cfg_with_inbound_ports(&[443, 2053, 2096, 8443]);
        let err = validate_config_excludes_ports(&cfg, &[443, 2053, 2096])
            .expect_err("multi-port collision must error");
        let msg = err.to_string();
        // The error renders the offending list as `{:?}` — sorted +
        // dedup'd by the validator.
        assert!(msg.contains("[443, 2053, 2096]"), "msg = {msg}");
    }

    #[test]
    fn reserved_ports_malformed_config_fails_closed() {
        // FAIL-CLOSED policy: the NEW config is what *we* render, so
        // bad JSON means our renderer is broken; refusing to upload
        // is the safest move. (Contrast with user_uuid_diff which
        // fail-OPENs on the OLD config because that may be hand-
        // edited.)
        let err = validate_config_excludes_ports(b"not-json", &[443])
            .expect_err("malformed config with non-empty reserved list must fail closed");
        let msg = err.to_string();
        assert!(msg.contains("parse"), "msg = {msg}");
    }

    #[test]
    fn reserved_ports_no_inbounds_array_is_safe() {
        // Future renderer might produce a config with only outbounds
        // (some route-only role). Treat as vacuously safe — no
        // listen_port to collide.
        let cfg = serde_json::to_vec(&serde_json::json!({"outbounds": []})).unwrap();
        assert!(validate_config_excludes_ports(&cfg, &[443]).is_ok());
    }

    #[test]
    fn reserved_ports_listen_port_missing_is_safe() {
        // Inbound without listen_port (e.g. a transport-only inbound
        // sharing a parent inbound's port) is skipped — only explicit
        // listen_port matches are checked.
        let cfg = serde_json::to_vec(&serde_json::json!({
            "inbounds": [{"type": "vless"}, {"type": "tuic", "listen_port": 8443}]
        }))
        .unwrap();
        assert!(validate_config_excludes_ports(&cfg, &[443]).is_ok());
    }

    #[test]
    fn reserved_ports_listen_port_non_u16_skipped() {
        // Defensive: a JSON value like `99999` or a float that doesn't
        // fit u16 must NOT crash the guard. Skip silently — the
        // sing-box `check -c` step downstream rejects bad ports anyway.
        let cfg = serde_json::to_vec(&serde_json::json!({
            "inbounds": [{"listen_port": 999_999}, {"listen_port": 443}]
        }))
        .unwrap();
        // 443 still flagged; 999_999 silently skipped.
        let err = validate_config_excludes_ports(&cfg, &[443]).expect_err("443 collides");
        assert!(err.to_string().contains("443"));
    }

    #[test]
    fn apply_script_snapshots_live_config_before_swap() {
        // BEFORE the `mv .new → live`, the live config must be copied to
        // a `.bak` (guarded on its existence — first deploy has none) so a
        // runtime-failed restart can roll back. `cp -a` must precede the mv.
        let s = sing_box_apply_script();
        let cp = s
            .find("cp -a /etc/sing-box/config.json /etc/sing-box/config.json.bak")
            .expect("snapshot cp -a to .bak missing");
        let mv = s
            .find("mv /etc/sing-box/config.json.new /etc/sing-box/config.json")
            .expect("atomic swap mv missing");
        assert!(cp < mv, "snapshot must come BEFORE the atomic swap");
        // Snapshot guarded on the live config existing (fresh node = none).
        assert!(
            s.contains("if [ -f /etc/sing-box/config.json ]; then"),
            "snapshot must be guarded on the live config existing: {s}"
        );
    }

    #[test]
    fn apply_script_restores_bak_on_is_active_failure() {
        // On the is-active-failed branch (after the diagnostics dump,
        // before `exit 1`) the script must restore the `.bak` back to the
        // live path and reload-or-restart so the node returns to last-good.
        let s = sing_box_apply_script();
        let journal = s
            .find("journalctl -u sing-box")
            .expect("diagnostics dump missing");
        let restore = s
            .find("mv /etc/sing-box/config.json.bak /etc/sing-box/config.json")
            .expect("restore mv from .bak missing");
        let exit1 = s.rfind("exit 1").expect("failure exit missing");
        assert!(
            journal < restore && restore < exit1,
            "restore must run on the failure branch, after diagnostics, before exit 1"
        );
        // The restore must reload-or-restart so the good config takes effect.
        let restart_after_restore =
            s[restore..exit1].contains("systemctl reload-or-restart sing-box");
        assert!(
            restart_after_restore,
            "restore branch must reload-or-restart back to the good config"
        );
        // The restore must run even though an earlier command "failed":
        // it's reached by falling through the poll loop, and each restore
        // step is `|| true`-guarded so it can't short-circuit before exit 1.
        assert!(
            s[restore..exit1].contains("|| true"),
            "restore steps must be `|| true`-guarded so the branch always reaches exit 1"
        );
    }

    #[test]
    fn apply_script_cleans_up_bak_on_success() {
        // On the active branch the transient `.bak` must be removed so it
        // doesn't accumulate across deploys.
        let s = sing_box_apply_script();
        assert!(
            s.contains("rm -f /etc/sing-box/config.json.bak"),
            "success path must clean up the .bak snapshot: {s}"
        );
    }
}
