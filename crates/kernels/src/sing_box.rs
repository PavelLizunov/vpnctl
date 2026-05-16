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
        // Идемпотентно: пакет ставится только если не установлен.
        //
        // Каноничный минимальный Debian (например, новый VDS) НЕ имеет
        // curl/gpg/ca-certificates — поэтому ставим их безусловно перед
        // тем, как тянуть APT-репо SagerNet. Найдено на staging-деплое
        // 84.19.3.104 (Debian 12 minimal): exec exit=127 «curl: команда
        // не найдена».
        //
        // **Logrotate (added 2026-05-16):** without an explicit rotation
        // policy, `/var/log/sing-box.log` grows linearly with traffic
        // (~MB/day on a low-traffic node, GB/day on a busy one). At
        // 20 GB disk staging boxes that's a death spiral within a
        // couple months. Install a logrotate fragment that caps log
        // age at 14 days + size at 100 MB, then `copytruncate` so
        // sing-box doesn't need a SIGHUP/restart to pick up the new
        // file. Idempotent: `cat > .../sing-box` replaces any prior
        // version (including a hand-edited one — operator should know).
        let script = r#"
            set -eu
            export DEBIAN_FRONTEND=noninteractive
            if ! command -v sing-box >/dev/null; then
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
            fi
            # Pre-create log file with sing-box ownership. Otherwise the
            # service crash-loops with "open /var/log/sing-box.log:
            # permission denied" — observed live on the staging deploy.
            install -o sing-box -g sing-box -m 0640 /dev/null /var/log/sing-box.log
            chown -R sing-box:sing-box /etc/sing-box
            systemctl enable sing-box >/dev/null
            # logrotate fragment for sing-box's main log file. `daily`
            # check with size-based trigger at 100 MB. `copytruncate`
            # so sing-box's open file descriptor stays valid (no SIGHUP
            # needed). Keep 14 rotations = ~14 days at most under
            # idle load.
            apt-get install -y --no-install-recommends logrotate
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
    su sing-box sing-box
    create 0640 sing-box sing-box
}
LR
            # Verify the fragment parses — logrotate's parser is strict
            # and a typo would silently disable rotation for ALL fragments.
            logrotate -d /etc/logrotate.d/sing-box >/dev/null 2>&1
            command -v sing-box  # final assertion — fails the exec on regression
            command -v logrotate
        "#;
        ssh.exec(script).await?;
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
        ssh.upload("/etc/sing-box/config.json.new", config).await?;
        // Атомарная замена + валидация перед перезагрузкой + ВЕРИФИКАЦИЯ
        // что сервис реально поднялся. Без последнего блока deploy'и
        // молча «succeed» когда sing-box crash-loop'ит (живой пример:
        // permission denied на /var/log/sing-box.log на свежей ноде).
        let cmd = r#"
            set -eu
            sing-box check -c /etc/sing-box/config.json.new
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
                [ "$state" = "active" ] && exit 0
                sleep 1
            done

            # Bail with the most diagnostic output possible.
            echo "sing-box did not become active. Last 20 log lines:" >&2
            journalctl -u sing-box --no-pager -n 20 >&2 || true
            exit 1
        "#;
        ssh.exec(cmd).await?;
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
}
