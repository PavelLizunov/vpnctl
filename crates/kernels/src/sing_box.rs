use async_trait::async_trait;
use serde_json::json;
use vpnctl_core::{
    CoreError, Kernel, KernelId, KernelStatus, Protocol, ProtocolId, RenderCtx, Result,
    SshTransport, User,
};

/// sing-box 1.13.x из официального APT-репо SagerNet.
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
            command -v sing-box  # final assertion — fails the exec on regression
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
            ]
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
