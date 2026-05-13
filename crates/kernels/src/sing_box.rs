use async_trait::async_trait;
use serde_json::json;
use vpnctl_core::{
    CoreError, Kernel, KernelId, KernelStatus, Protocol, ProtocolId, Result, Server, SshTransport,
    User,
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
        // Скрипт держим короткий — детальный bootstrap хостинга — в `vpnctl-hosters`.
        let script = r#"
            set -e
            if ! command -v sing-box >/dev/null; then
                curl -fsSL https://sing-box.app/gpg.key | gpg --dearmor -o /usr/share/keyrings/sagernet.gpg
                echo "deb [signed-by=/usr/share/keyrings/sagernet.gpg] https://deb.sagernet.org/ * *" \
                    > /etc/apt/sources.list.d/sagernet.list
                apt-get update
                apt-get install -y sing-box
            fi
            systemctl enable sing-box
        "#;
        ssh.exec(script).await?;
        Ok(())
    }

    fn render_config(
        &self,
        _server: &Server,
        users: &[User],
        protocols: &[&dyn Protocol],
    ) -> Result<Vec<u8>> {
        let mut inbounds = Vec::with_capacity(protocols.len());
        for p in protocols {
            inbounds.push(p.server_inbound(users)?);
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
        // Атомарная замена + валидация перед перезагрузкой.
        let cmd = r#"
            set -e
            sing-box check -c /etc/sing-box/config.json.new
            mv /etc/sing-box/config.json.new /etc/sing-box/config.json
            chown sing-box:sing-box /etc/sing-box/config.json
            systemctl reload-or-restart sing-box
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
