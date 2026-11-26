use async_trait::async_trait;
use serde::Deserialize;
use vpnctl_core::{
    CoreError, Kernel, KernelId, KernelStatus, Protocol, ProtocolId, RenderCtx, Result,
    SshTransport, User, shell::single_quote,
};

use crate::turnrelay::{stage_artifact, stage_file};

const SERVICE: &str = "vpnctl-turnrelay-relay.service";
const BASE: &str = "/etc/vpnctl-turnrelay";
const CANDIDATE: &str = "/usr/local/libexec/vpnctl-turnrelay/turnrelay-relay.candidate";

#[derive(Debug, Default)]
pub struct TurnRelayRelayKernel;

#[derive(Deserialize)]
struct RelayConfig {
    address: String,
    listen_port: u16,
    username: String,
    password: String,
    realm: String,
    allowed_exits: String,
}

#[async_trait]
impl Kernel for TurnRelayRelayKernel {
    fn id(&self) -> KernelId {
        KernelId("turnrelay-relay".into())
    }

    fn supported_protocols(&self) -> Vec<ProtocolId> {
        vec![ProtocolId("turnrelay-relay".into())]
    }

    fn service_units(&self) -> &'static [&'static str] {
        &[SERVICE]
    }

    async fn ensure_installed(&self, ssh: &dyn SshTransport) -> Result<()> {
        ssh.exec("install -d -o root -g root -m 0755 /etc/vpnctl-turnrelay /usr/local/libexec/vpnctl-turnrelay").await?;
        stage_artifact(ssh, "turnrelay-relay", CANDIDATE).await
    }

    fn render_config(
        &self,
        ctx: &RenderCtx<'_>,
        users: &[User],
        protocols: &[&dyn Protocol],
    ) -> Result<Vec<u8>> {
        let [protocol] = protocols else {
            return Err(CoreError::Render(
                "TurnRelay entry requires one protocol".into(),
            ));
        };
        if protocol.id().0 != "turnrelay-relay" {
            return Err(CoreError::Render("wrong TurnRelay entry protocol".into()));
        }
        let config: RelayConfig = serde_json::from_value(protocol.server_inbound(ctx, users)?)?;
        let env = format!(
            "RELAY_IP={}\nRELAY_PORT={}\nRELAY_USERNAME={}\nRELAY_PASSWORD={}\nRELAY_REALM={}\nEXIT_IPS={}\n",
            config.address,
            config.listen_port,
            config.username,
            config.password,
            config.realm,
            config.allowed_exits
        );
        let unit = include_str!("turnrelay_relay/vpnctl-turnrelay-relay.service");
        let script = include_str!("turnrelay_relay/apply.sh");
        Ok(format!(
            "relay_port={}\nrelay_env={}\nrelay_unit={}\n{script}",
            config.listen_port,
            single_quote(&env),
            single_quote(unit),
        )
        .into_bytes())
    }

    async fn apply_config(&self, ssh: &dyn SshTransport, config: &[u8]) -> Result<()> {
        stage_file(ssh, BASE, config, |path| format!("sh {path}")).await
    }

    async fn restart(&self, ssh: &dyn SshTransport) -> Result<()> {
        ssh.exec("set -eu; systemctl restart vpnctl-turnrelay-relay.service; systemctl is-active --quiet vpnctl-turnrelay-relay.service").await?;
        Ok(())
    }

    async fn status(&self, ssh: &dyn SshTransport) -> Result<KernelStatus> {
        let probe = format!("if systemctl is-active --quiet {SERVICE}; then echo active; fi");
        let active = ssh.exec(&probe).await?.trim() == "active";
        Ok(KernelStatus {
            active,
            version: None,
            uptime_seconds: None,
        })
    }
}
