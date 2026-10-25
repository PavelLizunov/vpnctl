mod arch;
mod guards;
mod scripts;
#[cfg(test)]
mod tests;

pub(crate) use arch::resolve_sing_box_artifact_path;
pub use guards::{live_config_user_uuids, validate_config_excludes_ports};
pub(crate) use scripts::firewall_open_script;
pub use scripts::{
    SING_BOX_AMD64_SHA256, SING_BOX_ARM64_SHA256, SING_BOX_ARMV7_SHA256, SING_BOX_MIN_VERSION,
    SING_BOX_VPNCTL_VERSION,
};

use std::collections::HashSet;

use async_trait::async_trait;
use guards::user_uuid_diff;
use scripts::{
    DEFAULT_STATS_HELPER_ARTIFACT, SING_BOX_SETUP_SCRIPT, cleanup_remote_artifacts_script,
    install_managed_artifacts_script, remote_artifact_paths, sing_box_apply_script,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use vpnctl_core::{
    CoreError, Kernel, KernelId, KernelStatus, KernelVersionPolicy, KernelVersionRequirement,
    Protocol, ProtocolId, RenderCtx, Result, SshTransport, User,
};

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

    fn service_units(&self) -> &'static [&'static str] {
        &["sing-box.service"]
    }

    fn supported_protocols(&self) -> Vec<ProtocolId> {
        vec![
            ProtocolId("vless+reality".to_string()),
            ProtocolId("tuic-v5".to_string()),
            ProtocolId("hysteria2".to_string()),
            ProtocolId("shadowsocks-2022".to_string()),
            ProtocolId("anytls".to_string()),
            ProtocolId("trojan".to_string()),
            ProtocolId("amneziawg2".to_string()),
            ProtocolId("amneziawg3".to_string()),
        ]
    }

    fn version_requirement(&self) -> Option<KernelVersionRequirement> {
        Some(KernelVersionRequirement {
            policy: KernelVersionPolicy::Floor,
            value: SING_BOX_MIN_VERSION,
        })
    }

    async fn ensure_installed(&self, ssh: &dyn SshTransport) -> Result<()> {
        let arch = ssh.exec("uname -m").await?.trim().to_string();
        let helper_override = std::env::var_os("VPNCTL_STATS_HELPER_ARTIFACT");
        // The bundled stats helper is linux/amd64; other nodes need an
        // operator-supplied helper built for their architecture.
        if helper_override.is_none() && !matches!(arch.as_str(), "x86_64" | "amd64") {
            return Err(CoreError::Transport(format!(
                "managed sing-box deploy requires an amd64 node: the stats helper is linux/amd64, node architecture is {arch:?} (set VPNCTL_STATS_HELPER_ARTIFACT to a helper built for it)"
            )));
        }
        let sing_box_path = resolve_sing_box_artifact_path(&arch);
        let helper_path = helper_override
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(DEFAULT_STATS_HELPER_ARTIFACT));
        let (sing_box, stats_helper, sb_digest, sh_digest) =
            tokio::task::spawn_blocking(move || {
                let sb = std::fs::read(&sing_box_path)?;
                let sh = std::fs::read(&helper_path)?;
                let sb_digest = format!("{:x}", Sha256::digest(&sb));
                let sh_digest = format!("{:x}", Sha256::digest(&sh));
                Ok::<_, std::io::Error>((sb, sh, sb_digest, sh_digest))
            })
            .await
            .map_err(|e| CoreError::Transport(format!("spawn_blocking failed: {e}")))?
            .map_err(CoreError::Io)?;

        ssh.exec(SING_BOX_SETUP_SCRIPT.as_str()).await?;

        let check_cmd = "sha256sum /usr/bin/sing-box /usr/local/libexec/vpnctl/singbox-stats-helper 2>/dev/null; systemctl is-active --quiet sing-box 2>/dev/null && echo 'active' || true";
        if let Ok(output) = ssh.exec(check_cmd).await {
            if is_artifact_up_to_date(&output, &sb_digest, &sh_digest) {
                return Ok(());
            }
        }

        let (remote_sing_box, remote_stats_helper) = remote_artifact_paths();
        let cleanup_script =
            cleanup_remote_artifacts_script(&remote_sing_box, &remote_stats_helper);
        let install_script =
            install_managed_artifacts_script(&remote_sing_box, &remote_stats_helper);
        let install_result: Result<()> = async {
            ssh.upload(&remote_sing_box, &sing_box).await?;
            ssh.upload(&remote_stats_helper, &stats_helper).await?;
            ssh.exec(&install_script).await?;
            Ok(())
        }
        .await;
        if install_result.is_err() {
            let _ = ssh.exec(&cleanup_script).await;
        }
        install_result
    }

    fn render_config(
        &self,
        ctx: &RenderCtx<'_>,
        users: &[User],
        protocols: &[&dyn Protocol],
    ) -> Result<Vec<u8>> {
        let mut inbounds = Vec::with_capacity(protocols.len());
        let mut endpoints = Vec::new();
        for p in protocols {
            let fragment = p.server_inbound(ctx, users)?;
            if fragment.get("type").and_then(serde_json::Value::as_str) == Some("wireguard") {
                endpoints.push(fragment);
            } else {
                inbounds.push(fragment);
            }
        }
        let stats_users: Vec<&str> = users.iter().map(|user| user.id.0.as_str()).collect();
        let stats_inbounds: Vec<String> = inbounds
            .iter()
            .map(|inbound| {
                inbound
                    .get("tag")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| CoreError::Render("sing-box inbound is missing its tag".into()))
            })
            .collect::<Result<_>>()?;
        let mut cfg = json!({
            "log": { "level": "info", "output": "/var/log/sing-box.log", "timestamp": true },
            "inbounds": inbounds,
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "block", "tag": "block" }
            ],
            "experimental": {
                "clash_api": {
                    "external_controller": "127.0.0.1:9090"
                },
                "v2ray_api": {
                    "listen": "127.0.0.1:10085",
                    "stats": {
                        "enabled": true,
                        "inbounds": stats_inbounds,
                        "users": stats_users
                    }
                }
            }
        });
        if !endpoints.is_empty() {
            let endpoint_tags: Vec<&str> = endpoints
                .iter()
                .map(|endpoint| {
                    endpoint
                        .get("tag")
                        .and_then(serde_json::Value::as_str)
                        .filter(|tag| !tag.is_empty())
                        .ok_or_else(|| {
                            CoreError::Render("sing-box endpoint is missing its tag".into())
                        })
                })
                .collect::<Result<_>>()?;
            let mut rules = vec![json!({
                "inbound": endpoint_tags, "ip_is_private": true, "action": "reject"
            })];
            if let Ok(address) = ctx.server.address.parse::<std::net::IpAddr>() {
                let prefix = if address.is_ipv4() { 32 } else { 128 };
                rules.push(json!({
                    "inbound": endpoint_tags,
                    "ip_cidr": [format!("{address}/{prefix}")],
                    "action": "reject"
                }));
            } else {
                return Err(CoreError::Render(
                    "AWG server isolation requires a literal server IP; set the server address in the admin UI before deploying".into(),
                ));
            }
            cfg["route"] = json!({ "rules": rules, "final": "direct" });
            cfg["endpoints"] = json!(endpoints);
        }
        serde_json::to_vec_pretty(&cfg).map_err(CoreError::from)
    }

    async fn apply_config(&self, ssh: &dyn SshTransport, config: &[u8]) -> Result<()> {
        self.apply_config_with_known_users(ssh, config, &HashSet::new())
            .await
    }

    async fn apply_config_with_known_users(
        &self,
        ssh: &dyn SshTransport,
        config: &[u8],
        known_user_uuids: &HashSet<String>,
    ) -> Result<()> {
        if let Ok(old_bytes) = ssh.read_file("/etc/sing-box/config.json").await {
            match user_uuid_diff(&old_bytes, config) {
                Ok(removed) => {
                    let mut unknown: Vec<String> = removed
                        .into_iter()
                        .filter(|uuid| !known_user_uuids.contains(uuid))
                        .collect();
                    unknown.sort();
                    let allow = std::env::var("VPNCTLD_ALLOW_USER_REMOVAL")
                        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                        .unwrap_or(false);
                    if !unknown.is_empty() && !allow {
                        let preview: Vec<&String> = unknown.iter().take(5).collect();
                        return Err(CoreError::Render(format!(
                            "sing-box apply_config: refusing to deploy a config that would \
                             REMOVE {} user UUID(s) from inbounds[*].users[]: {:?}{}. \
                             These UUIDs are live on the server but were never known to \
                             vpnctld's inventory. To keep them, add a user with the SAME \
                             UUID in the admin UI and grant it on this server; to drop \
                             them, add that user and then delete it.",
                            unknown.len(),
                            preview,
                            if unknown.len() > preview.len() {
                                format!(" (+{} more)", unknown.len() - preview.len())
                            } else {
                                String::new()
                            },
                        )));
                    }
                }
                Err(e) => {
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
        ctx: &RenderCtx<'_>,
        protocols: &[&dyn Protocol],
    ) -> Result<()> {
        let ports: Vec<(&str, u16)> = protocols
            .iter()
            .flat_map(|p| p.effective_listen_ports(ctx.secrets))
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
            .exec("systemctl is-active sing-box 2>/dev/null || true")
            .await?
            .trim()
            .eq("active");
        let version = ssh
            .exec("/usr/bin/sing-box version 2>/dev/null | awk '/version/{print $3; exit}'")
            .await
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        Ok(KernelStatus {
            active,
            version,
            uptime_seconds: None,
        })
    }
}

pub(crate) fn is_artifact_up_to_date(
    node_check_output: &str,
    sb_digest: &str,
    sh_digest: &str,
) -> bool {
    let lines: Vec<&str> = node_check_output.trim().lines().map(str::trim).collect();
    if lines.len() >= 3 && lines[2] == "active" {
        let node_sb_sha = lines[0].split_whitespace().next().unwrap_or("");
        let node_sh_sha = lines[1].split_whitespace().next().unwrap_or("");
        return !sb_digest.is_empty()
            && !sh_digest.is_empty()
            && node_sb_sha == sb_digest
            && node_sh_sha == sh_digest;
    }
    false
}
