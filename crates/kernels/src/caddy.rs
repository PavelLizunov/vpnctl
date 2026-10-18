mod builder;
mod render;
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use vpnctl_core::{
    CoreError, Kernel, KernelId, KernelStatus, KernelVersionPolicy, KernelVersionRequirement,
    Protocol, ProtocolId, RenderCtx, Result, SshTransport, User,
};

use self::builder::{
    CADDY_RESTART_IF_ACTIVE, CADDY_VERSION, caddy_build_script, caddy_cache_path,
    caddy_needs_reinstall, caddy_present, caddy_restart_command, caddy_runtime_provision_script,
    caddy_vlessws_status_command,
};
use self::render::{
    BUNDLE_DELIMITER, naive_apply_script, render_naive_config, render_vlessws_bundle,
    vlessws_apply_script,
};

#[derive(Debug, Default)]
pub struct Caddy;

impl Caddy {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Kernel for Caddy {
    fn id(&self) -> KernelId {
        KernelId("caddy".to_string())
    }

    fn supported_protocols(&self) -> Vec<ProtocolId> {
        vec![
            ProtocolId("naive".to_string()),
            ProtocolId("vless-ws".to_string()),
        ]
    }

    fn version_requirement(&self) -> Option<KernelVersionRequirement> {
        Some(KernelVersionRequirement {
            policy: KernelVersionPolicy::Pin,
            value: CADDY_VERSION,
        })
    }

    async fn ensure_installed(&self, ssh: &dyn SshTransport) -> Result<()> {
        let cache = caddy_cache_path();
        let cache_read = tokio::task::spawn_blocking({
            let cache = cache.clone();
            move || {
                std::fs::read(&cache).map(|bytes| {
                    let digest = format!("{:x}", Sha256::digest(&bytes));
                    (bytes, digest)
                })
            }
        })
        .await
        .map_err(|e| CoreError::Transport(format!("spawn_blocking failed: {e}")))?;

        let binary_changed = match cache_read {
            Ok((bytes, digest)) => {
                let node_sha = ssh
                    .exec("sha256sum /usr/local/bin/caddy 2>/dev/null | cut -d' ' -f1")
                    .await?;
                let needs_reinstall = caddy_needs_reinstall(&digest, &node_sha);
                if needs_reinstall {
                    ssh.upload("/usr/local/bin/caddy.new", &bytes).await?;
                    ssh.exec(&format!(
                        "set -eu\n\
                          echo '{digest}  /usr/local/bin/caddy.new' | sha256sum -c - >/dev/null\n\
                          chmod 0755 /usr/local/bin/caddy.new\n\
                          mv -f /usr/local/bin/caddy.new /usr/local/bin/caddy\n\
                          /usr/local/bin/caddy list-modules | grep -q forward_proxy"
                    ))
                    .await?;
                }
                needs_reinstall
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let present = ssh
                    .exec(
                        "command -v /usr/local/bin/caddy >/dev/null 2>&1 \
                          && /usr/local/bin/caddy list-modules 2>/dev/null | grep -q forward_proxy \
                          && echo present || echo absent",
                    )
                    .await?;
                let needs_reinstall = !caddy_present(&present);
                if needs_reinstall {
                    ssh.exec(&caddy_build_script()).await?;
                }
                needs_reinstall
            }
            Err(e) => return Err(CoreError::Io(e)),
        };

        ssh.exec(&caddy_runtime_provision_script()).await?;
        if binary_changed {
            ssh.exec(CADDY_RESTART_IF_ACTIVE).await?;
        }
        Ok(())
    }

    fn render_config(
        &self,
        ctx: &RenderCtx<'_>,
        users: &[User],
        protocols: &[&dyn Protocol],
    ) -> Result<Vec<u8>> {
        let vlessws = protocols
            .iter()
            .find(|p| p.id() == ProtocolId("vless-ws".to_string()));
        let naive_present = protocols
            .iter()
            .any(|p| p.id() == ProtocolId("naive".to_string()));
        if let Some(vlessws) = vlessws {
            if naive_present {
                return Err(CoreError::Render(
                    "caddy kernel: a server has BOTH `naive` and `vless-ws` enabled, but the \
                      caddy kernel serves exactly one front protocol per node (they contend for \
                      the LE cert + front port). Disable one of them on this server."
                        .into(),
                ));
            }
            return render_vlessws_bundle(ctx, users, *vlessws);
        }

        let naive = protocols
            .iter()
            .find(|p| p.id() == ProtocolId("naive".to_string()))
            .ok_or_else(|| {
                CoreError::Render(
                    "caddy kernel requires the naive or vless-ws protocol in `protocols`".into(),
                )
            })?;

        render_naive_config(ctx, users, *naive)
    }

    async fn apply_config(&self, ssh: &dyn SshTransport, config: &[u8]) -> Result<()> {
        if config.starts_with(BUNDLE_DELIMITER.as_bytes()) {
            ssh.upload("/etc/caddy/.vlessws-bundle.new", config).await?;
            ssh.exec(&vlessws_apply_script()).await?;
            return Ok(());
        }
        ssh.upload("/etc/caddy/Caddyfile.new", config).await?;
        ssh.exec(&naive_apply_script()).await?;
        Ok(())
    }

    async fn restart(&self, ssh: &dyn SshTransport) -> Result<()> {
        ssh.exec(&caddy_restart_command()).await?;
        Ok(())
    }

    async fn status(&self, ssh: &dyn SshTransport) -> Result<KernelStatus> {
        let caddy_active = ssh
            .exec("systemctl is-active caddy 2>/dev/null || true")
            .await?
            .trim()
            .eq("active");
        let active = if caddy_active {
            let probe = ssh
                .exec(&caddy_vlessws_status_command())
                .await?
                .trim()
                .to_string();
            probe == "active" || probe == "absent"
        } else {
            false
        };
        let version = ssh
            .exec("/usr/local/bin/caddy version 2>/dev/null | awk '{print $1; exit}'")
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
