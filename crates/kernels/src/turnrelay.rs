use async_trait::async_trait;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::path::PathBuf;
use vpnctl_core::{
    CoreError, Kernel, KernelId, KernelStatus, Protocol, ProtocolId, RenderCtx, Result, Server,
    SshTransport, User, shell::single_quote,
};

const VERSION: &str = "0.7.0-beta";
const SERVICE: &str = "vpnctl-turnrelay.service";
const BASE: &str = "/etc/vpnctl-turnrelay";
const CERT: &str = "/var/lib/vpnctl-turnrelay/cert.pem";
const CANDIDATE: &str = "/usr/local/libexec/vpnctl-turnrelay/turnrelay-server.candidate";
const PROBE: &str = "if systemctl is-active --quiet vpnctl-turnrelay.service; then echo active; else echo inactive; fi";

#[derive(Debug, Default)]
pub struct TurnRelayKernel;

#[derive(Deserialize)]
struct ServerConfig {
    address: String,
    listen_port: u16,
    mode: String,
    password: String,
    applied: String,
}

fn artifact_path(arch: &str) -> Result<PathBuf> {
    let arch = match arch.trim() {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "armv7l" => "armv7",
        _ => {
            return Err(CoreError::Transport(
                "TurnRelay does not support this node architecture".into(),
            ));
        }
    };
    Ok(PathBuf::from(format!(
        "/opt/vpnctl/node-artifacts/turnrelay-server-{arch}"
    )))
}

fn checksum_path(artifact: &std::path::Path) -> PathBuf {
    let mut path = artifact.as_os_str().to_owned();
    path.push(".sha256");
    PathBuf::from(path)
}

fn pinned_digest(artifact: &std::path::Path) -> Result<String> {
    let checksum = std::fs::read_to_string(checksum_path(artifact)).map_err(|error| {
        CoreError::Transport(format!(
            "TurnRelay node artifact checksum unavailable ({}): {error}",
            checksum_path(artifact).display()
        ))
    })?;
    let digest = checksum
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CoreError::Transport(
            "TurnRelay node artifact checksum is not SHA-256".into(),
        ));
    }
    Ok(digest)
}

async fn stage_file(
    ssh: &dyn SshTransport,
    directory: &str,
    content: &[u8],
    action: impl FnOnce(&str) -> String + Send,
) -> Result<()> {
    let prefix = format!("{directory}/.upload.");
    let path = ssh
        .exec(&format!(
            "set -eu; umask 077; test ! -L {directory}; mktemp {prefix}XXXXXXXX"
        ))
        .await?;
    let path = path.trim();
    if !path.strip_prefix(&prefix).is_some_and(|suffix| {
        suffix.len() == 8 && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
    }) {
        return Err(CoreError::Transport(
            "unexpected TurnRelay staging path".into(),
        ));
    }
    let quoted = single_quote(path);
    let command = format!("set -eu; trap 'rm -f -- {path}' EXIT; {}", action(&quoted));
    crate::apply_staged_config(ssh, path, content, &command).await
}

#[async_trait]
impl Kernel for TurnRelayKernel {
    fn id(&self) -> KernelId {
        KernelId("turnrelay".into())
    }

    fn supported_protocols(&self) -> Vec<ProtocolId> {
        vec![ProtocolId("turnrelay".into())]
    }

    fn validate_server_support(&self, server: &Server) -> Result<()> {
        let address = server
            .address
            .parse::<IpAddr>()
            .map_err(|_| CoreError::Render("TurnRelay needs a literal IP node address".into()))?;
        if address.is_unspecified() || address.is_multicast() {
            return Err(CoreError::Render(
                "TurnRelay node address must be a routable literal IP".into(),
            ));
        }
        Ok(())
    }

    fn service_units(&self) -> &'static [&'static str] {
        &[SERVICE]
    }

    async fn ensure_installed(&self, ssh: &dyn SshTransport) -> Result<()> {
        ssh.exec("set -eu; install -d -o root -g root -m 0755 /etc/vpnctl-turnrelay /usr/local/libexec/vpnctl-turnrelay; command -v nft >/dev/null; command -v openssl >/dev/null").await?;
        let arch = ssh.exec("uname -m").await?;
        let artifact = artifact_path(&arch)?;
        let digest = pinned_digest(&artifact)?;
        let bytes = std::fs::read(&artifact).map_err(|error| {
            CoreError::Transport(format!(
                "TurnRelay node artifact unavailable ({}): {error}",
                artifact.display()
            ))
        })?;
        if format!("{:x}", Sha256::digest(&bytes)) != digest {
            return Err(CoreError::Transport(
                "TurnRelay node artifact failed its pinned SHA-256 check".into(),
            ));
        }
        stage_file(ssh, "/usr/local/libexec/vpnctl-turnrelay", &bytes, |path| {
            format!(
                "test \"$(sha256sum {path} | cut -d' ' -f1)\" = {digest}; chmod 0755 {path}; mv -f {path} {CANDIDATE}"
            )
        })
        .await
    }

    fn render_config(
        &self,
        ctx: &RenderCtx<'_>,
        users: &[User],
        protocols: &[&dyn Protocol],
    ) -> Result<Vec<u8>> {
        let [protocol] = protocols else {
            return Err(CoreError::Render("TurnRelay requires one protocol".into()));
        };
        if protocol.id().0 != "turnrelay" {
            return Err(CoreError::Render("wrong TurnRelay protocol".into()));
        }
        let config: ServerConfig = serde_json::from_value(protocol.server_inbound(ctx, users)?)?;
        if config.address.trim().is_empty() {
            return Err(CoreError::Render("TurnRelay node address is empty".into()));
        }
        let values = [
            (
                "turnrelay_listen",
                format!("0.0.0.0:{}", config.listen_port),
            ),
            ("turnrelay_port", config.listen_port.to_string()),
            ("turnrelay_mode", config.mode),
            ("turnrelay_password", config.password),
            ("turnrelay_applied", config.applied),
            (
                "turnrelay_unit",
                include_str!("turnrelay/vpnctl-turnrelay.service").to_owned(),
            ),
        ];
        let mut script = String::new();
        for (name, value) in values {
            script.push_str(&format!("{name}={}\n", single_quote(&value)));
        }
        script.push_str(include_str!("turnrelay/apply.sh"));
        Ok(script.into_bytes())
    }

    async fn apply_config(&self, ssh: &dyn SshTransport, config: &[u8]) -> Result<()> {
        stage_file(ssh, BASE, config, |path| format!("sh {path}")).await
    }

    async fn open_firewall(
        &self,
        ssh: &dyn SshTransport,
        ctx: &RenderCtx<'_>,
        protocols: &[&dyn Protocol],
    ) -> Result<()> {
        let ports = protocols
            .iter()
            .find(|protocol| protocol.id().0 == "turnrelay")
            .map(|protocol| protocol.effective_listen_ports(ctx.secrets))
            .unwrap_or_default();
        if let Some(script) = crate::firewall::firewall_open_script(&ports) {
            ssh.exec(&script).await?;
        }
        Ok(())
    }

    async fn restart(&self, ssh: &dyn SshTransport) -> Result<()> {
        ssh.exec("set -eu; systemctl restart vpnctl-turnrelay.service; systemctl is-active --quiet vpnctl-turnrelay.service").await?;
        Ok(())
    }

    async fn status(&self, ssh: &dyn SshTransport) -> Result<KernelStatus> {
        let active = ssh.exec(PROBE).await?.trim() == "active";
        Ok(KernelStatus {
            active,
            version: active.then(|| VERSION.to_owned()),
            uptime_seconds: None,
        })
    }

    async fn deployed_server_secrets(
        &self,
        ssh: &dyn SshTransport,
        ctx: &RenderCtx<'_>,
    ) -> Result<Vec<(String, String)>> {
        if !self.status(ssh).await?.active {
            return Err(CoreError::Transport("TurnRelay service is inactive".into()));
        }
        let applied = vpnctl_protocols::turnrelay_applied_digest(ctx)?;
        let fingerprint = ssh
            .exec(&format!(
                "set -eu; test -s {CERT}; openssl x509 -in {CERT} -outform DER | sha256sum | cut -d' ' -f1"
            ))
            .await?;
        let fingerprint = fingerprint.trim();
        if !vpnctl_protocols::is_valid_turnrelay_fingerprint(fingerprint) {
            return Err(CoreError::Transport(
                "TurnRelay certificate fingerprint is not SHA-256".into(),
            ));
        }
        Ok(vec![
            (
                "observed.turnrelay.cert_sha256".into(),
                fingerprint.to_owned(),
            ),
            ("observed.turnrelay.applied".into(), applied),
        ])
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests;
