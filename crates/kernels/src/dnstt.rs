use async_trait::async_trait;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{net::Ipv4Addr, path::PathBuf};
use vpnctl_core::{
    CoreError, Kernel, KernelId, KernelStatus, Protocol, ProtocolId, RenderCtx, Result, Server,
    SshTransport, User, shell::single_quote,
};

const VERSION: &str = "1.20260501.0";
const SERVICE: &str = "vpnctl-dnstt.service";
const SSH_SERVICE: &str = "vpnctl-dnstt-sshd.service";
const BASE: &str = "/etc/vpnctl-dnstt";
const CANDIDATE: &str = "/usr/local/libexec/vpnctl-dnstt/dnstt-server.candidate";
const PROBE: &str = "if systemctl is-active --quiet vpnctl-dnstt.service && systemctl is-active --quiet vpnctl-dnstt-sshd.service; then echo active; else echo inactive; fi";

#[derive(Debug, Default)]
pub struct DnsttKernel;

#[derive(Deserialize)]
struct ServerConfig {
    domain: String,
    address: Ipv4Addr,
    noise_private: String,
    ssh_host_private: String,
    authorized_keys: Vec<String>,
}

fn artifact_path(arch: &str) -> Result<(PathBuf, &'static str)> {
    let (arch, digest) = match arch.trim() {
        "x86_64" => (
            "amd64",
            "8ad795cd9bd862b3c5bd9fa358c6ae889987c8b52c6bddeb4d5c67d86bfb97f0",
        ),
        "aarch64" => (
            "arm64",
            "ffbc3f00e9d480dc153f62132bfc0f47d67970f9136eed347ec8e6e25d00064e",
        ),
        "armv7l" => (
            "armv7",
            "82eb7763f6e58d86ac9fbe8dad428d4a5937dedb6e33ae4d04233bf01adb9db0",
        ),
        _ => {
            return Err(CoreError::Transport(
                "DNSTT does not support this node architecture".into(),
            ));
        }
    };
    Ok((
        PathBuf::from(format!("/opt/vpnctl/node-artifacts/dnstt-server-{arch}")),
        digest,
    ))
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
        return Err(CoreError::Transport("unexpected DNSTT staging path".into()));
    }
    let quoted = single_quote(path);
    let command = format!("set -eu; trap 'rm -f -- {path}' EXIT; {}", action(&quoted));
    crate::apply_staged_config(ssh, path, content, &command).await
}

#[async_trait]
impl Kernel for DnsttKernel {
    fn id(&self) -> KernelId {
        KernelId("dnstt".into())
    }

    fn supported_protocols(&self) -> Vec<ProtocolId> {
        vec![ProtocolId("dnstt".into())]
    }

    fn validate_server_support(&self, server: &Server) -> Result<()> {
        server
            .address
            .parse::<Ipv4Addr>()
            .map_err(|_| CoreError::Render("DNSTT needs a literal IPv4 node address".into()))?;
        Ok(())
    }

    fn service_units(&self) -> &'static [&'static str] {
        &[SERVICE, SSH_SERVICE]
    }

    async fn ensure_installed(&self, ssh: &dyn SshTransport) -> Result<()> {
        ssh.exec("set -eu; install -d -o root -g root -m 0755 /etc/vpnctl-dnstt /usr/local/libexec/vpnctl-dnstt; command -v nft >/dev/null; command -v sshd >/dev/null").await?;
        let arch = ssh.exec("uname -m").await?;
        let (path, digest) = artifact_path(&arch)?;
        let bytes = std::fs::read(path).map_err(|error| {
            CoreError::Transport(format!("DNSTT node artifact unavailable: {error}"))
        })?;
        if format!("{:x}", Sha256::digest(&bytes)) != digest {
            return Err(CoreError::Transport(
                "DNSTT node artifact failed its pinned SHA-256 check".into(),
            ));
        }
        stage_file(ssh, "/usr/local/libexec/vpnctl-dnstt", &bytes, |path| {
            format!("test \"$(sha256sum {path} | cut -d' ' -f1)\" = {digest}; chmod 0755 {path}; mv -f {path} {CANDIDATE}")
        }).await
    }

    fn render_config(
        &self,
        ctx: &RenderCtx<'_>,
        users: &[User],
        protocols: &[&dyn Protocol],
    ) -> Result<Vec<u8>> {
        let [protocol] = protocols else {
            return Err(CoreError::Render("DNSTT requires one protocol".into()));
        };
        if protocol.id().0 != "dnstt" {
            return Err(CoreError::Render("wrong DNSTT protocol".into()));
        }
        let config: ServerConfig = serde_json::from_value(protocol.server_inbound(ctx, users)?)?;
        let authorized_keys = config
            .authorized_keys
            .iter()
            .map(|key| format!("restrict,port-forwarding {key}\n"))
            .collect::<String>();
        let (ipv6, ipv4): (Vec<&str>, Vec<&str>) = crate::USER_TRAFFIC_DENIED_CIDRS
            .iter()
            .copied()
            .partition(|cidr| cidr.contains(':'));
        let values = [
            ("dnstt_address", config.address.to_string()),
            ("dnstt_domain", config.domain),
            ("dnstt_private", config.noise_private),
            ("dnstt_ssh_host_private", config.ssh_host_private),
            ("dnstt_authorized_keys", authorized_keys),
            ("dnstt_ipv4_deny", ipv4.join(", ")),
            ("dnstt_ipv6_deny", ipv6.join(", ")),
            ("dnstt_sshd", include_str!("dnstt/sshd_config").to_owned()),
            (
                "dnstt_unit",
                include_str!("dnstt/vpnctl-dnstt.service").to_owned(),
            ),
            (
                "dnstt_ssh_unit",
                include_str!("dnstt/vpnctl-dnstt-sshd.service").to_owned(),
            ),
        ];
        let mut script = String::new();
        for (name, value) in values {
            script.push_str(&format!("{name}={}\n", single_quote(&value)));
        }
        script.push_str(include_str!("dnstt/apply.sh"));
        Ok(script.into_bytes())
    }

    async fn apply_config(&self, ssh: &dyn SshTransport, config: &[u8]) -> Result<()> {
        stage_file(ssh, BASE, config, |path| format!("sh {path}")).await
    }

    async fn open_firewall(
        &self,
        ssh: &dyn SshTransport,
        ctx: &RenderCtx<'_>,
        _: &[&dyn Protocol],
    ) -> Result<()> {
        let address = ctx
            .server
            .address
            .parse::<Ipv4Addr>()
            .map_err(|_| CoreError::Render("DNSTT needs a literal IPv4 node address".into()))?;
        ssh.exec(&format!("set -eu; if command -v ufw >/dev/null 2>&1 && LC_ALL=C ufw status | grep -qx 'Status: active'; then ufw allow in proto udp to {address} port 53 comment 'vpnctl DNSTT'; fi")).await?;
        Ok(())
    }

    async fn restart(&self, ssh: &dyn SshTransport) -> Result<()> {
        ssh.exec("set -eu; systemctl restart vpnctl-dnstt-sshd.service vpnctl-dnstt.service; systemctl is-active --quiet vpnctl-dnstt-sshd.service; systemctl is-active --quiet vpnctl-dnstt.service").await?;
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
            return Err(CoreError::Transport("DNSTT services are inactive".into()));
        }
        let (Some(domain), Some(resolver), Some(noise)) = (
            ctx.secrets.get("dnstt.domain"),
            ctx.secrets.get("dnstt.resolver"),
            ctx.secrets.get("dnstt.public_key"),
        ) else {
            return Err(CoreError::Render("missing DNSTT settings".into()));
        };
        let host_key = ssh
            .exec(&format!("ssh-keygen -y -f {BASE}/ssh_host_ed25519_key"))
            .await?;
        let authorized = ssh
            .exec(&format!(
                "sed -n 's/^restrict,port-forwarding //p' {BASE}/authorized_keys"
            ))
            .await?;
        Ok(vec![
            ("dnstt.ssh_host_key".into(), host_key.trim().to_owned()),
            ("dnstt.authorized_keys".into(), authorized),
            (
                "dnstt.applied".into(),
                format!("{domain}+{resolver}+{noise}"),
            ),
        ])
    }
}
