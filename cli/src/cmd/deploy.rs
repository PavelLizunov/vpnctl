use crate::ui;
use serde_json::json;
use std::path::PathBuf;
use vpnctl_core::{Protocol, RenderCtx, ServerId};
use vpnctl_inventory::{NodeOperationLock, SqliteInventory};
use vpnctl_ssh::SubprocessSshTransport;

pub(crate) async fn run(
    server_id: &str,
    ssh_key: Option<PathBuf>,
    db_flag: Option<PathBuf>,
) -> anyhow::Result<()> {
    let db_path = ui::resolve_db_path(db_flag)?;
    let inv = SqliteInventory::open(&db_path).await?;

    let sid = ServerId(server_id.to_string());
    let server = inv
        .get_server(&sid)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no such server: {server_id}"))?;
    let _operation_lock = NodeOperationLock::try_acquire(&server.id.0)?
        .ok_or_else(|| anyhow::anyhow!("server '{}' is busy with deploy/update", server.id))?;

    let registry = crate::registry::build()?;
    let secrets = inv.list_server_secrets(&sid).await?;
    registry.validate_server(&server, &secrets)?;

    if server.kernels.is_empty() {
        anyhow::bail!("server '{}' has no kernels declared", server.id);
    }
    println!("→ bootstrapping per-protocol server secrets (idempotent)");
    let (_, minted) = vpnctl_inventory::bootstrap_server_secrets(&inv, &server, &registry)
        .await
        .map_err(|e| anyhow::anyhow!("secret bootstrap failed: {e}"))?;
    for label in &minted {
        println!("  minted {label}");
    }

    let deploy_revision = inv.deploy_input_revision(&sid).await?;
    let server = inv
        .get_server(&sid)
        .await?
        .ok_or_else(|| anyhow::anyhow!("server was removed before deploy: {server_id}"))?;
    let secrets = inv.list_server_secrets(&sid).await?;
    let users = inv.users_for_server(&sid).await?;
    registry.validate_server(&server, &secrets)?;
    if server.kernels.is_empty() {
        anyhow::bail!("server '{}' has no kernels declared", server.id);
    }
    inv.assert_no_uuid_collisions(&sid).await?;
    if inv.deploy_input_revision(&sid).await? != deploy_revision {
        anyhow::bail!("inventory changed while preparing deploy; retry");
    }

    let kernels: Vec<&dyn vpnctl_core::Kernel> = server
        .kernels
        .iter()
        .map(|kid| {
            registry
                .kernel(kid)
                .ok_or_else(|| anyhow::anyhow!("kernel not registered: {kid}"))
        })
        .collect::<anyhow::Result<_>>()?;

    let key_path = resolve_key_path(ssh_key)?;
    println!(
        "→ connecting to {}@{}:{} (key {})",
        server.ssh_user,
        server.address,
        server.ssh_port,
        key_path.display()
    );
    let jump = inv.resolve_jump_host(&server).await?;
    let fingerprint = if let Some(value) = server.trusted_host_fingerprint.clone() {
        Some(value)
    } else if jump.is_none() {
        let observed =
            vpnctl_host_fingerprint::fetch_via_keyscan(&server.address, server.ssh_port)?;
        inv.update_trusted_fingerprint(&sid, &observed).await?;
        println!("  TOFU: stored host fingerprint {observed}");
        Some(observed)
    } else {
        None
    };
    let ssh = SubprocessSshTransport::new(&server.address, &server.ssh_user, key_path)
        .port(server.ssh_port)
        .trusted_fingerprint(fingerprint)
        .with_jump(jump);

    for k in &kernels {
        println!("→ ensuring kernel '{}' is installed", k.id());
        k.ensure_installed(&ssh).await?;
    }

    let ctx = RenderCtx::new(&server, &secrets);

    let mut total_config_bytes = 0usize;
    let mut rendered_kernels: Vec<String> = Vec::new();
    for k in &kernels {
        let supported = k.supported_protocols();
        let protocols_for_k: Vec<&dyn Protocol> = server
            .enabled_protocols
            .iter()
            .filter(|pid| supported.contains(pid))
            .map(|pid| {
                registry
                    .protocol(pid)
                    .ok_or_else(|| anyhow::anyhow!("protocol not registered: {pid}"))
            })
            .collect::<anyhow::Result<_>>()?;
        if protocols_for_k.is_empty() {
            println!(
                "→ skipping {} (no enabled_protocols this kernel can render)",
                k.id()
            );
            continue;
        }
        println!(
            "→ rendering config for {} ({} users × {} protocols)",
            k.id(),
            users.len(),
            protocols_for_k.len()
        );
        let config = k.render_config(&ctx, &users, &protocols_for_k)?;
        if k.id().0 == "sing-box" {
            let reserved = inv.get_reserved_ports(&server.id).await?;
            vpnctl_kernels::validate_config_excludes_ports(&config, &reserved)?;
        }
        println!(
            "→ uploading and restarting {} ({} bytes)",
            k.id(),
            config.len()
        );
        k.apply_config(&ssh, &config).await?;
        if let Err(e) = k.open_firewall(&ssh, &ctx, &protocols_for_k).await {
            println!("⚠ firewall step skipped for {}: {e}", k.id());
        }
        total_config_bytes += config.len();
        rendered_kernels.push(k.id().0);
    }

    let payload = json!({
        "users": users.len(),
        "protocols": server.enabled_protocols.iter().map(|p| p.0.as_str()).collect::<Vec<_>>(),
        "kernels_rendered": rendered_kernels,
        "config_bytes_total": total_config_bytes,
        "inputs_changed": false,
    });
    let audit_action = if rendered_kernels.is_empty() {
        inv.audit(
            "cli",
            "server.deploy.skipped",
            Some(server_id),
            Some(&payload),
        )
        .await?;
        "server.deploy.skipped"
    } else if inv
        .audit_deploy_if_revision("cli", &sid, &deploy_revision, &payload)
        .await?
    {
        "server.deploy"
    } else {
        "server.deploy.stale"
    };

    if audit_action != "server.deploy" {
        anyhow::bail!(if audit_action == "server.deploy.stale" {
            "inventory changed during deploy; the server remains pending — deploy again"
        } else {
            "deploy skipped — no kernel config was applied"
        });
    }

    println!("✔ deploy complete");
    Ok(())
}

pub(crate) fn resolve_key_path(flag: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    resolve_key_path_inner(flag, default_key_path()?)
}

fn resolve_key_path_inner(flag: Option<PathBuf>, default: PathBuf) -> anyhow::Result<PathBuf> {
    if let Some(p) = flag {
        return Ok(p);
    }
    if !default.exists() {
        anyhow::bail!(
            "default SSH key '{}' not found — pass --key <path> \
             (note: under sudo $HOME is /root, so the default differs from your login shell)",
            default.display()
        );
    }
    Ok(default)
}

pub(crate) fn default_key_path() -> anyhow::Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("cannot resolve $HOME"))?;
    Ok(home.join(".ssh/id_ed25519"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {

    use super::resolve_key_path_inner;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use vpnctl_core::{KernelId, ProtocolId, RenderCtx, Server, ServerId};
    use vpnctl_inventory::{SqliteInventory, bootstrap_server_secrets};

    #[test]
    fn resolve_key_path_default_missing_returns_actionable_error() {
        let home = TempDir::new().unwrap();
        let default = home.path().join(".ssh/id_ed25519");
        assert!(!default.exists());

        let err =
            resolve_key_path_inner(None, default.clone()).expect_err("missing default must error");
        let msg = err.to_string();
        assert!(msg.contains("--key"), "error must point at --key: {msg}");
        assert!(
            msg.contains(&default.display().to_string()),
            "error must name the missing path: {msg}"
        );
        assert!(
            msg.contains("sudo") && msg.contains("/root"),
            "error must carry the sudo/$HOME=/root hint: {msg}"
        );
    }

    #[test]
    fn resolve_key_path_explicit_existing_key_is_ok() {
        let dir = TempDir::new().unwrap();
        let key = dir.path().join("my_key");
        std::fs::write(&key, b"PRIVATE KEY").unwrap();
        let got = resolve_key_path_inner(Some(key.clone()), PathBuf::from("/nonexistent/default"))
            .expect("explicit existing key must be Ok");
        assert_eq!(got, key);
    }

    #[test]
    fn resolve_key_path_default_present_is_ok() {
        let home = TempDir::new().unwrap();
        let ssh = home.path().join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        let key = ssh.join("id_ed25519");
        std::fs::write(&key, b"PRIVATE KEY").unwrap();

        let got = resolve_key_path_inner(None, key.clone()).expect("present default must be Ok");
        assert_eq!(got, key);
    }

    fn server_with(protocols: &[&str]) -> Server {
        Server {
            id: ServerId("ss-node".into()),
            address: "203.0.113.50".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: protocols.iter().map(|p| ProtocolId((*p).into())).collect(),
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    async fn open(dir: &TempDir) -> SqliteInventory {
        SqliteInventory::open(&dir.path().join("inv.db"))
            .await
            .expect("open")
    }

    #[tokio::test]
    async fn cli_deploy_bootstrap_mints_ss2022_and_hy2_secrets() {
        let dir = TempDir::new().unwrap();
        let inv = open(&dir).await;
        let registry = crate::registry::build().unwrap();
        let server = server_with(&["vless+reality", "shadowsocks-2022", "hysteria2"]);
        inv.add_server(&server).await.unwrap();

        let (secrets, _minted) = bootstrap_server_secrets(&inv, &server, &registry)
            .await
            .unwrap();

        let psk = secrets
            .get("ss2022.psk")
            .expect("ss2022.psk must be minted by the CLI deploy bootstrap");
        assert_eq!(psk.len(), 24, "aes-128 PSK = 24-char padded base64");
        assert!(psk.ends_with("=="), "standard base64 of 16 bytes ends '=='");
        assert!(
            !psk.contains('-') && !psk.contains('_'),
            "PSK must be STANDARD base64, not url-safe"
        );
        assert!(secrets.contains_key("hysteria2.obfs.password"));
        assert!(secrets.contains_key("vless.private_key"));
        assert!(secrets.contains_key("vless.public_key"));
        assert!(secrets.contains_key("vless.short_id"));

        let ctx = RenderCtx::new(&server, &secrets);
        for pid in &server.enabled_protocols {
            let proto = registry.protocol(pid).unwrap();
            if let Err(vpnctl_core::CoreError::MissingSecret { key, .. }) =
                proto.server_inbound(&ctx, &[])
            {
                panic!("protocol {pid:?} still missing `{key}` after CLI bootstrap");
            }
        }
    }

    #[tokio::test]
    async fn cli_deploy_bootstrap_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let inv = open(&dir).await;
        let registry = crate::registry::build().unwrap();
        let server = server_with(&["shadowsocks-2022"]);
        inv.add_server(&server).await.unwrap();

        let (secrets1, minted1) = bootstrap_server_secrets(&inv, &server, &registry)
            .await
            .unwrap();
        assert!(!minted1.is_empty(), "first bootstrap must mint ss2022.psk");

        let (secrets2, minted2) = bootstrap_server_secrets(&inv, &server, &registry)
            .await
            .unwrap();
        assert!(
            minted2.is_empty(),
            "second bootstrap must mint nothing; got {minted2:?}"
        );
        assert_eq!(secrets1, secrets2, "idempotent — never rotates a key");
    }
}
