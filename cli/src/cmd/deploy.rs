//! `vpnctl deploy <server>` — главная команда v0.2.
//!
//! Полный сценарий идемпотентного развёртывания:
//!
//!   1. Прочитать сервер + grants из inventory.
//!   2. Открыть SSH (TOFU first-connect → запись fingerprint в inventory).
//!   3. Установить ядро если не установлено.
//!   4. Bootstrap secrets:
//!      - VLESS+REALITY: gen x25519 keypair + 8-hex short_id, если их нет
//!        в `server_secrets`.
//!      - TUIC v5: на ноде сгенерить self-signed cert+key, если их там нет.
//!   5. Собрать `RenderCtx`, отрендерить server config через `Kernel`.
//!   6. Залить + перезагрузить ядро.
//!   7. audit_log("server.deploy", payload).

use crate::ui;
use serde_json::json;
use std::path::PathBuf;
use vpnctl_core::{Protocol, RenderCtx, ServerId, SshTransport};
use vpnctl_crypto::{gen_short_id, gen_x25519_keypair};
use vpnctl_inventory::SqliteInventory;
use vpnctl_ssh::RusshTransportBuilder;

const TUIC_CERT_PATH: &str = "/etc/sing-box/cert.pem";
const TUIC_KEY_PATH: &str = "/etc/sing-box/key.pem";

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

    let registry = crate::registry::build()?;
    registry.validate_server(&server)?;

    let kernel = registry
        .kernel(&server.kernel)
        .ok_or_else(|| anyhow::anyhow!("kernel not registered: {}", server.kernel))?;

    // ─── 1. SSH ──────────────────────────────────────────────────────────
    let key_path = resolve_key_path(ssh_key)?;
    println!(
        "→ connecting to {}@{}:{} (key {})",
        server.ssh_user,
        server.address,
        server.ssh_port,
        key_path.display()
    );
    let mut builder =
        RusshTransportBuilder::new(server.address.clone(), server.ssh_user.clone(), key_path)
            .port(server.ssh_port);
    if let Some(fp) = server.trusted_host_fingerprint.as_deref() {
        builder = builder.trusted_fingerprint(fp);
    }
    let ssh = builder.connect().await?;

    // TOFU: if we didn't have a fingerprint, persist what we observed.
    if server.trusted_host_fingerprint.is_none() {
        if let Some(observed) = ssh.observed_host_fingerprint().await {
            inv.update_trusted_fingerprint(&sid, &observed).await?;
            println!("  TOFU: stored host fingerprint {observed}");
        }
    }

    // ─── 2. Install kernel if needed ─────────────────────────────────────
    println!("→ ensuring kernel '{}' is installed", kernel.id());
    kernel.ensure_installed(&ssh).await?;

    // ─── 3. Bootstrap missing secrets ────────────────────────────────────
    let mut secrets = inv.list_server_secrets(&sid).await?;

    let needs_reality = server
        .enabled_protocols
        .iter()
        .any(|p| p.0 == "vless+reality");
    if needs_reality
        && (!secrets.contains_key("vless.private_key")
            || !secrets.contains_key("vless.public_key")
            || !secrets.contains_key("vless.short_id"))
    {
        println!("→ generating REALITY keypair + short_id (first deploy)");
        let (priv_key, pub_key) = gen_x25519_keypair();
        let short_id = gen_short_id()?;
        inv.set_server_secret(&sid, "vless.private_key", &priv_key)
            .await?;
        inv.set_server_secret(&sid, "vless.public_key", &pub_key)
            .await?;
        inv.set_server_secret(&sid, "vless.short_id", &short_id)
            .await?;
        secrets.insert("vless.private_key".into(), priv_key);
        secrets.insert("vless.public_key".into(), pub_key);
        secrets.insert("vless.short_id".into(), short_id);
    }

    let needs_tuic = server.enabled_protocols.iter().any(|p| p.0 == "tuic-v5");
    if needs_tuic {
        let probe = ssh
            .exec(&format!(
                "test -f {TUIC_CERT_PATH} && test -f {TUIC_KEY_PATH} && echo OK || echo MISSING"
            ))
            .await?;
        if probe.trim() == "MISSING" {
            println!("→ generating TUIC self-signed certificate on node");
            let gen_cmd = format!(
                "openssl req -x509 -newkey rsa:2048 \
                 -keyout {TUIC_KEY_PATH} -out {TUIC_CERT_PATH} \
                 -days 3650 -nodes -subj \"/CN=$(hostname)\" 2>&1 && \
                 chown sing-box:sing-box {TUIC_CERT_PATH} {TUIC_KEY_PATH} && \
                 chmod 600 {TUIC_KEY_PATH}"
            );
            ssh.exec(&gen_cmd).await?;
        }
    }

    // ─── 4. Resolve protocols and users ──────────────────────────────────
    let mut protocols: Vec<&dyn Protocol> = Vec::with_capacity(server.enabled_protocols.len());
    for pid in &server.enabled_protocols {
        let p = registry
            .protocol(pid)
            .ok_or_else(|| anyhow::anyhow!("protocol not registered: {pid}"))?;
        protocols.push(p);
    }
    let users = inv.users_for_server(&sid).await?;
    println!(
        "→ rendering config ({} users × {} protocols)",
        users.len(),
        protocols.len()
    );

    // ─── 5. Render + apply ───────────────────────────────────────────────
    let ctx = RenderCtx::new(&server, &secrets);
    let config = kernel.render_config(&ctx, &users, &protocols)?;
    println!(
        "→ uploading and restarting {} ({} bytes)",
        kernel.id(),
        config.len()
    );
    kernel.apply_config(&ssh, &config).await?;

    // ─── 6. Audit ────────────────────────────────────────────────────────
    inv.audit(
        "cli",
        "server.deploy",
        Some(server_id),
        Some(&json!({
            "users": users.len(),
            "protocols": server.enabled_protocols.iter().map(|p| p.0.as_str()).collect::<Vec<_>>(),
            "config_bytes": config.len(),
        })),
    )
    .await?;

    println!("✔ deploy complete");
    Ok(())
}

pub(crate) fn resolve_key_path(flag: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(p) = flag {
        return Ok(p);
    }
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("cannot resolve $HOME"))?;
    Ok(home.join(".ssh/id_ed25519"))
}
