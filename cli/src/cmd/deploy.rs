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
use vpnctl_core::{Protocol, RenderCtx, ServerId};
use vpnctl_inventory::SqliteInventory;
use vpnctl_ssh::RusshTransportBuilder;

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
    registry.validate_server(&server)?;
    if server.kernels.is_empty() {
        anyhow::bail!("server '{}' has no kernels declared", server.id);
    }
    if inv.deploy_input_revision(&sid).await? != deploy_revision {
        anyhow::bail!("inventory changed while preparing deploy; retry");
    }

    // Multi-kernel: resolve every declared kernel up front. validate_server
    // already verified each is registered + each protocol has at least one
    // kernel that supports it; the unwrap-ish lookup below is now just
    // construction of the dispatch loop.
    let kernels: Vec<&dyn vpnctl_core::Kernel> = server
        .kernels
        .iter()
        .map(|kid| {
            registry
                .kernel(kid)
                .ok_or_else(|| anyhow::anyhow!("kernel not registered: {kid}"))
        })
        .collect::<anyhow::Result<_>>()?;

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

    // ─── 2. Install every declared kernel if needed ──────────────────────
    for k in &kernels {
        println!("→ ensuring kernel '{}' is installed", k.id());
        k.ensure_installed(&ssh).await?;
    }

    // The shared node-side self-signed TLS cert (/etc/sing-box/{cert,key}.pem)
    // that tuic-v5 / hysteria2 / trojan / anytls all reference is now
    // provisioned idempotently by the sing-box kernel's `ensure_installed`
    // (step 2 above) — in BOTH this CLI path and the daemon web/SSE path.
    // It used to be minted here, gated on tuic-v5, so a hy2/trojan/anytls-
    // only node missed it; see `crates/kernels/src/sing_box.rs`.

    // ─── 4. Resolve users + per-kernel protocol partition ────────────────
    let ctx = RenderCtx::new(&server, &secrets);

    // ─── 5. Render + apply, one kernel at a time ─────────────────────────
    // Each kernel renders ONLY the protocols it supports. A protocol
    // landing on multiple kernels (currently impossible — no overlap
    // in registered supported_protocols, but trait allows it) would
    // be rendered twice, once per kernel; sing-box/amneziawg topology
    // makes this a non-issue today.
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
        // Reserved-ports pre-apply guard (post-2026-05-26). Refuses
        // to push a config that would bind a port the operator has
        // marked reserved on this server (typically a co-tenant
        // service like a legacy 3x-ui panel on :443). The guard is
        // sing-box-specific today; other kernels are no-ops here.
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
        // Best-effort firewall open (Kernel::open_firewall) so a fresh
        // deploy is reachable without a manual `ufw allow`. Non-fatal.
        if let Err(e) = k.open_firewall(&ssh, &protocols_for_k).await {
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

/// Resolve the SSH private-key path for a command, validating that the
/// *default* actually exists before we hand it to russh.
///
/// When the operator passes `--key` explicitly we trust them and return it
/// as-is — a bad path then surfaces from the transport as usual. But when we
/// fall back to the default `$HOME/.ssh/id_ed25519`, a missing file otherwise
/// dies deep inside russh as an opaque `load key ... io error` with no hint of
/// the real footgun: under `sudo`, `$HOME` is `/root`, so the default differs
/// from the login shell's `~/.ssh/id_ed25519`. We pre-check `exists()` and emit
/// an actionable error pointing at `--key` and the sudo/`$HOME` gotcha.
///
/// Shared by `deploy`, `status`, `bootstrap` (private-key load) and `migrate`.
/// For call sites that only need the *path* (e.g. deriving the `.pub`
/// sibling), use [`default_key_path`] to skip the existence check.
pub(crate) fn resolve_key_path(flag: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    resolve_key_path_inner(flag, default_key_path()?)
}

/// Inner resolver with the default path injected, so tests can exercise the
/// missing-default branch without mutating the global `$HOME` env (the crate
/// forbids `unsafe`, so `std::env::set_var` is off-limits).
fn resolve_key_path_inner(flag: Option<PathBuf>, default: PathBuf) -> anyhow::Result<PathBuf> {
    if let Some(p) = flag {
        // Explicit --key: trust the operator; let the transport surface a bad
        // path. (We don't second-guess an intentional choice.)
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

/// The default SSH private-key path (`$HOME/.ssh/id_ed25519`) without any
/// existence check. Use [`resolve_key_path`] when the key will actually be
/// loaded; this is only for deriving sibling paths (e.g. the `.pub` file).
pub(crate) fn default_key_path() -> anyhow::Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("cannot resolve $HOME"))?;
    Ok(home.join(".ssh/id_ed25519"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    //! Regression net for the secret-bootstrap drift: `vpnctl deploy` must
    //! mint EVERY enabled protocol's server-side secret via the shared
    //! declarative `bootstrap_server_secrets` (built over each protocol's
    //! `server_secret_specs()`), NOT the old hardcoded vless/wireguard
    //! set. The bug: shadowsocks-2022's `ss2022.psk` was never minted →
    //! the whole node deploy hard-failed at render with `MissingSecret {
    //! ss2022.psk }`; hysteria2's `hysteria2.obfs.password` was omitted →
    //! Salamander obfs silently degraded. We exercise the SAME shared
    //! function the deploy path now calls (the deploy `run` itself needs a
    //! live node over SSH, so we test the secret-bootstrap seam directly).

    use super::resolve_key_path_inner;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use vpnctl_core::{KernelId, ProtocolId, RenderCtx, Server, ServerId};
    use vpnctl_inventory::{SqliteInventory, bootstrap_server_secrets};

    #[test]
    fn resolve_key_path_default_missing_returns_actionable_error() {
        // Point the *default* at a tempdir with NO `.ssh/id_ed25519` (mirrors
        // the sudo `$HOME=/root` footgun). The default fallback must fail with
        // an actionable error, not an opaque russh load error later.
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
        // An explicit --key to an existing file is returned verbatim, no error.
        // (The injected default is intentionally bogus — an explicit --key must
        // never even consult it.)
        let dir = TempDir::new().unwrap();
        let key = dir.path().join("my_key");
        std::fs::write(&key, b"PRIVATE KEY").unwrap();
        let got = resolve_key_path_inner(Some(key.clone()), PathBuf::from("/nonexistent/default"))
            .expect("explicit existing key must be Ok");
        assert_eq!(got, key);
    }

    #[test]
    fn resolve_key_path_default_present_is_ok() {
        // Default points at an existing file: resolves Ok with that path.
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

        // Headline fix: ss2022 PSK minted (was silently omitted), in the
        // sing-box-compatible STANDARD base64 (24 chars, padded — a
        // url-safe/unpadded PSK would crash the node config).
        let psk = secrets
            .get("ss2022.psk")
            .expect("ss2022.psk must be minted by the CLI deploy bootstrap");
        assert_eq!(psk.len(), 24, "aes-128 PSK = 24-char padded base64");
        assert!(psk.ends_with("=="), "standard base64 of 16 bytes ends '=='");
        assert!(
            !psk.contains('-') && !psk.contains('_'),
            "PSK must be STANDARD base64, not url-safe"
        );
        // hysteria2 Salamander obfs password minted.
        assert!(secrets.contains_key("hysteria2.obfs.password"));
        // REALITY still minted (no regression for the protocols the old
        // hardcoded path already covered).
        assert!(secrets.contains_key("vless.private_key"));
        assert!(secrets.contains_key("vless.public_key"));
        assert!(secrets.contains_key("vless.short_id"));

        // The contract: every enabled protocol renders its server inbound
        // WITHOUT a MissingSecret after bootstrap — the exact failure mode
        // the bug produced at deploy time.
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
