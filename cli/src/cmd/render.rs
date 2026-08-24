//! `vpnctl render <server> [--kernel <kernel>]` — render the kernel config for a server
//! and print it to stdout WITHOUT SSH'ing anywhere.
//!
//! Closes the methodology TODO from `docs/PROTOCOL_TESTING.md` layer 5:
//! "until we ship `vpnctl render-server-config`, hand-construct the
//! JSON and unit-test the equivalence." This command IS that helper.
//!
//! Use cases:
//!   - Reviewing what a `vpnctl deploy <server>` WOULD push, without
//!     actually SSH'ing (offline confidence-check)
//!   - Live-staging tests — pipe through `sing-box check` on the node
//!     to fast-loop config drafts without re-implementing the render
//!     in Python
//!   - Diffing: render twice with different secrets, diff the outputs
//!
//! Output: kernel-native format (JSON for sing-box, INI for
//! AmneziaWG). Goes to stdout — pipe to file, less, or another
//! tool. Metadata (kernel headers) goes to stderr so stdout is
//! raw config-compatible.
//!
//! Exit codes:
//!   * 0 — rendered successfully
//!   * non-zero (via `anyhow`) — server unknown, secrets missing,
//!     protocol mismatch with kernel, ambiguous multi-kernel without selector, etc.

use std::io::Write;
use std::path::PathBuf;

use crate::registry;
use crate::ui;
use vpnctl_core::{KernelId, Protocol, Registry, RenderCtx, ServerId};
use vpnctl_inventory::SqliteInventory;

pub(crate) async fn run(
    server: &str,
    kernel_filter: Option<&str>,
    db_flag: Option<PathBuf>,
) -> anyhow::Result<()> {
    let db_path = ui::resolve_db_path(db_flag)?;
    let inv = SqliteInventory::open(&db_path).await?;
    let reg = registry::build()?;
    let sid = ServerId(server.to_string());
    render_server_configs(
        &inv,
        &reg,
        &sid,
        kernel_filter,
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    )
    .await
}

pub(crate) async fn render_server_configs<W1: Write, W2: Write>(
    inv: &SqliteInventory,
    reg: &Registry,
    sid: &ServerId,
    kernel_filter: Option<&str>,
    stdout: &mut W1,
    stderr: &mut W2,
) -> anyhow::Result<()> {
    let server_row = inv
        .get_server(sid)
        .await?
        .ok_or_else(|| anyhow::anyhow!("server not in inventory: {}", sid.0))?;

    // Secrets loaded BEFORE validation so the port-conflict guard sees
    // per-server overrides (vless.listen_port) — same order `deploy` uses.
    let secrets = inv.list_server_secrets(sid).await?;

    // Same protocol-vs-kernel validation `deploy` does pre-SSH — fail
    // here too so operators don't get a surprise from `sing-box check`
    // on the rendered output.
    reg.validate_server(&server_row, &secrets)?;

    let target_kid: KernelId = match kernel_filter {
        Some(k_str) => {
            let kid = KernelId(k_str.to_string());
            if reg.kernel(&kid).is_none() {
                anyhow::bail!("kernel not registered: {k_str}");
            }
            if !server_row.kernels.contains(&kid) {
                let available = if server_row.kernels.is_empty() {
                    "none".to_string()
                } else {
                    server_row
                        .kernels
                        .iter()
                        .map(|k| k.0.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                anyhow::bail!(
                    "server '{}' does not use kernel '{k_str}' (configured kernels: {available})",
                    sid.0
                );
            }
            kid
        }
        None => match server_row.kernels.as_slice() {
            [] => anyhow::bail!("server '{}' has no configured kernels", sid.0),
            [single] => single.clone(),
            _ => {
                let kernels_str = server_row
                    .kernels
                    .iter()
                    .map(|k| k.0.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                anyhow::bail!(
                    "server '{}' has multiple kernels ({kernels_str}); specify which kernel to render with --kernel <name>",
                    sid.0
                );
            }
        },
    };

    let kernel = reg
        .kernel(&target_kid)
        .ok_or_else(|| anyhow::anyhow!("kernel not registered: {target_kid}"))?;

    let users = inv.users_for_server(sid).await?;
    let ctx = RenderCtx::new(&server_row, &secrets);

    let supported = kernel.supported_protocols();
    let protocols: Vec<&dyn Protocol> = server_row
        .enabled_protocols
        .iter()
        .filter(|pid| supported.contains(pid))
        .map(|pid| {
            reg.protocol(pid)
                .ok_or_else(|| anyhow::anyhow!("protocol not registered: {pid}"))
        })
        .collect::<anyhow::Result<_>>()?;

    if protocols.is_empty() {
        // Kernel declared but no protocols for it — still print a
        // header so the operator notices the dead kernel.
        writeln!(
            stderr,
            "# === kernel: {target_kid} (no enabled_protocols this kernel can render — skipped) ==="
        )?;
        return Ok(());
    }

    writeln!(stderr, "# === kernel: {target_kid} ===")?;
    let bytes = kernel.render_config(&ctx, &users, &protocols)?;
    stdout.write_all(&bytes)?;
    if !bytes.ends_with(b"\n") {
        writeln!(stdout)?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use vpnctl_core::{KernelId, ProtocolId, Server, UserId};
    use vpnctl_inventory::bootstrap_server_secrets;

    async fn setup_test_inventory() -> (TempDir, SqliteInventory, Registry) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("inv.db");
        let inv = SqliteInventory::open(&db_path).await.unwrap();
        let reg = registry::build().unwrap();

        // Single kernel server: sing-box only
        let s_single = Server {
            id: ServerId("s-single".into()),
            address: "203.0.113.5".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        };
        inv.add_server(&s_single).await.unwrap();
        bootstrap_server_secrets(&inv, &s_single, &reg)
            .await
            .unwrap();

        // Multi-kernel server: sing-box + amneziawg
        let s_multi = Server {
            id: ServerId("s-multi".into()),
            address: "203.0.113.6".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into()), KernelId("amneziawg".into())],
            enabled_protocols: vec![
                ProtocolId("vless+reality".into()),
                ProtocolId("wireguard".into()),
            ],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        };
        inv.add_server(&s_multi).await.unwrap();
        bootstrap_server_secrets(&inv, &s_multi, &reg)
            .await
            .unwrap();

        // User alice granted to both servers
        inv.add_user(&vpnctl_core::User {
            id: UserId("alice".into()),
            uuid: "00000000-0000-0000-0000-000000000001".into(),
            tuic_password: None,
            wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
        inv.grant(&UserId("alice".into()), &ServerId("s-single".into()))
            .await
            .unwrap();
        inv.grant(&UserId("alice".into()), &ServerId("s-multi".into()))
            .await
            .unwrap();

        (dir, inv, reg)
    }

    #[tokio::test]
    async fn render_single_kernel_server_without_selector_succeeds() {
        let (_dir, inv, reg) = setup_test_inventory().await;
        let sid = ServerId("s-single".into());

        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();

        render_server_configs(&inv, &reg, &sid, None, &mut stdout_buf, &mut stderr_buf)
            .await
            .unwrap();

        let stdout_str = String::from_utf8(stdout_buf).expect("stdout must be UTF-8");
        let stderr_str = String::from_utf8(stderr_buf).expect("stderr must be UTF-8");

        // stdout is raw JSON config without stderr headers
        assert!(!stdout_str.contains("# === kernel: sing-box ==="));
        let _json: serde_json::Value = serde_json::from_str(&stdout_str)
            .expect("vpnctl render stdout must be valid JSON raw config");

        // stderr contains metadata header
        assert!(stderr_str.contains("# === kernel: sing-box ==="));
    }

    #[tokio::test]
    async fn render_multi_kernel_server_without_selector_fails_actionably() {
        let (_dir, inv, reg) = setup_test_inventory().await;
        let sid = ServerId("s-multi".into());

        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();

        let err = render_server_configs(&inv, &reg, &sid, None, &mut stdout_buf, &mut stderr_buf)
            .await
            .expect_err("rendering multi-kernel server without selector must fail");

        let err_msg = err.to_string();
        assert!(
            err_msg.contains("s-multi"),
            "error should mention server id: {err_msg}"
        );
        assert!(
            err_msg.contains("multiple kernels"),
            "error should explain multiple kernels: {err_msg}"
        );
        assert!(
            err_msg.contains("sing-box") && err_msg.contains("amneziawg"),
            "error should list available kernels: {err_msg}"
        );
        assert!(
            err_msg.contains("--kernel"),
            "error should give actionable --kernel hint: {err_msg}"
        );
        assert!(stdout_buf.is_empty(), "stdout must remain empty on error");
    }

    #[tokio::test]
    async fn render_multi_kernel_server_with_valid_selector_singbox() {
        let (_dir, inv, reg) = setup_test_inventory().await;
        let sid = ServerId("s-multi".into());

        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();

        render_server_configs(
            &inv,
            &reg,
            &sid,
            Some("sing-box"),
            &mut stdout_buf,
            &mut stderr_buf,
        )
        .await
        .unwrap();

        let stdout_str = String::from_utf8(stdout_buf).expect("stdout must be UTF-8");
        let stderr_str = String::from_utf8(stderr_buf).expect("stderr must be UTF-8");

        // stdout is raw JSON config for sing-box, not contaminated by amneziawg or headers
        assert!(!stdout_str.contains("# ==="));
        assert!(!stdout_str.contains("[Interface]"));
        let _json: serde_json::Value = serde_json::from_str(&stdout_str)
            .expect("vpnctl render stdout must be valid JSON raw config");

        // stderr has sing-box header, NOT amneziawg header
        assert!(stderr_str.contains("# === kernel: sing-box ==="));
        assert!(!stderr_str.contains("# === kernel: amneziawg ==="));
    }

    #[tokio::test]
    async fn render_multi_kernel_server_with_valid_selector_amneziawg() {
        let (_dir, inv, reg) = setup_test_inventory().await;
        let sid = ServerId("s-multi".into());

        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();

        render_server_configs(
            &inv,
            &reg,
            &sid,
            Some("amneziawg"),
            &mut stdout_buf,
            &mut stderr_buf,
        )
        .await
        .unwrap();

        let stdout_str = String::from_utf8(stdout_buf).expect("stdout must be UTF-8");
        let stderr_str = String::from_utf8(stderr_buf).expect("stderr must be UTF-8");

        // stdout is raw INI config for AmneziaWG
        assert!(!stdout_str.contains("# ==="));
        assert!(stdout_str.contains("[Interface]"));
        assert!(stdout_str.contains("PrivateKey"));

        // stderr has amneziawg header, NOT sing-box header
        assert!(stderr_str.contains("# === kernel: amneziawg ==="));
        assert!(!stderr_str.contains("# === kernel: sing-box ==="));
    }

    #[tokio::test]
    async fn render_invalid_selector_not_in_registry_fails() {
        let (_dir, inv, reg) = setup_test_inventory().await;
        let sid = ServerId("s-multi".into());

        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();

        let err = render_server_configs(
            &inv,
            &reg,
            &sid,
            Some("nonexistent-kernel"),
            &mut stdout_buf,
            &mut stderr_buf,
        )
        .await
        .expect_err("unknown kernel must fail");

        let err_msg = err.to_string();
        assert!(
            err_msg.contains("kernel not registered: nonexistent-kernel"),
            "got error: {err_msg}"
        );
    }

    #[tokio::test]
    async fn render_invalid_selector_not_on_server_fails() {
        let (_dir, inv, reg) = setup_test_inventory().await;
        let sid = ServerId("s-single".into()); // only has sing-box

        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();

        let err = render_server_configs(
            &inv,
            &reg,
            &sid,
            Some("amneziawg"),
            &mut stdout_buf,
            &mut stderr_buf,
        )
        .await
        .expect_err("kernel not assigned to server must fail");

        let err_msg = err.to_string();
        assert!(
            err_msg.contains("server 's-single' does not use kernel 'amneziawg'"),
            "got error: {err_msg}"
        );
        assert!(
            err_msg.contains("sing-box"),
            "error should list configured kernels: {err_msg}"
        );
    }
}
