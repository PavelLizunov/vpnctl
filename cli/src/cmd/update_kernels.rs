//! `vpnctl update-kernels <server> | --all` — upgrade node kernel
//! binaries to their version floor WITHOUT rendering or applying config.
//!
//! ## Why this exists (the feature's whole point)
//!
//! Every `Kernel::ensure_installed(ssh)` already carries the version-gated
//! apt upgrade for that kernel (sing-box, amneziawg, content-aware
//! caddy). Running JUST `ensure_installed` upgrades the
//! on-disk binary and lets the package manager restart the service
//! against the config that is ALREADY on the node — it never enters
//! `apply_config`, so it never triggers the DG-1 pre-apply UUID-removal
//! diff-guard.
//!
//! That bypass is deliberate. `vpnctl deploy` refuses to push a config
//! that would drop a `users[*].uuid` it doesn't know about (service
//! accounts, inventory-drift nodes). On such a node `deploy` is BLOCKED
//! at apply-time, so the operator could never get a security/feature
//! kernel upgrade onto it. `update-kernels` upgrades the binary on those
//! exact nodes — config is left untouched, the drift is preserved, only
//! the kernel version moves.
//!
//! ## What it does NOT do
//!
//! No render, no `apply_config`, no firewall step, no secret bootstrap.
//! Kernel ids come from each server's declaration and resolve through the
//! existing registry, so adding a kernel does not add another updater list.
//! It reuses `Kernel::status` (before/after version) and
//! `Kernel::ensure_installed` (the upgrade) only.

use crate::{OutputFormat, ui};
use serde::Serialize;
use serde_json::json;
use std::path::PathBuf;
use vpnctl_core::{Server, ServerId, SshTransport};
use vpnctl_inventory::{NodeOperationLock, SqliteInventory};
use vpnctl_ssh::SubprocessSshTransport;

/// Which node(s) to upgrade.
#[derive(Debug, Clone)]
pub(crate) enum UpdateTarget {
    /// A single server, by inventory id.
    One(String),
    /// Every server in the inventory.
    All,
}

/// Per-kernel result row — also the JSON output shape.
#[derive(Debug, Clone, Serialize)]
struct KernelUpdate {
    kernel: String,
    version_before: Option<String>,
    version_after: Option<String>,
    changed: bool,
    active_after: Option<bool>,
    reboot_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_before_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Per-server block in the output.
#[derive(Debug, Clone, Serialize)]
struct ServerUpdate {
    server: String,
    kernels: Vec<KernelUpdate>,
    reboot_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Pure record-classification helper, extracted so the before/after
/// logic is unit-testable without SSH. Returns `(changed, label)`.
///
/// * `err == true`  → `(false, "error")` — an `ensure_installed` failure
///   means we did not observe a successful upgrade, so it is never
///   reported as "changed", regardless of the version readings.
/// * version moved   → `(true, "upgraded")`
/// * version steady   → `(false, "unchanged")`
///
/// A `None` reading (status couldn't parse a version) is treated as a
/// distinct value: `None → Some` and `Some → None` both count as a
/// change, `None → None` does not.
fn summarize(before: Option<&str>, after: Option<&str>, err: bool) -> (bool, &'static str) {
    if err {
        return (false, "error");
    }
    if before == after {
        (false, "unchanged")
    } else {
        (true, "upgraded")
    }
}

fn inactive_after_error(active: Option<bool>) -> Option<String> {
    matches!(active, Some(false)).then(|| "kernel is inactive after update".to_string())
}

fn failed_kernel_ids(updates: &[ServerUpdate]) -> Vec<String> {
    updates
        .iter()
        .flat_map(|server| {
            let mut failed = server
                .kernels
                .iter()
                .filter(|kernel| kernel.error.is_some())
                .map(|kernel| format!("{}/{}", server.server, kernel.kernel))
                .collect::<Vec<_>>();
            if server.error.is_some() {
                failed.push(format!("{}/*", server.server));
            }
            failed
        })
        .collect()
}

fn is_reboot_required_error(error: &str) -> bool {
    error.to_ascii_lowercase().contains("reboot required")
}

async fn reboot_required_status(ssh: &dyn SshTransport) -> Option<bool> {
    ssh.exec(
        "if [ -e /var/run/reboot-required ] || [ -e /run/reboot-required ]; then printf yes; else printf no; fi",
    )
    .await
    .ok()
    .map(|value| value.trim() == "yes")
}

pub(crate) async fn run(
    target: UpdateTarget,
    ssh_key: Option<PathBuf>,
    db_flag: Option<PathBuf>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let db_path = ui::resolve_db_path(db_flag)?;
    let inv = SqliteInventory::open(&db_path).await?;
    let registry = crate::registry::build()?;

    let servers: Vec<Server> = match &target {
        UpdateTarget::One(id) => {
            let sid = ServerId(id.clone());
            let server = inv
                .get_server(&sid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("no such server: {id}"))?;
            vec![server]
        }
        UpdateTarget::All => {
            let all = inv.list_fleet_servers().await?;
            if all.is_empty() {
                anyhow::bail!("inventory has no servers");
            }
            all
        }
    };

    let mut all_updates: Vec<ServerUpdate> = Vec::with_capacity(servers.len());
    for server in &servers {
        let update = match update_one_server(&inv, &registry, &ssh_key, server).await {
            Ok(update) => update,
            Err(error) => {
                let message = format!("{error:#}");
                inv.audit(
                    "cli",
                    "kernel.update",
                    Some(&server.id.0),
                    Some(&json!({
                        "kernels": [],
                        "reboot_required": null,
                        "error": message,
                    })),
                )
                .await?;
                ServerUpdate {
                    server: server.id.0.clone(),
                    kernels: Vec::new(),
                    reboot_required: None,
                    error: Some(message),
                }
            }
        };
        sync_update_failure_alert(&inv, &update).await?;
        all_updates.push(update);
    }

    ui::print(format, &all_updates, |list| {
        for su in list {
            println!("server   : {}", su.server);
            if let Some(error) = &su.error {
                println!("  error  : {error}");
            }
            for k in &su.kernels {
                let (_, label) = summarize(
                    k.version_before.as_deref(),
                    k.version_after.as_deref(),
                    k.error.is_some(),
                );
                println!("  kernel : {}", k.kernel);
                println!(
                    "    before : {}",
                    k.version_before.as_deref().unwrap_or("(unknown)")
                );
                println!(
                    "    after  : {}",
                    k.version_after.as_deref().unwrap_or("(unknown)")
                );
                println!("    status : {label}");
                println!(
                    "    active : {}",
                    k.active_after
                        .map_or("unknown", |value| if value { "yes" } else { "no" })
                );
                println!("    reboot-required : {}", k.reboot_required);
                if let Some(e) = &k.error {
                    println!("    error  : {e}");
                }
            }
            println!(
                "  host reboot-required : {}",
                su.reboot_required
                    .map_or("unknown", |value| if value { "yes" } else { "no" })
            );
        }
        Ok(())
    })?;

    let failed = failed_kernel_ids(&all_updates);
    if !failed.is_empty() {
        anyhow::bail!("kernel update failed for: {}", failed.join(", "));
    }
    Ok(())
}

/// Connect to one server (TOFU-persisting the host fingerprint on a
/// first connect, mirroring `deploy`/`status`) and run `ensure_installed`
/// for each declared kernel. Returns the per-kernel result rows.
///
/// Per-kernel error isolation: one kernel's `ensure_installed` failure is
/// recorded in its row and the remaining kernels still run — mirroring
/// the redeploy pipeline's posture. An SSH-connect failure (no kernel
/// could be touched at all) IS propagated, so `--all` does not silently
/// pretend an unreachable node was upgraded.
async fn update_one_server(
    inv: &SqliteInventory,
    registry: &vpnctl_core::Registry,
    ssh_key: &Option<PathBuf>,
    server: &Server,
) -> anyhow::Result<ServerUpdate> {
    let _operation_lock = NodeOperationLock::try_acquire(&server.id.0)?
        .ok_or_else(|| anyhow::anyhow!("server '{}' is busy with deploy/update", server.id))?;
    if server.kernels.is_empty() {
        anyhow::bail!("server '{}' has no kernels declared", server.id);
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

    let key_path = crate::cmd::deploy::resolve_key_path(ssh_key.clone())?;
    println!(
        "→ connecting to {}@{}:{} (key {})",
        server.ssh_user,
        server.address,
        server.ssh_port,
        key_path.display()
    );
    let jump = inv.resolve_jump_host(server).await?;
    let fingerprint = if let Some(value) = server.trusted_host_fingerprint.clone() {
        Some(value)
    } else if jump.is_none() {
        let observed =
            vpnctl_host_fingerprint::fetch_via_keyscan(&server.address, server.ssh_port)?;
        inv.update_trusted_fingerprint(&server.id, &observed)
            .await?;
        println!("  TOFU: stored host fingerprint {observed}");
        Some(observed)
    } else {
        None
    };
    let ssh = SubprocessSshTransport::new(&server.address, &server.ssh_user, key_path)
        .port(server.ssh_port)
        .trusted_fingerprint(fingerprint)
        .with_jump(jump);

    let mut rows: Vec<KernelUpdate> = Vec::with_capacity(kernels.len());
    for k in &kernels {
        let kid = k.id().0;
        println!("→ upgrading kernel '{kid}' (ensure_installed; config untouched)");

        let (before, status_before_error) = match k.status(&ssh).await {
            Ok(status) => (status.version, None),
            Err(error) => (None, Some(format!("status before update failed: {error}"))),
        };

        // THE upgrade. NEVER apply_config — that is the whole point of
        // this command (see module doc): it must not enter the DG-1
        // diff-guard, so inventory-drift nodes can still get the binary.
        let upgrade = k.ensure_installed(&ssh).await;
        let upgrade_error = upgrade.as_ref().err().map(|e| format!("{e:#}"));
        let reboot_required = upgrade_error
            .as_deref()
            .is_some_and(is_reboot_required_error);
        let mut error = upgrade_error.filter(|error| !is_reboot_required_error(error));

        // Re-query after the attempt regardless — even on a failed
        // upgrade the on-disk version + active flag are informative.
        let (version_after, active_after, status_after_error) = match k.status(&ssh).await {
            Ok(status) => (status.version, Some(status.active), None),
            Err(status_error) => (
                None,
                None,
                Some(format!("status after update failed: {status_error}")),
            ),
        };
        if let Some(status_error) = status_after_error {
            error = Some(match error {
                Some(ensure_error) => format!("{ensure_error}; {status_error}"),
                None => status_error,
            });
        }
        if error.is_none() {
            error = inactive_after_error(active_after);
        }

        let (changed, _label) =
            summarize(before.as_deref(), version_after.as_deref(), error.is_some());

        rows.push(KernelUpdate {
            kernel: kid,
            version_before: before,
            version_after,
            changed,
            active_after,
            reboot_required,
            status_before_error,
            error,
        });
    }

    let marker_reboot_required = reboot_required_status(&ssh).await;
    let reboot_required = if rows.iter().any(|row| row.reboot_required) {
        Some(true)
    } else {
        marker_reboot_required
    };

    inv.audit(
        "cli",
        "kernel.update",
        Some(&server.id.0),
        Some(&json!({
            "kernels": rows
                .iter()
                .map(|r| json!({
                    "kernel": r.kernel,
                    "version_before": r.version_before,
                    "version_after": r.version_after,
                    "changed": r.changed,
                    "active_after": r.active_after,
                    "reboot_required": r.reboot_required,
                    "status_before_error": r.status_before_error,
                    "error": r.error,
                }))
                .collect::<Vec<_>>(),
            "reboot_required": reboot_required,
        })),
    )
    .await?;

    Ok(ServerUpdate {
        server: server.id.0.clone(),
        kernels: rows,
        reboot_required,
        error: None,
    })
}

async fn sync_update_failure_alert(
    inv: &SqliteInventory,
    update: &ServerUpdate,
) -> anyhow::Result<()> {
    let server_id = ServerId(update.server.clone());
    let failures = failed_kernel_ids(std::slice::from_ref(update));
    if failures.is_empty() {
        inv.ack_open_alerts("kernel.update.failed", Some(&server_id))
            .await?;
        return Ok(());
    }
    let summary = format!(
        "nightly kernel update failed on {}: {}",
        update.server,
        failures.join(", ")
    );
    let payload = json!({
        "failures": failures,
        "error": update.error,
        "reboot_required": update.reboot_required,
    })
    .to_string();
    if let Some(alert_id) = inv
        .insert_alert_if_no_unacked(
            "kernel.update.failed",
            Some(&server_id),
            "error",
            &summary,
            Some(&payload),
        )
        .await?
    {
        inv.audit(
            "cli",
            "alert.fire",
            Some(&update.server),
            Some(&json!({
                "alert_id": alert_id,
                "kind": "kernel.update.failed",
                "summary": summary,
            })),
        )
        .await?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn summarize_version_moved_is_upgraded() {
        let (changed, label) = summarize(Some("1.10.0"), Some("1.11.0"), false);
        assert!(changed);
        assert_eq!(label, "upgraded");
    }

    #[test]
    fn summarize_same_version_is_unchanged() {
        let (changed, label) = summarize(Some("1.11.0"), Some("1.11.0"), false);
        assert!(!changed);
        assert_eq!(label, "unchanged");
    }

    #[test]
    fn summarize_none_to_some_is_changed() {
        // status couldn't read a version before the upgrade, then could:
        // that is a meaningful change (e.g. binary freshly installed).
        let (changed, label) = summarize(None, Some("1.11.0"), false);
        assert!(changed);
        assert_eq!(label, "upgraded");
    }

    #[test]
    fn summarize_none_to_none_is_unchanged() {
        let (changed, label) = summarize(None, None, false);
        assert!(!changed);
        assert_eq!(label, "unchanged");
    }

    #[test]
    fn summarize_error_overrides_version_change() {
        // Even if the post-attempt version reading differs, an
        // ensure_installed error must surface as "error" and NOT as a
        // successful upgrade.
        let (changed, label) = summarize(Some("1.10.0"), Some("1.11.0"), true);
        assert!(!changed, "an errored upgrade is never reported as changed");
        assert_eq!(label, "error");
    }

    #[test]
    fn inactive_after_update_is_an_error() {
        let error = inactive_after_error(Some(false));
        assert_eq!(error.as_deref(), Some("kernel is inactive after update"));
        assert_eq!(
            summarize(Some("old"), Some("new"), error.is_some()),
            (false, "error")
        );
        assert!(inactive_after_error(Some(true)).is_none());
        assert!(inactive_after_error(None).is_none());
    }

    #[test]
    fn any_kernel_error_makes_the_command_fail() {
        let updates = vec![ServerUpdate {
            server: "de".into(),
            kernels: vec![KernelUpdate {
                kernel: "sing-box".into(),
                version_before: Some("1".into()),
                version_after: Some("1".into()),
                changed: false,
                active_after: Some(false),
                reboot_required: false,
                status_before_error: None,
                error: Some("kernel is inactive after update".into()),
            }],
            reboot_required: Some(false),
            error: None,
        }];
        assert_eq!(failed_kernel_ids(&updates), vec!["de/sing-box"]);
    }

    #[test]
    fn reboot_required_is_status_not_an_install_failure() {
        assert!(is_reboot_required_error(
            "amneziawg DKMS module built for newer kernel. Reboot required."
        ));
        assert!(!is_reboot_required_error("apt download failed"));
    }

    #[test]
    fn nightly_timer_and_service_contract() {
        let timer = include_str!("../../../scripts/vpnctl-update-kernels.timer");
        let service = include_str!("../../../scripts/vpnctl-update-kernels.service");
        let backup_timer = include_str!("../../../scripts/vpnctl-backup.timer");
        let daemon_service = include_str!("../../../scripts/vpnctld.service");

        assert!(timer.contains("OnCalendar=*-*-* 00:30:00 UTC"));
        assert!(!timer.contains("OnCalendar=Sun"));
        assert!(timer.contains("Persistent=true"));
        assert!(timer.contains("RandomizedDelaySec=600"));
        assert!(backup_timer.contains("OnCalendar=*-*-* 00:00:00 UTC"));

        assert!(service.contains("update-kernels --all"));
        assert!(service.contains("After=vpnctl-backup.service"));
        assert!(service.contains("--db /var/lib/vpnctl/inv.db"));
        assert!(service.contains("--key /var/lib/vpnctl/.ssh/id_ed25519"));
        assert!(service.contains("ReadWritePaths=/var/lib/vpnctl"));
        assert!(service.contains("VPNCTLD_NODE_LOCK_DIR=/var/lib/vpnctl/locks"));
        assert!(daemon_service.contains("VPNCTLD_NODE_LOCK_DIR=/var/lib/vpnctl/locks"));
        assert!(!service.contains("apply_config"));
        assert!(!service.contains("systemctl reboot"));
        assert!(!service.contains("shutdown -r"));
    }
}
