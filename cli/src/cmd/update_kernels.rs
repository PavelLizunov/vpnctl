//! `vpnctl update-kernels <server> | --all` — upgrade node kernel
//! binaries to their version floor WITHOUT rendering or applying config.
//!
//! ## Why this exists (the feature's whole point)
//!
//! Every `Kernel::ensure_installed(ssh)` already carries the version-gated
//! apt upgrade for that kernel (sing-box, amneziawg, content-aware
//! caddy / dns-tunnel). Running JUST `ensure_installed` upgrades the
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
//! It does not add a `Kernel` trait method and it does not touch the
//! registry — no kernel or protocol is introduced, so the
//! Kernel × Protocol orthogonality is preserved. It reuses the existing
//! `Kernel::status` (before/after version) + `Kernel::ensure_installed`
//! (the upgrade) only.

use crate::{OutputFormat, ui};
use serde::Serialize;
use serde_json::json;
use std::path::PathBuf;
use vpnctl_core::{Server, ServerId};
use vpnctl_inventory::SqliteInventory;
use vpnctl_ssh::RusshTransportBuilder;

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
    active_after: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Per-server block in the output.
#[derive(Debug, Clone, Serialize)]
struct ServerUpdate {
    server: String,
    kernels: Vec<KernelUpdate>,
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
            let all = inv.list_servers().await?;
            if all.is_empty() {
                anyhow::bail!("inventory has no servers");
            }
            all
        }
    };

    let mut all_updates: Vec<ServerUpdate> = Vec::with_capacity(servers.len());
    for server in &servers {
        let kernels = update_one_server(&inv, &registry, &ssh_key, server).await?;
        all_updates.push(ServerUpdate {
            server: server.id.0.clone(),
            kernels,
        });
    }

    ui::print(format, &all_updates, |list| {
        for su in list {
            println!("server   : {}", su.server);
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
                println!("    active : {}", k.active_after);
                if let Some(e) = &k.error {
                    println!("    error  : {e}");
                }
            }
        }
        Ok(())
    })
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
) -> anyhow::Result<Vec<KernelUpdate>> {
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
    let mut builder =
        RusshTransportBuilder::new(server.address.clone(), server.ssh_user.clone(), key_path)
            .port(server.ssh_port);
    if let Some(fp) = server.trusted_host_fingerprint.as_deref() {
        builder = builder.trusted_fingerprint(fp);
    }
    let ssh = builder.connect().await?;

    // TOFU: persist the observed fingerprint on a first connect, exactly
    // like `deploy`/`status` so this command can't be a fingerprint-pinning
    // blind spot.
    if server.trusted_host_fingerprint.is_none() {
        if let Some(observed) = ssh.observed_host_fingerprint().await {
            inv.update_trusted_fingerprint(&server.id, &observed)
                .await?;
            println!("  TOFU: stored host fingerprint {observed}");
        }
    }

    let mut rows: Vec<KernelUpdate> = Vec::with_capacity(kernels.len());
    for k in &kernels {
        let kid = k.id().0;
        println!("→ upgrading kernel '{kid}' (ensure_installed; config untouched)");

        let before = k.status(&ssh).await.ok().and_then(|s| s.version);

        // THE upgrade. NEVER apply_config — that is the whole point of
        // this command (see module doc): it must not enter the DG-1
        // diff-guard, so inventory-drift nodes can still get the binary.
        let upgrade = k.ensure_installed(&ssh).await;
        let error = upgrade.as_ref().err().map(|e| format!("{e:#}"));

        // Re-query after the attempt regardless — even on a failed
        // upgrade the on-disk version + active flag are informative.
        let after_status = k.status(&ssh).await.ok();
        let version_after = after_status.as_ref().and_then(|s| s.version.clone());
        let active_after = after_status.as_ref().is_some_and(|s| s.active);

        let (changed, _label) =
            summarize(before.as_deref(), version_after.as_deref(), error.is_some());

        rows.push(KernelUpdate {
            kernel: kid,
            version_before: before,
            version_after,
            changed,
            active_after,
            error,
        });
    }

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
                    "error": r.error,
                }))
                .collect::<Vec<_>>(),
        })),
    )
    .await?;

    Ok(rows)
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
}
