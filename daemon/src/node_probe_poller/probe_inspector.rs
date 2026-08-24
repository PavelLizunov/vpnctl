use vpnctl_core::{Registry, SshTransport};
use vpnctl_inventory::SqliteInventory;

/// Centralised "does this kernel expose the probe-able surface" check.
/// Today only `sing-box` answers — AmneziaWG nodes don't run systemd
/// `sing-box`, so the probe script's `systemctl is-active sing-box`
/// would just emit `unknown` noise. Used by BOTH `node_probe_poller`
/// (writes node_health) AND `health_monitor` (reads node_health) so
/// the two surfaces never disagree on what's in scope.
///
/// **TODO(amneziawg)**: when the AmneziaWG kernel ships, either teach
/// this fn to return `true` for it AND wire a per-kernel probe variant
/// (`wg show` instead of `systemctl is-active sing-box`), OR keep the
/// sing-box-only behaviour and add a sibling `probeable_amneziawg`.
/// Today's grep target: `fn probeable`.
pub(crate) fn probeable(server: &vpnctl_core::Server) -> bool {
    !server.kernels.is_empty()
}

/// Outcome of one `probe_one_server` invocation. The poller's state
/// machine reads this to drive the `server.unreachable` consecutive-
/// failure detector (Phase G chunk 2). Probe success ⇒ `Ok(_)`; SSH-
/// or-shell-broken ⇒ `SshFailed`; probe parsed but row insert failed
/// ⇒ `RowWriteFailed` (the failure is logged but doesn't count
/// against the unreachable detector — the node IS reachable).
// `Ok(Probe)` is much larger than the error variants, but a ProbeOutcome
// is created once per probe + matched immediately (never bulk-stored), so
// boxing would add indirection for no real memory benefit.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// Probe succeeded; carries the parsed snapshot so the caller can
    /// dispatch derived alerts (e.g. `fail2ban.banned_self`).
    Ok(crate::node_probe::Probe),
    /// SSH transport / probe script failed entirely. Counts toward the
    /// `server.unreachable` consecutive-failure threshold. Carries a
    /// short human-readable reason (already redacted, safe for
    /// alert payload).
    SshFailed(String),
    /// Probe ran fine but the inventory write failed (sqlx-level
    /// error). Does NOT count toward unreachable (the node IS
    /// reachable; storage is broken, separate problem).
    RowWriteFailed,
    /// Server has no probe-able kernel (e.g. AmneziaWG-only). Skipped
    /// entirely; not a failure.
    Skipped,
    /// Deploy key not on disk. Skipped at the SSH transport boundary;
    /// not a failure.
    NoDeployKey,
}

/// Probe one server, insert the row, and return a [`ProbeOutcome`]
/// so the caller's `FailState` can drive the `server.unreachable`
/// detector. Pure side-effect, never panics. Every error is logged
/// at warn-or-info and folded into the outcome enum (callers don't
/// need to re-check Result variants).
pub(crate) async fn probe_one_server(
    inv: &SqliteInventory,
    server: &vpnctl_core::Server,
) -> ProbeOutcome {
    let registry = match crate::app::build_registry() {
        Ok(registry) => registry,
        Err(e) => return ProbeOutcome::SshFailed(format!("registry build failed: {e}")),
    };
    probe_one_server_with_registry(inv, &registry, server).await
}

pub(crate) async fn probe_one_server_with_registry(
    inv: &SqliteInventory,
    registry: &Registry,
    server: &vpnctl_core::Server,
) -> ProbeOutcome {
    // Skip non-sing-box kernels for now via the centralised filter
    // (see `probeable` doc-comment for the AmneziaWG TODO). Once-per-
    // tick info log so the operator can grep + spot the no-op state
    // when a new kernel lands without probe support — debug is too
    // quiet (invisible by default).
    if !probeable(server) {
        tracing::info!(
            target = "vpnctld::node_probe",
            server = %server.id.0,
            kernels = ?server.kernels.iter().map(|k| k.0.as_str()).collect::<Vec<_>>(),
            "skipping probe — no probe-able kernel (today: sing-box only)"
        );
        return ProbeOutcome::Skipped;
    }

    let key_path = crate::app::deploy_key_path();
    if !key_path.exists() {
        // Pre-deploy: same as clash_poller, log once per tick at info
        // (operator can grep) without spamming at warn.
        tracing::info!(
            target = "vpnctld::node_probe",
            server = %server.id.0,
            key = %key_path.display(),
            "skipping: deploy SSH key not yet on the homelab host"
        );
        return ProbeOutcome::NoDeployKey;
    }

    let ssh = crate::ssh_subprocess::SubprocessSshTransport::new(
        server.address.clone(),
        server.ssh_user.clone(),
        key_path,
    )
    .port(server.ssh_port);

    use crate::node_probe::{ProbeClient, SshProbeClient};
    let client = SshProbeClient::new(&ssh);
    let mut probe = match client.snapshot().await {
        Ok(p) => p,
        Err(e) => {
            let msg = e.to_string();
            tracing::warn!(
                target = "vpnctld::node_probe",
                server = %server.id.0,
                error = %msg,
                "probe snapshot failed"
            );
            return ProbeOutcome::SshFailed(msg);
        }
    };

    collect_declared_kernel_statuses(&mut probe, registry, server, &ssh).await;
    if !server.kernels.iter().any(|kid| kid.0 == "sing-box") {
        probe.sing_box_active = None;
        probe.sing_box_log_bytes = None;
    }

    // Serialise the sorted (proto, port) set as a JSON array of
    // "proto/port" strings — matches `0007_node_health.sql` schema
    // doc-comment.
    let listening_json: Option<String> = if probe.listening.is_empty() {
        None
    } else {
        let v: Vec<String> = probe
            .listening
            .iter()
            .map(|(proto, port)| format!("{proto}/{port}"))
            .collect();
        serde_json::to_string(&v).ok()
    };

    // PR-Q — serialise the on-node kernel versions as a JSON object
    // (BTreeMap → deterministic key order). NULL when empty (old node /
    // partial-probe tick) rather than `{}`.
    let kernel_versions_json: Option<String> =
        if probe.kernel_versions.is_empty() && probe.kernel_active.is_empty() {
            None
        } else {
            let mut observations = std::collections::BTreeMap::new();
            for kid in &server.kernels {
                let version = probe.kernel_versions.get(&kid.0);
                let active = probe.kernel_active.get(&kid.0);
                if version.is_some() || active.is_some() {
                    observations.insert(
                        kid.0.clone(),
                        serde_json::json!({ "version": version, "active": active }),
                    );
                }
            }
            serde_json::to_string(&observations).ok()
        };

    let res = inv
        .record_node_health(
            &server.id,
            probe.sing_box_active,
            probe.fail2ban_active,
            probe.disk_used_mib,
            probe.disk_total_mib,
            probe.mem_available_mib,
            probe.mem_total_mib,
            probe.load_1min_x100,
            listening_json.as_deref(),
            probe.sing_box_log_bytes,
            kernel_versions_json.as_deref(),
            probe.nic_iface.as_deref(),
            probe.nic_rx_bytes,
            probe.nic_tx_bytes,
            probe.sing_box_nrestarts,
        )
        .await;

    match res {
        Ok(()) => {
            tracing::info!(
                target = "vpnctld::node_probe",
                server = %server.id.0,
                sing_box = ?probe.sing_box_active,
                disk_pct = ?probe.disk_pct(),
                "node_health row persisted"
            );
            ProbeOutcome::Ok(probe)
        }
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::node_probe",
                server = %server.id.0,
                error = %e,
                "record_node_health failed"
            );
            ProbeOutcome::RowWriteFailed
        }
    }
}

/// Reuse each declared kernel's own status implementation instead of
/// duplicating version parsers in the generic shell probe. One broken kernel
/// leaves only that observation unknown; the rest of the snapshot survives.
async fn collect_declared_kernel_statuses(
    probe: &mut crate::node_probe::Probe,
    registry: &Registry,
    server: &vpnctl_core::Server,
    ssh: &dyn SshTransport,
) {
    for kid in &server.kernels {
        let Some(kernel) = registry.kernel(kid) else {
            tracing::warn!(
                target = "vpnctld::node_probe",
                server = %server.id.0,
                kernel = %kid.0,
                "declared kernel is not registered; version remains unknown"
            );
            continue;
        };
        match kernel.status(ssh).await {
            Ok(status) => {
                probe.kernel_active.insert(kid.0.clone(), status.active);
                if let Some(version) = status.version.filter(|v| !v.trim().is_empty()) {
                    probe.kernel_versions.insert(kid.0.clone(), version);
                }
            }
            Err(e) => tracing::warn!(
                target = "vpnctld::node_probe",
                server = %server.id.0,
                kernel = %kid.0,
                error = %e,
                "kernel status probe failed; keeping partial node snapshot"
            ),
        }
    }
}
