use vpnctl_core::{Registry, SshTransport};
use vpnctl_inventory::SqliteInventory;

pub(crate) fn probeable(server: &vpnctl_core::Server) -> bool {
    !server.kernels.is_empty()
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    Ok(crate::node_probe::Probe),
    SshFailed(String),
    RowWriteFailed,
    Skipped,
    NoDeployKey,
}

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
        tracing::info!(
            target = "vpnctld::node_probe",
            server = %server.id.0,
            key = %key_path.display(),
            "skipping: deploy SSH key not yet on the homelab host"
        );
        return ProbeOutcome::NoDeployKey;
    }

    let jump = match inv.resolve_jump_host(server).await {
        Ok(j) => j,
        Err(e) => return ProbeOutcome::SshFailed(format!("jump host resolution failed: {e}")),
    };

    let ssh = crate::ssh_subprocess::SubprocessSshTransport::new(
        server.address.clone(),
        server.ssh_user.clone(),
        key_path,
    )
    .port(server.ssh_port)
    .trusted_fingerprint(server.trusted_host_fingerprint.clone())
    .with_jump(jump);

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

async fn collect_declared_kernel_statuses(
    probe: &mut crate::node_probe::Probe,
    registry: &Registry,
    server: &vpnctl_core::Server,
    ssh: &dyn SshTransport,
) {
    for kid in &server.kernels {
        if probe.kernel_active.contains_key(&kid.0) && probe.kernel_versions.contains_key(&kid.0) {
            continue;
        }

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
