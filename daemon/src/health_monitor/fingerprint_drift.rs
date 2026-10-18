use vpnctl_inventory::SqliteInventory;

pub async fn check_fingerprint_drift(
    inv: &SqliteInventory,
    servers: &[vpnctl_core::Server],
) -> Result<(), vpnctl_inventory::SqliteInventoryError> {
    for server in servers {
        let Some(pinned) = server.trusted_host_fingerprint.as_deref() else {
            continue;
        };
        if server.jump_via.is_some() {
            continue;
        }
        if server.address.is_empty() {
            continue;
        }
        let kind = format!("server.fingerprint.drift:{}", server.id.0);
        const DRIFT_SCAN_ATTEMPTS: usize = 3;
        let mut attempts: Vec<Option<Vec<String>>> = Vec::with_capacity(DRIFT_SCAN_ATTEMPTS);
        for attempt in 0..DRIFT_SCAN_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            let addr = server.address.clone();
            let port = server.ssh_port;
            let scanned = match tokio::task::spawn_blocking(move || {
                vpnctl_host_fingerprint::fetch_all_fingerprints(&addr, port)
            })
            .await
            {
                Ok(Ok(observed)) => Some(observed),
                Ok(Err(e)) => {
                    tracing::debug!(
                        target = "vpnctld::health_monitor",
                        server = %server.id.0,
                        error = %e,
                        "ssh-keyscan failed during fingerprint drift check; will retry"
                    );
                    None
                }
                Err(e) => {
                    tracing::warn!(
                        target = "vpnctld::health_monitor",
                        server = %server.id.0,
                        error = %e,
                        "spawn_blocking for ssh-keyscan failed"
                    );
                    None
                }
            };
            let satisfied = scanned
                .as_ref()
                .is_some_and(|keys| pin_is_present(pinned, keys));
            attempts.push(scanned);
            if satisfied {
                break;
            }
        }
        let observed = match decide_drift(pinned, &attempts) {
            DriftDecision::Matched => {
                match inv.ack_open_alerts(&kind, Some(&server.id)).await {
                    Ok(0) => {}
                    Ok(n) => {
                        tracing::info!(
                            target = "vpnctld::health_monitor",
                            server = %server.id.0,
                            acked = n,
                            "auto-recovered server.fingerprint.drift — pinned key still served"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            target = "vpnctld::health_monitor",
                            server = %server.id.0,
                            error = %e,
                            "auto-recovery ack failed for server.fingerprint.drift"
                        );
                    }
                }
                continue;
            }
            DriftDecision::Inconclusive => continue,
            DriftDecision::Drift { observed } => observed,
        };
        let summary = format!(
            "host fingerprint for {} differs from pinned value — either legitimate SSH key rotation OR active MITM",
            server.id.0
        );
        let payload = serde_json::json!({
            "server_id": server.id.0,
            "previous": pinned,
            "observed_keys": observed,
            "ssh_user": server.ssh_user,
            "ssh_port": server.ssh_port,
            "ip": server.address,
        });
        let payload_str = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string());
        let subject = crate::node_probe_poller::server_subject(inv, &server.id).await;
        match inv
            .insert_alert_if_no_unacked(
                &kind,
                Some(&server.id),
                "warning",
                &summary,
                Some(&payload_str),
            )
            .await
        {
            Ok(Some(alert_id)) => {
                tracing::warn!(
                    target = "vpnctld::health_monitor",
                    alert_id,
                    server = %server.id.0,
                    "fired server.fingerprint.drift alert"
                );
                if let Err(e) = inv
                    .audit(
                        "vpnctld",
                        "alert.fire",
                        Some(&server.id.0),
                        Some(&serde_json::json!({
                            "alert_id": alert_id,
                            "kind": kind,
                            "severity": "warning",
                            "summary": summary,
                        })),
                    )
                    .await
                {
                    tracing::warn!(
                        target = "vpnctld::health_monitor",
                        alert_id,
                        server = %server.id.0,
                        error = %e,
                        "alert.fire audit row failed for server.fingerprint.drift"
                    );
                }
                crate::node_probe_poller::push_alert(
                    inv,
                    &kind,
                    "warning",
                    &subject,
                    &payload,
                    Some(alert_id),
                )
                .await;
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    target = "vpnctld::health_monitor",
                    server = %server.id.0,
                    error = %e,
                    "insert server.fingerprint.drift alert failed"
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn pin_is_present(pinned: &str, observed: &[String]) -> bool {
    observed
        .iter()
        .any(|fp| vpnctl_host_fingerprint::fingerprints_match(pinned, fp))
}

#[derive(Debug, PartialEq)]
pub(crate) enum DriftDecision {
    Matched,
    Drift { observed: Vec<String> },
    Inconclusive,
}

pub(crate) fn decide_drift(pinned: &str, attempts: &[Option<Vec<String>>]) -> DriftDecision {
    let mut any_success = false;
    let mut observed: Vec<String> = Vec::new();
    for keys in attempts.iter().flatten() {
        any_success = true;
        if pin_is_present(pinned, keys) {
            return DriftDecision::Matched;
        }
        for k in keys {
            if !observed.iter().any(|existing| {
                vpnctl_host_fingerprint::fingerprints_match(existing, k) || existing == k
            }) {
                observed.push(k.clone());
            }
        }
    }
    if any_success {
        DriftDecision::Drift { observed }
    } else {
        DriftDecision::Inconclusive
    }
}
