use std::time::Duration;

use vpnctl_inventory::SqliteInventory;

use super::diff::{SINGBOX_LOG_TRIGGER_BYTES, diff_rows, is_one_shot_event};
use super::fingerprint_drift::check_fingerprint_drift;
use super::remediation::{Remediation, auto_remediate_alert};
use super::specialized_checks::{
    check_attribution_stall, check_sub_fetch_without_traffic, check_user_traffic_limits,
};

const ONE_SHOT_PUSH_COOLDOWN: chrono::Duration = chrono::Duration::minutes(30);

static LAST_ONE_SHOT_PUSH: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, chrono::DateTime<chrono::Utc>>>,
> = std::sync::LazyLock::new(Default::default);

pub(crate) const DEFAULT_INTERVAL_SECS: u64 = 10 * 60;

pub fn spawn_health_monitor(inv: SqliteInventory) -> tokio::task::JoinHandle<()> {
    use tokio::time::{MissedTickBehavior, interval};

    let interval_secs = crate::config::parse_positive_secs(
        "VPNCTLD_HEALTH_MONITOR_INTERVAL_SECS",
        DEFAULT_INTERVAL_SECS,
    );

    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(interval_secs));
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        tick.tick().await;
        loop {
            tick.tick().await;
            if let Err(e) = scan_once_inner(&inv, true).await {
                tracing::warn!(
                    target = "vpnctld::health_monitor",
                    error = %e,
                    "scan_once failed; retrying next tick"
                );
            }
        }
    })
}

pub async fn scan_once(
    inv: &SqliteInventory,
) -> Result<(), vpnctl_inventory::SqliteInventoryError> {
    scan_once_inner(inv, false).await
}

async fn scan_once_inner(
    inv: &SqliteInventory,
    auto_remediate: bool,
) -> Result<(), vpnctl_inventory::SqliteInventoryError> {
    let servers = inv.list_fleet_servers().await?;
    for server in &servers {
        if !crate::node_probe_poller::probeable(server) {
            continue;
        }
        let rows = match inv.recent_node_health_for_server(&server.id, 24).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    target = "vpnctld::health_monitor",
                    server = %server.id.0,
                    error = %e,
                    "recent_node_health_for_server failed"
                );
                continue;
            }
        };
        if rows.len() < 2 {
            continue;
        }
        let cur = &rows[0];
        let prev = &rows[1];
        for mut ev in diff_rows(prev, cur) {
            if let (Some(p_id), Some(c_id)) = (prev.sample_id.as_deref(), cur.sample_id.as_deref())
            {
                if let serde_json::Value::Object(ref mut map) = ev.payload {
                    map.insert(
                        "_source_event".to_string(),
                        serde_json::json!(format!("{p_id}:{c_id}")),
                    );
                }
            }
            if ev.kind == "server.singbox.log.too_big"
                && prev
                    .sing_box_log_bytes
                    .is_some_and(|b| b >= SINGBOX_LOG_TRIGGER_BYTES)
            {
                match inv
                    .has_condition_since_recovery(
                        ev.kind,
                        "server.singbox.log.recovered",
                        Some(&server.id),
                    )
                    .await
                {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(e) => {
                        tracing::warn!(
                            target = "vpnctld::health_monitor",
                            server = %server.id.0,
                            error = %e,
                            "could not deduplicate steady oversized-log alert"
                        );
                        continue;
                    }
                }
            }
            let payload_str = match serde_json::to_string(&ev.payload) {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::warn!(
                        target = "vpnctld::health_monitor",
                        error = %e,
                        kind = ev.kind,
                        "alert payload serialise failed; storing empty JSON object"
                    );
                    Some("{}".to_string())
                }
            };
            let should_insert = if let Some(resolved_kind) = ev.resolves {
                match inv.ack_open_alerts(resolved_kind, Some(&server.id)).await {
                    Ok(0) => match inv
                        .has_condition_since_recovery(resolved_kind, ev.kind, Some(&server.id))
                        .await
                    {
                        Ok(true) => {
                            tracing::info!(
                                target = "vpnctld::health_monitor",
                                server = %server.id.0,
                                resolved_kind,
                                "recording recovery for an already-acknowledged paired condition"
                            );
                            true
                        }
                        Ok(false) => false,
                        Err(e) => {
                            tracing::warn!(
                                target = "vpnctld::health_monitor",
                                server = %server.id.0,
                                resolved_kind,
                                error = %e,
                                "could not determine whether the paired condition needs recovery"
                            );
                            false
                        }
                    },
                    Ok(n) => {
                        tracing::info!(
                            target = "vpnctld::health_monitor",
                            server = %server.id.0,
                            resolved_kind,
                            acked = n,
                            "auto-resolved paired condition alert on recovery"
                        );
                        if let Err(e) = inv
                            .audit(
                                "vpnctld",
                                "alert.auto_ack",
                                Some(&server.id.0),
                                Some(&serde_json::json!({
                                    "kind": resolved_kind,
                                    "rows_acked": n,
                                    "reason": ev.kind,
                                })),
                            )
                            .await
                        {
                            tracing::warn!(
                                target = "vpnctld::health_monitor",
                                server = %server.id.0,
                                error = %e,
                                "alert.auto_ack audit row failed; ack already committed"
                            );
                        }
                        true
                    }
                    Err(e) => {
                        tracing::warn!(
                            target = "vpnctld::health_monitor",
                            server = %server.id.0,
                            resolved_kind,
                            error = %e,
                            "auto-resolve ack failed; stale condition alert stays open"
                        );
                        false
                    }
                }
            } else {
                true
            };
            if !should_insert {
                continue;
            }
            let insert_res = if ev.resolves.is_some() || is_one_shot_event(ev.kind) {
                inv.insert_alert_acked(
                    ev.kind,
                    Some(&server.id),
                    ev.severity,
                    &ev.summary,
                    payload_str.as_deref(),
                )
                .await
                .map(Some)
            } else {
                inv.insert_alert_if_no_unacked(
                    ev.kind,
                    Some(&server.id),
                    ev.severity,
                    &ev.summary,
                    payload_str.as_deref(),
                )
                .await
            };
            match insert_res {
                Ok(Some(alert_id)) => {
                    tracing::info!(
                        target = "vpnctld::health_monitor",
                        alert_id,
                        server = %server.id.0,
                        kind = ev.kind,
                        severity = ev.severity,
                        "fired alert"
                    );
                    if let Err(e) = inv
                        .audit(
                            "vpnctld",
                            "alert.fire",
                            Some(&server.id.0),
                            Some(&serde_json::json!({
                                "alert_id": alert_id,
                                "kind": ev.kind,
                                "severity": ev.severity,
                                "summary": ev.summary,
                            })),
                        )
                        .await
                    {
                        tracing::warn!(
                            target = "vpnctld::health_monitor",
                            alert_id,
                            server = %server.id.0,
                            error = %e,
                            "alert.fire audit row failed; admin_alerts row exists but timeline will be missing this entry"
                        );
                    }
                    let subject = crate::node_probe_poller::server_subject(inv, &server.id).await;
                    if let Some(resolves) = ev.resolves {
                        crate::node_probe_poller::recover_alert(
                            inv,
                            ev.kind,
                            resolves,
                            &subject,
                            &ev.payload,
                            Some(&server.id),
                            Some(alert_id),
                        )
                        .await;
                    } else {
                        let fixed = if auto_remediate {
                            if let Some(plan) = Remediation::for_kind(ev.kind) {
                                auto_remediate_alert(inv, server, alert_id, ev.kind, plan, &subject)
                                    .await
                            } else {
                                false
                            }
                        } else {
                            false
                        };
                        let throttled = is_one_shot_event(ev.kind)
                            && !claim_one_shot_push(
                                &LAST_ONE_SHOT_PUSH,
                                &format!("{}\0{}", server.id.0, ev.kind),
                                chrono::Utc::now(),
                            );
                        if !fixed && !throttled {
                            crate::node_probe_poller::push_alert(
                                inv,
                                ev.kind,
                                ev.severity,
                                &subject,
                                &ev.payload,
                                Some(alert_id),
                            )
                            .await;
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(
                        target = "vpnctld::health_monitor",
                        server = %server.id.0,
                        error = %e,
                        kind = ev.kind,
                        "insert_alert failed"
                    );
                }
            }
        }
    }
    if let Err(e) = check_user_traffic_limits(inv).await {
        tracing::warn!(
            target = "vpnctld::health_monitor",
            error = %e,
            "check_user_traffic_limits failed; alert pass skipped this tick"
        );
    }
    if let Err(e) = check_fingerprint_drift(inv, &servers).await {
        tracing::warn!(
            target = "vpnctld::health_monitor",
            error = %e,
            "check_fingerprint_drift failed; fingerprint pass skipped this tick"
        );
    }
    if let Err(e) = check_attribution_stall(inv, &servers).await {
        tracing::warn!(
            target = "vpnctld::health_monitor",
            error = %e,
            "check_attribution_stall failed; attribution pass skipped this tick"
        );
    }
    if let Err(e) = check_sub_fetch_without_traffic(inv).await {
        tracing::warn!(
            target = "vpnctld::health_monitor",
            error = %e,
            "check_sub_fetch_without_traffic failed; sub-stall pass skipped this tick"
        );
    }
    Ok(())
}

pub(super) fn claim_one_shot_push(
    last_push: &std::sync::Mutex<std::collections::HashMap<String, chrono::DateTime<chrono::Utc>>>,
    key: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let Ok(mut map) = last_push.lock() else {
        return true;
    };
    if map
        .get(key)
        .is_some_and(|last| now.signed_duration_since(*last) < ONE_SHOT_PUSH_COOLDOWN)
    {
        return false;
    }
    map.insert(key.to_string(), now);
    true
}
