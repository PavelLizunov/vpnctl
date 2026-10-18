use vpnctl_inventory::SqliteInventory;

pub async fn check_user_traffic_limits(
    inv: &SqliteInventory,
) -> Result<(), vpnctl_inventory::SqliteInventoryError> {
    let rows = inv.users_traffic_vs_limit().await?;
    for (uid, used, lim, threshold_pct) in rows {
        if lim == 0 {
            continue;
        }
        let pct = ((u128::from(used) * 100) / u128::from(lim)) as u64;
        let kind = format!("user.traffic_limit:{}", uid.0);
        if pct < u64::from(threshold_pct) {
            match inv.ack_open_alerts(&kind, None).await {
                Ok(0) => {}
                Ok(n) => {
                    tracing::info!(
                        target = "vpnctld::health_monitor",
                        user = %uid.0,
                        pct = pct,
                        threshold_pct = threshold_pct,
                        acked = n,
                        "auto-recovered user.traffic_limit — usage now below threshold"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        target = "vpnctld::health_monitor",
                        user = %uid.0,
                        error = %e,
                        "auto-recovery ack failed for user.traffic_limit"
                    );
                }
            }
            continue;
        }
        let used_gib = bytes_as_gib_text(used);
        let lim_gib = bytes_as_gib_text(lim);
        let summary = format!(
            "user {} crossed traffic threshold · {pct}% · {used_gib} of {lim_gib} this month",
            uid.0
        );
        let payload = serde_json::json!({
            "user_id": uid.0,
            "used_bytes": used,
            "limit_bytes": lim,
            "pct": pct,
            "threshold_pct": threshold_pct,
        });
        let payload_str = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string());
        match inv
            .insert_alert_if_no_unacked(&kind, None, "warning", &summary, Some(&payload_str))
            .await
        {
            Ok(Some(alert_id)) => {
                tracing::info!(
                    target = "vpnctld::health_monitor",
                    alert_id,
                    user = %uid.0,
                    pct = pct,
                    threshold_pct = threshold_pct,
                    "fired user.traffic_limit alert"
                );
                if let Err(e) = inv
                    .audit(
                        "vpnctld",
                        "alert.fire",
                        Some(&uid.0),
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
                        user = %uid.0,
                        error = %e,
                        "alert.fire audit row failed for user.traffic_limit"
                    );
                }
                crate::node_probe_poller::push_alert(
                    inv,
                    &kind,
                    "warning",
                    &uid.0,
                    &payload,
                    Some(alert_id),
                )
                .await;
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    target = "vpnctld::health_monitor",
                    user = %uid.0,
                    error = %e,
                    "insert user.traffic_limit alert failed"
                );
            }
        }
    }
    Ok(())
}

pub async fn check_attribution_stall(
    inv: &SqliteInventory,
    servers: &[vpnctl_core::Server],
) -> Result<(), vpnctl_inventory::SqliteInventoryError> {
    const KIND: &str = "server.attribution.stalled";
    const WINDOW_MINUTES: u32 = 15;
    const MIN_ACTIVE: u32 = 5;

    let stalled = inv
        .attribution_stall_servers(WINDOW_MINUTES, MIN_ACTIVE)
        .await?;
    let stalled: std::collections::HashSet<&str> = stalled.iter().map(|s| s.0.as_str()).collect();

    for server in servers {
        let sid = &server.id;
        if !stalled.contains(sid.0.as_str()) {
            match inv.ack_open_alerts(KIND, Some(sid)).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(
                    target = "vpnctld::health_monitor",
                    server = %sid.0,
                    acked = n,
                    "auto-recovered server.attribution.stalled — attribution resumed"
                ),
                Err(e) => tracing::warn!(
                    target = "vpnctld::health_monitor",
                    server = %sid.0,
                    error = %e,
                    "auto-recovery ack failed for server.attribution.stalled"
                ),
            }
            continue;
        }
        let summary = format!(
            "per-user attribution stalled on {} — connections are active but the sing-box log scrape attributed 0 users for \u{2265}{WINDOW_MINUTES}m (likely an orphaned sing-box log fd; per-user stats + abuse views go blank for this node until the log is reopened)",
            sid.0
        );
        let payload = serde_json::json!({
            "server_id": sid.0,
            "window_minutes": WINDOW_MINUTES,
            "min_active": MIN_ACTIVE,
        });
        let payload_str = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string());
        match inv
            .insert_alert_if_no_unacked(KIND, Some(sid), "warning", &summary, Some(&payload_str))
            .await
        {
            Ok(Some(alert_id)) => {
                tracing::info!(
                    target = "vpnctld::health_monitor",
                    alert_id,
                    server = %sid.0,
                    "fired server.attribution.stalled alert"
                );
                if let Err(e) = inv
                    .audit(
                        "vpnctld",
                        "alert.fire",
                        Some(&sid.0),
                        Some(&serde_json::json!({
                            "alert_id": alert_id,
                            "kind": KIND,
                            "severity": "warning",
                            "summary": summary,
                        })),
                    )
                    .await
                {
                    tracing::warn!(
                        target = "vpnctld::health_monitor",
                        alert_id,
                        server = %sid.0,
                        error = %e,
                        "alert.fire audit row failed for server.attribution.stalled"
                    );
                }
                let subject = crate::node_probe_poller::server_subject(inv, sid).await;
                crate::node_probe_poller::push_alert(
                    inv,
                    KIND,
                    "warning",
                    &subject,
                    &payload,
                    Some(alert_id),
                )
                .await;
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(
                target = "vpnctld::health_monitor",
                server = %sid.0,
                error = %e,
                "insert server.attribution.stalled alert failed"
            ),
        }
    }
    Ok(())
}

pub async fn check_sub_fetch_without_traffic(
    inv: &SqliteInventory,
) -> Result<(), vpnctl_inventory::SqliteInventoryError> {
    const KIND_PREFIX: &str = "user.sub_no_traffic:";
    const GRACE_MINUTES: u32 = 45;
    const LOOKBACK_MINUTES: u32 = 360;
    const ACTIVE_DAYS: u32 = 7;

    let firing = inv
        .sub_fetch_without_traffic_users(GRACE_MINUTES, LOOKBACK_MINUTES, ACTIVE_DAYS)
        .await?;
    let firing_ids: std::collections::HashSet<&str> =
        firing.iter().map(|u| u.user_id.0.as_str()).collect();

    let open_subjects = inv
        .open_alert_subjects_with_kind_prefix(KIND_PREFIX)
        .await?;
    for uid in &open_subjects {
        if firing_ids.contains(uid.as_str()) {
            continue;
        }
        let kind = format!("{KIND_PREFIX}{uid}");
        match inv.ack_open_alerts(&kind, None).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(
                target = "vpnctld::health_monitor",
                user = %uid,
                acked = n,
                "auto-resolved user.sub_no_traffic — traffic resumed or fetch aged out"
            ),
            Err(e) => tracing::warn!(
                target = "vpnctld::health_monitor",
                user = %uid,
                error = %e,
                "auto-resolve ack failed for user.sub_no_traffic"
            ),
        }
    }

    for u in &firing {
        let kind = format!("{KIND_PREFIX}{}", u.user_id.0);
        let last_seen = u.last_traffic.as_deref().unwrap_or("never");
        let summary = format!(
            "user {} re-fetched their subscription {}m ago but has sent no traffic since (last traffic: {}) — their issued config may no longer connect",
            u.user_id.0, u.fetch_age_minutes, last_seen
        );
        let payload = serde_json::json!({
            "user_id": u.user_id.0,
            "last_fetch": u.last_fetch,
            "last_traffic": u.last_traffic,
            "fetch_age_minutes": u.fetch_age_minutes,
            "grace_minutes": GRACE_MINUTES,
            "lookback_minutes": LOOKBACK_MINUTES,
        });
        let payload_str = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string());
        match inv
            .insert_alert_if_no_unacked(&kind, None, "warning", &summary, Some(&payload_str))
            .await
        {
            Ok(Some(alert_id)) => {
                tracing::info!(
                    target = "vpnctld::health_monitor",
                    alert_id,
                    user = %u.user_id.0,
                    fetch_age_minutes = u.fetch_age_minutes,
                    "fired user.sub_no_traffic alert"
                );
                if let Err(e) = inv
                    .audit(
                        "vpnctld",
                        "alert.fire",
                        Some(&u.user_id.0),
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
                        user = %u.user_id.0,
                        error = %e,
                        "alert.fire audit row failed for user.sub_no_traffic"
                    );
                }
                crate::node_probe_poller::push_alert(
                    inv,
                    &kind,
                    "warning",
                    &u.user_id.0,
                    &payload,
                    Some(alert_id),
                )
                .await;
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(
                target = "vpnctld::health_monitor",
                user = %u.user_id.0,
                error = %e,
                "insert user.sub_no_traffic alert failed"
            ),
        }
    }
    Ok(())
}

pub(crate) fn bytes_as_gib_text(b: u64) -> String {
    let gib = (b as f64) / (1024.0 * 1024.0 * 1024.0);
    format!("{gib:.1} GiB")
}
