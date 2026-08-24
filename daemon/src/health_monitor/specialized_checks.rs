use vpnctl_inventory::SqliteInventory;

/// Per-tick scan for users whose monthly traffic has crossed the
/// configured `traffic_alert_threshold_pct`. Fires a
/// `user.traffic_limit:<user_id>` alert (severity `warning`), routed
/// through the standard `admin_alerts` → Telegram pipeline.
///
/// The kind suffix is the user_id (mirrors the existing
/// `sub_access.suspicious_local_ip:<user_id>` convention from
/// `access_log.rs`) so the partial-UNIQUE index on
/// `(kind, COALESCE(server_id, '__GLOBAL__')) WHERE acked_at IS NULL`
/// deduplicates per-user: one open alert at a time, not one per tick.
///
/// **Auto-recovery (shipped 2026-05-23, commit b4608d2):** when a
/// user drops back below `threshold_pct` (e.g. month rolls over,
/// operator raised the limit, traffic stopped), the open warning is
/// silently acked via `ack_open_alerts(kind, None)`. Matches the
/// existing `ack_open_alerts` doc-comment policy: «a self-clearing
/// alert doesn't need operator attention; the audit_log row from
/// the original fire keeps the timeline complete». If we ever want
/// explicit `*.recovered` info-alerts, that's a separate change.
pub async fn check_user_traffic_limits(
    inv: &SqliteInventory,
) -> Result<(), vpnctl_inventory::SqliteInventoryError> {
    let rows = inv.users_traffic_vs_limit().await?;
    for (uid, used, lim, threshold_pct) in rows {
        // Same percent math as the dashboard tile (admin.rs:706-711).
        // Skip rows where the limit is 0 (no limit configured — the
        // SQL filters with `WHERE u.monthly_bandwidth_limit_bytes IS
        // NOT NULL` already, but defense in depth on the divide-by-
        // zero edge).
        if lim == 0 {
            continue;
        }
        let pct = ((u128::from(used) * 100) / u128::from(lim)) as u64;
        let kind = format!("user.traffic_limit:{}", uid.0);
        if pct < u64::from(threshold_pct) {
            // Auto-recovery: drop below threshold (e.g. month
            // rolled over, operator raised the limit, traffic
            // stopped) → silently ack any open warning. Without
            // this the alert sits in /admin/alerts forever and
            // forces the operator to manually triage every
            // monthly cycle. Server_id=None matches the original
            // insert site (user-traffic alerts aren't server-
            // scoped).
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
        // Format used / limit as GiB-with-one-decimal for the Telegram
        // line. Doing the format string Rust-side rather than relying
        // on TelegramSink's formatting because we want the user-facing
        // message to be short + scannable («user X: 95% / 18.5 of
        // 20 GiB monthly»).
        let used_gib = bytes_as_gib_text(used);
        let lim_gib = bytes_as_gib_text(lim);
        // `kind` already bound above (used by the recovery branch
        // before the threshold check). Reuse rather than rebind so
        // the kind string is computed exactly once per row.
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
            .insert_alert_if_no_unacked(
                &kind,
                None, // not server-scoped
                "warning",
                &summary,
                Some(&payload_str),
            )
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
                // Mirror to audit_log so /admin/audit timeline shows
                // the firing — same shape as the per-server alerts
                // above + node_probe_poller's pattern.
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
                // Best-effort Telegram push (same pattern as
                // node_probe_poller). Failures stay in the log; the
                // admin_alerts row is the source of truth. Subject is the
                // user id (this alert is user-scoped, not server-scoped).
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
            Ok(None) => {
                // Already-open alert for the same (kind, NULL) pair —
                // partial UNIQUE index dedup. Nothing to do.
            }
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

/// Detect + alert on per-user attribution STALL (2026-06-14). Fires
/// `server.attribution.stalled` (warning, server-scoped) when a node has
/// live connections but the clash poll attributed ZERO users over the
/// recent window — the silent signature of an orphaned sing-box log fd or
/// a persistently failing log scrape (both hit prod: the logrotate orphan,
/// then the `install /dev/null` ensure_installed orphan). Auto-resolves
/// (`ack_open_alerts`) the moment attribution returns. Mirrors the
/// `check_user_traffic_limits` fire/resolve idiom + per-server `(kind,
/// server_id)` dedup.
///
/// Thresholds: a 15-minute window (≥3 poll ticks at the 5-min cadence) so a
/// transient one-tick gap right after a sing-box restart does NOT fire; a
/// 5-connection floor so a near-idle node isn't flagged.
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
            // Not stalled → auto-resolve any open alert for this server.
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
        // Stalled — fire (idempotent: insert_alert_if_no_unacked dedups on
        // the (kind, server_id) pair; a no-op while the alert is open).
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

/// Detect + alert on per-user «subscription fetched but no traffic followed»
/// (2026-06-16). Fires `user.sub_no_traffic:<id>` (warning, not server-scoped)
/// when a previously-active user re-fetched their `/sub` subscription ≥GRACE
/// ago but has had ZERO attributed traffic since — the silent signature of an
/// issued config that no longer connects. The `fp=chrome` DPI breakage was
/// exactly this shape: clients re-imported the sub and failed to dial, with
/// NO server-side error to catch. Auto-resolves the moment traffic returns
/// (or the fetch ages past the lookback and the user leaves the violation
/// set). Mirrors `check_attribution_stall`'s fire/resolve idiom + the
/// per-user `user.traffic_limit` dedup-via-kind-suffix pattern.
///
/// Thresholds: GRACE 45m (a just-fetched user is still importing/setting up;
/// no traffic by 45m is the real signal, not impatience), LOOKBACK 6h (only
/// recent re-imports are actionable), ACTIVE 7d (regression gate — flag
/// known-good users who broke, not brand-new never-connected ones).
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

    // Auto-resolve sweep: ack any OPEN alert whose subject is no longer in
    // violation (traffic resumed, or the fetch aged out of the lookback).
    // The subject universe here is "users holding an open alert of this
    // kind", not the full user list — symmetric with the attribution-stall
    // recovery branch but keyed off the kind suffix.
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

    // Fire (idempotent: insert_alert_if_no_unacked dedups on the (kind, NULL)
    // pair — a no-op while the alert is open).
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

/// Format a byte count as «GiB with one decimal» for short alert
/// summaries. `1610612736 → "1.5 GiB"`. Used by C3 traffic-limit
/// alerts; not exported because the formatting is specific to that
/// caller (e.g. it never says "MB" — the limit is always GiB-range).
pub(crate) fn bytes_as_gib_text(b: u64) -> String {
    let gib = (b as f64) / (1024.0 * 1024.0 * 1024.0);
    format!("{gib:.1} GiB")
}
