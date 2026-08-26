use std::time::Duration;

use vpnctl_inventory::SqliteInventory;

use super::diff::{SINGBOX_LOG_TRIGGER_BYTES, diff_rows};
use super::fingerprint_drift::check_fingerprint_drift;
use super::remediation::{Remediation, auto_remediate_alert};
use super::specialized_checks::{
    check_attribution_stall, check_sub_fetch_without_traffic, check_user_traffic_limits,
};

/// Default cadence: same as the probe poller. There's no point
/// scanning faster than the probe writes.
pub(crate) const DEFAULT_INTERVAL_SECS: u64 = 10 * 60;

/// Spawn the health-monitor task. Returns the [`tokio::task::JoinHandle`]
/// for test/abort symmetry with the other pollers.
pub fn spawn_health_monitor(inv: SqliteInventory) -> tokio::task::JoinHandle<()> {
    use tokio::time::{MissedTickBehavior, interval};

    // `> 0` guard + warn-on-bad lives in `config::parse_positive_secs`:
    // `interval(Duration::from_secs(0))` panics → monitor crash-loop.
    let interval_secs = crate::config::parse_positive_secs(
        "VPNCTLD_HEALTH_MONITOR_INTERVAL_SECS",
        DEFAULT_INTERVAL_SECS,
    );

    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(interval_secs));
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        tick.tick().await; // drop immediate first fire
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

/// Single sweep: for each sing-box server in inventory, fetch the
/// latest two `node_health` rows and diff them. Public so tests can
/// invoke without going through the spawn loop.
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
        // Same filter as node_probe_poller — using the shared helper
        // so the two surfaces never disagree on what's in scope.
        if !crate::node_probe_poller::probeable(server) {
            continue;
        }
        // Two newest rows are enough for the diff. Looking back 24h is
        // overkill but `recent_node_health_for_server` is the only
        // existing API; we slice off the top two below.
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
            // Seed snapshot or no data — diff requires two samples.
            continue;
        }
        // recent_node_health_for_server returns newest-first; we want
        // (prev, cur) = (rows[1], rows[0]).
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
            // A level-trigger catches a daemon that starts while the log
            // is already oversized. Once the condition has been recorded,
            // though, a manual ack must not reopen + re-push it every ten
            // minutes while the same high spell continues. A real
            // below-threshold recovery resets this history gate.
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
            // payload is always built via `serde_json::json!{}` literal,
            // so serialization cannot fail in practice. But silently
            // dropping the context (`.ok()`) on the rare error would
            // break the detail-expander promise in migration 0011.
            // Surface failure at warn + fall back to "{}" so the alert
            // row still gets inserted with structured (if empty) JSON.
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
            // Recovery events (alerts-cleanup 2026-06-10) first CLOSE
            // their paired condition alert, then land pre-acked: the
            // good news belongs in history (`?show=all`), not in the
            // open feed demanding a manual ack. Condition alerts keep
            // the original open-insert path.
            let should_insert = if let Some(resolved_kind) = ev.resolves {
                match inv.ack_open_alerts(resolved_kind, Some(&server.id)).await {
                    // A zero-row ack is ambiguous: the condition may
                    // never have fired, OR its warning was already
                    // acknowledged manually. Preserve the latter's
                    // recovery history and edit-on-recover Telegram
                    // path, while still dropping a true orphan boundary.
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
                        // A hysteresis-boundary crossing can happen
                        // without the trigger ever having fired (for
                        // example disk 88% → 84% after daemon startup).
                        // Do not create an orphan green recovery row or
                        // Telegram message.
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
                        // Audit the actual mutation (review 2026-06-10):
                        // node_probe_poller's auto-ack sets the
                        // convention — without this row the unified
                        // timeline shows fire(*.down) + fire(*.up) but
                        // silently loses WHO closed the down alert.
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
            let insert_res = if ev.resolves.is_some() {
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
                    // Mirror into audit_log so /admin/audit's
                    // unified timeline includes alert firings.
                    // Surface audit-write failure at warn — silent drop
                    // would make the audit timeline lose the firing trail
                    // with zero log signal (review-agent caught this on
                    // the burst sweep).
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
                    // Push the localized message (best-effort). These
                    // diff-events (sing-box / fail2ban / disk / mem /
                    // log up+down) were previously dashboard-only; the
                    // notification-normalization work pushes them too,
                    // rendered in the operator's language.
                    let subject = crate::node_probe_poller::server_subject(inv, &server.id).await;
                    if let Some(resolves) = ev.resolves {
                        // Recovery event (`*.up` / `*.recovered`): EDIT the
                        // original 🔴 condition message to 🟢 instead of
                        // posting a second message (edit-on-recover).
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
                        // A newly-open condition gets exactly one automatic
                        // attempt. Success emits only the green
                        // "fixed automatically" notification; failure keeps
                        // this alert open and pushes the normal warning.
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
                        if !fixed {
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
                Ok(None) => {} // condition is already open; quiet idempotent no-op
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
    // C3 — user-traffic-limit crossing alert. Runs after the per-
    // server diff loop so a single tick processes both infra +
    // per-user signals. Fire-once-per-condition via
    // insert_alert_if_no_unacked; recovery (auto-ack when user drops
    // below threshold) deferred to a later bundle to keep this
    // surface tight.
    if let Err(e) = check_user_traffic_limits(inv).await {
        tracing::warn!(
            target = "vpnctld::health_monitor",
            error = %e,
            "check_user_traffic_limits failed; alert pass skipped this tick"
        );
    }
    // C2 — stale-fingerprint detection (audit 2026-05-22). For each
    // server with a pinned `trusted_host_fingerprint`, re-run
    // `ssh-keyscan` and compare. Mismatch = either legitimate key
    // rotation OR active MITM — both warrant operator attention.
    // Skipped when no fingerprint is pinned (the wizard handles
    // first-pin via TOFU; the drift check only meaningful after
    // there's something to compare against).
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
