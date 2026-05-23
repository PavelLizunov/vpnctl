//! Phase G — operator-facing infra alerts driven by `node_health`.
//!
//! Sits ON TOP OF the Phase H probe pipeline. The probe (chunk 1)
//! collects raw metrics over SSH; the poller (chunk 4) INSERTs one
//! `node_health` row per tick per server; THIS module diffs the latest
//! two rows per server and emits an `admin_alerts` row when a
//! state-change crosses a threshold the operator cares about.
//!
//! # Why a separate poller (not inline in `node_probe_poller`)
//!
//! Failure isolation. If the alert state-machine has a bug, the probe
//! data keeps flowing. If the probe SSH fails on one server, the
//! state-machine still gets to inspect ALL servers (including the
//! ones the probe succeeded for). They share the cadence —
//! `VPNCTLD_HEALTH_MONITOR_INTERVAL_SECS`, default 10 min, matching
//! the probe interval — so we don't waste cycles diffing the same
//! row twice.
//!
//! # State source
//!
//! `inv.recent_node_health_for_server(id, 1h)` returns up to ~6 rows
//! per server at the 10-min cadence. We inspect the newest two:
//!
//!   * **First row only** (single snapshot for this server) → seed,
//!     no alert. The diff requires two samples.
//!   * **No rows at all** → server is being probed but the row hasn't
//!     landed yet (or every probe has failed). No alert here — Phase G
//!     chunk 2 will add `server.unreachable` after N consecutive
//!     missing-row ticks, that's the right surface for "we can't
//!     measure this node at all".
//!
//! # Detection rules (this chunk)
//!
//! | Condition | Severity | Alert kind |
//! |---|---|---|
//! | sing_box_active flipped `true → false` | critical | `server.singbox.down` |
//! | sing_box_active flipped `false → true` | info | `server.singbox.up` |
//! | fail2ban_active flipped `true → false` | warning | `server.fail2ban.down` |
//! | fail2ban_active flipped `false → true` | info | `server.fail2ban.up` |
//! | disk_pct crossed 90 going up | warning | `server.disk.pressure` |
//! | disk_pct dropped below 85 (hysteresis) | info | `server.disk.recovered` |
//! | mem_used_pct crossed 95 going up | warning | `server.mem.pressure` |
//! | mem_used_pct dropped below 90 (hysteresis) | info | `server.mem.recovered` |
//! | sing_box_log_bytes crossed 500 MiB going up | warning | `server.singbox.log.too_big` |
//!
//! Hysteresis on the disk/mem thresholds (90 vs 85, 95 vs 90) prevents
//! flapping: a node hovering exactly at 90.0% disk would otherwise
//! emit pressure+recovered+pressure… on every probe tick. The
//! recovery threshold is set ~5 pp below the trigger so a brief dip
//! doesn't reset the alert state.
//!
//! # Future chunks (NOT in this commit)
//!
//! - **chunk 2**: `server.unreachable` after N consecutive probe failures.
//! - **chunk 2**: `server.fail2ban.banned_self` (parse `fail2ban-client
//!   status sshd` + match our IP against the bans list).
//! - **chunk 3**: webhook transport. Stub'd via env
//!   `VPNCTLD_NOTIFY_WEBHOOK_URL` — when set, alerts also POST a
//!   small JSON to that URL (Telegram bot / ntfy.sh / generic).
//!   Pavel must pick the target before this chunk lands.

use std::time::Duration;

use vpnctl_inventory::{NodeHealthRow, SqliteInventory};

/// Default cadence: same as the probe poller. There's no point
/// scanning faster than the probe writes.
const DEFAULT_INTERVAL_SECS: u64 = 10 * 60;

/// Disk-pressure thresholds, with 5-pp hysteresis.
const DISK_PRESSURE_TRIGGER_PCT: u8 = 90;
const DISK_PRESSURE_RECOVER_PCT: u8 = 85;

/// Memory-pressure thresholds.
const MEM_PRESSURE_TRIGGER_PCT: u8 = 95;
const MEM_PRESSURE_RECOVER_PCT: u8 = 90;

/// sing-box log size threshold (bytes). 500 MiB — Pavel's earlier
/// disk-fill concern. The logrotate fragment we install in
/// `kernels::sing_box::ensure_installed` caps growth, but a freshly
/// bootstrapped node before the first rotation OR a node where the
/// fragment got blown away will eventually trip this.
const SINGBOX_LOG_TRIGGER_BYTES: u64 = 500 * 1024 * 1024;

/// One state-change detected by `diff_rows`. Materialised into an
/// `admin_alerts` row + `audit_log` row by the caller. Exposed as a
/// `pub` data type so the spawn-loop is testable WITHOUT a real
/// inventory — feed in two `NodeHealthRow`s, assert the Vec of
/// `AlertEvent`s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertEvent {
    pub kind: &'static str,
    pub severity: &'static str,
    pub summary: String,
    /// Serialized as `payload_json` — small JSON object with the
    /// crossing thresholds + prior/current values for the audit row.
    pub payload: serde_json::Value,
}

/// Compute mem-used percentage from a `NodeHealthRow`. Mirrors
/// `Probe::mem_used_pct` but operates on the stored row.
fn mem_used_pct(row: &NodeHealthRow) -> Option<u8> {
    let avail = row.mem_available_mib?;
    let total = row.mem_total_mib?;
    if total == 0 {
        return None;
    }
    let used_pct = 100u64.saturating_sub(avail.saturating_mul(100) / total);
    u8::try_from(used_pct.min(100)).ok()
}

/// Compute disk-used percentage from a `NodeHealthRow`.
fn disk_pct(row: &NodeHealthRow) -> Option<u8> {
    let used = row.disk_used_mib?;
    let total = row.disk_total_mib?;
    if total == 0 {
        return None;
    }
    let pct = used.saturating_mul(100) / total;
    u8::try_from(pct.min(100)).ok()
}

/// Pure diff: given the previous probe row and the current one,
/// return every state-change alert the operator should see.
///
/// Stateless — same input always produces the same output. Caller
/// is responsible for "did we already emit this same alert in the
/// last few ticks" dedup (the table-level WHERE-not-acked on the
/// dashboard handles user-visible duplication; firing the same
/// `*.pressure` repeatedly is intentional so the operator sees the
/// condition has not been resolved).
pub fn diff_rows(prev: &NodeHealthRow, cur: &NodeHealthRow) -> Vec<AlertEvent> {
    let mut out: Vec<AlertEvent> = Vec::new();

    // ── service state flips ────────────────────────────────────────
    if let (Some(p), Some(c)) = (prev.sing_box_active, cur.sing_box_active) {
        if p && !c {
            out.push(AlertEvent {
                kind: "server.singbox.down",
                severity: "critical",
                summary: "sing-box is no longer active".into(),
                payload: serde_json::json!({"prior": p, "current": c}),
            });
        } else if !p && c {
            out.push(AlertEvent {
                kind: "server.singbox.up",
                severity: "info",
                summary: "sing-box recovered to active".into(),
                payload: serde_json::json!({"prior": p, "current": c}),
            });
        }
    }
    if let (Some(p), Some(c)) = (prev.fail2ban_active, cur.fail2ban_active) {
        if p && !c {
            out.push(AlertEvent {
                kind: "server.fail2ban.down",
                severity: "warning",
                summary: "fail2ban is no longer active".into(),
                payload: serde_json::json!({"prior": p, "current": c}),
            });
        } else if !p && c {
            out.push(AlertEvent {
                kind: "server.fail2ban.up",
                severity: "info",
                summary: "fail2ban recovered to active".into(),
                payload: serde_json::json!({"prior": p, "current": c}),
            });
        }
    }

    // ── disk pressure (hysteretic) ─────────────────────────────────
    if let (Some(p), Some(c)) = (disk_pct(prev), disk_pct(cur)) {
        if p < DISK_PRESSURE_TRIGGER_PCT && c >= DISK_PRESSURE_TRIGGER_PCT {
            out.push(AlertEvent {
                kind: "server.disk.pressure",
                severity: "warning",
                summary: format!("disk usage crossed {DISK_PRESSURE_TRIGGER_PCT}% ({p}% → {c}%)"),
                payload: serde_json::json!({
                    "prior_pct": p, "current_pct": c, "threshold": DISK_PRESSURE_TRIGGER_PCT
                }),
            });
        } else if p >= DISK_PRESSURE_TRIGGER_PCT && c < DISK_PRESSURE_RECOVER_PCT {
            out.push(AlertEvent {
                kind: "server.disk.recovered",
                severity: "info",
                summary: format!(
                    "disk usage dropped back under {DISK_PRESSURE_RECOVER_PCT}% ({p}% → {c}%)"
                ),
                payload: serde_json::json!({
                    "prior_pct": p, "current_pct": c, "recover_threshold": DISK_PRESSURE_RECOVER_PCT
                }),
            });
        }
    }

    // ── memory pressure (hysteretic) ───────────────────────────────
    if let (Some(p), Some(c)) = (mem_used_pct(prev), mem_used_pct(cur)) {
        if p < MEM_PRESSURE_TRIGGER_PCT && c >= MEM_PRESSURE_TRIGGER_PCT {
            out.push(AlertEvent {
                kind: "server.mem.pressure",
                severity: "warning",
                summary: format!("memory usage crossed {MEM_PRESSURE_TRIGGER_PCT}% ({p}% → {c}%)"),
                payload: serde_json::json!({
                    "prior_pct": p, "current_pct": c, "threshold": MEM_PRESSURE_TRIGGER_PCT
                }),
            });
        } else if p >= MEM_PRESSURE_TRIGGER_PCT && c < MEM_PRESSURE_RECOVER_PCT {
            out.push(AlertEvent {
                kind: "server.mem.recovered",
                severity: "info",
                summary: format!(
                    "memory usage dropped back under {MEM_PRESSURE_RECOVER_PCT}% ({p}% → {c}%)"
                ),
                payload: serde_json::json!({
                    "prior_pct": p, "current_pct": c, "recover_threshold": MEM_PRESSURE_RECOVER_PCT
                }),
            });
        }
    }

    // ── sing-box log size ──────────────────────────────────────────
    if let (Some(p), Some(c)) = (prev.sing_box_log_bytes, cur.sing_box_log_bytes) {
        if p < SINGBOX_LOG_TRIGGER_BYTES && c >= SINGBOX_LOG_TRIGGER_BYTES {
            out.push(AlertEvent {
                kind: "server.singbox.log.too_big",
                severity: "warning",
                summary: format!("sing-box log size crossed 500 MiB ({} → {} bytes)", p, c),
                payload: serde_json::json!({
                    "prior_bytes": p, "current_bytes": c,
                    "threshold_bytes": SINGBOX_LOG_TRIGGER_BYTES
                }),
            });
        }
    }

    out
}

/// Spawn the health-monitor task. Returns the [`tokio::task::JoinHandle`]
/// for test/abort symmetry with the other pollers.
pub fn spawn_health_monitor(inv: SqliteInventory) -> tokio::task::JoinHandle<()> {
    use tokio::time::{MissedTickBehavior, interval};

    let interval_secs: u64 = std::env::var("VPNCTLD_HEALTH_MONITOR_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_INTERVAL_SECS);

    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(interval_secs));
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        tick.tick().await; // drop immediate first fire
        loop {
            tick.tick().await;
            if let Err(e) = scan_once(&inv).await {
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
    let servers = inv.list_servers().await?;
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
        for ev in diff_rows(prev, cur) {
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
            match inv
                .insert_alert(
                    ev.kind,
                    Some(&server.id),
                    ev.severity,
                    &ev.summary,
                    payload_str.as_deref(),
                )
                .await
            {
                Ok(alert_id) => {
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
                }
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
    Ok(())
}

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
/// **Not in scope for this fn:** auto-ack on drop-below-threshold.
/// Once Telegram fires, the operator acks via the web button OR the
/// alert ages off after manual ack. If the user crosses again next
/// month, a fresh alert fires (since the previous one is acked, the
/// partial unique no longer blocks).
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
        if pct < u64::from(threshold_pct) {
            continue;
        }
        // Format used / limit as GiB-with-one-decimal for the Telegram
        // line. Doing the format string Rust-side rather than relying
        // on TelegramSink's formatting because we want the user-facing
        // message to be short + scannable («user X: 95% / 18.5 of
        // 20 GiB monthly»).
        let used_gib = bytes_as_gib_text(used);
        let lim_gib = bytes_as_gib_text(lim);
        let kind = format!("user.traffic_limit:{}", uid.0);
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
                // admin_alerts row is the source of truth.
                crate::node_probe_poller::push_alert(inv, &kind, "warning", &summary).await;
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

/// Format a byte count as «GiB with one decimal» for short alert
/// summaries. `1610612736 → "1.5 GiB"`. Used by C3 traffic-limit
/// alerts; not exported because the formatting is specific to that
/// caller (e.g. it never says "MB" — the limit is always GiB-range).
fn bytes_as_gib_text(b: u64) -> String {
    let gib = (b as f64) / (1024.0 * 1024.0 * 1024.0);
    format!("{gib:.1} GiB")
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use vpnctl_core::ServerId;

    #[allow(clippy::too_many_arguments)]
    fn row(
        mins_ago: i64,
        sb: Option<bool>,
        f2b: Option<bool>,
        disk_u: Option<u64>,
        disk_t: Option<u64>,
        mem_a: Option<u64>,
        mem_t: Option<u64>,
        log_b: Option<u64>,
    ) -> NodeHealthRow {
        NodeHealthRow {
            ts: Utc.with_ymd_and_hms(2026, 5, 17, 22, 0, 0).unwrap()
                - chrono::Duration::minutes(mins_ago),
            server_id: ServerId("test".into()),
            sing_box_active: sb,
            fail2ban_active: f2b,
            disk_used_mib: disk_u,
            disk_total_mib: disk_t,
            mem_available_mib: mem_a,
            mem_total_mib: mem_t,
            load_1min_x100: None,
            listening_ports_json: None,
            sing_box_log_bytes: log_b,
        }
    }

    #[test]
    fn diff_rows_singbox_down_fires_critical() {
        let prev = row(10, Some(true), None, None, None, None, None, None);
        let cur = row(0, Some(false), None, None, None, None, None, None);
        let evs = diff_rows(&prev, &cur);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, "server.singbox.down");
        assert_eq!(evs[0].severity, "critical");
        assert!(evs[0].summary.contains("sing-box"));
    }

    #[test]
    fn diff_rows_singbox_up_fires_info() {
        let prev = row(10, Some(false), None, None, None, None, None, None);
        let cur = row(0, Some(true), None, None, None, None, None, None);
        let evs = diff_rows(&prev, &cur);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, "server.singbox.up");
        assert_eq!(evs[0].severity, "info");
    }

    #[test]
    fn diff_rows_no_change_emits_nothing() {
        let prev = row(
            10,
            Some(true),
            Some(true),
            Some(50),
            Some(100),
            Some(80),
            Some(100),
            Some(1024),
        );
        let cur = row(
            0,
            Some(true),
            Some(true),
            Some(50),
            Some(100),
            Some(80),
            Some(100),
            Some(1024),
        );
        assert!(diff_rows(&prev, &cur).is_empty());
    }

    #[test]
    fn diff_rows_disk_pressure_crosses_90_fires() {
        // 89% → 91%
        let prev = row(10, None, None, Some(89), Some(100), None, None, None);
        let cur = row(0, None, None, Some(91), Some(100), None, None, None);
        let evs = diff_rows(&prev, &cur);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, "server.disk.pressure");
        assert_eq!(evs[0].severity, "warning");
    }

    #[test]
    fn diff_rows_disk_hysteresis_no_flap_at_88_pct() {
        // Already at 91 (in pressure state), drops to 88 — still in
        // the hysteresis dead-zone (85–90), NO recovery alert.
        let prev = row(10, None, None, Some(91), Some(100), None, None, None);
        let cur = row(0, None, None, Some(88), Some(100), None, None, None);
        assert!(diff_rows(&prev, &cur).is_empty());
    }

    #[test]
    fn diff_rows_disk_recovered_under_85_fires_info() {
        // 91 → 84 — past the recovery threshold.
        let prev = row(10, None, None, Some(91), Some(100), None, None, None);
        let cur = row(0, None, None, Some(84), Some(100), None, None, None);
        let evs = diff_rows(&prev, &cur);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, "server.disk.recovered");
        assert_eq!(evs[0].severity, "info");
    }

    #[test]
    fn diff_rows_mem_pressure_crosses_95_fires() {
        // mem_avail 6 / total 100 → mem_used 94%
        let prev = row(10, None, None, None, None, Some(6), Some(100), None);
        // mem_avail 4 / total 100 → mem_used 96%
        let cur = row(0, None, None, None, None, Some(4), Some(100), None);
        let evs = diff_rows(&prev, &cur);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, "server.mem.pressure");
    }

    #[test]
    fn diff_rows_singbox_log_crosses_500mib_fires() {
        let prev = row(
            10,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(400 * 1024 * 1024),
        );
        let cur = row(
            0,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(600 * 1024 * 1024),
        );
        let evs = diff_rows(&prev, &cur);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, "server.singbox.log.too_big");
    }

    #[test]
    fn diff_rows_unknown_prior_emits_nothing() {
        // Probe parser couldn't get sing_box state on the prior tick
        // → can't tell whether this is a flip or a steady state. Don't
        // emit a spurious "down" just because we lost visibility.
        let prev = row(10, None, None, None, None, None, None, None);
        let cur = row(0, Some(false), None, None, None, None, None, None);
        assert!(diff_rows(&prev, &cur).is_empty());
    }

    #[test]
    fn diff_rows_multi_signal_combines() {
        // sing-box down + disk crossing 90 in one snapshot.
        let prev = row(10, Some(true), None, Some(80), Some(100), None, None, None);
        let cur = row(0, Some(false), None, Some(95), Some(100), None, None, None);
        let evs = diff_rows(&prev, &cur);
        let kinds: Vec<&str> = evs.iter().map(|e| e.kind).collect();
        assert!(kinds.contains(&"server.singbox.down"));
        assert!(kinds.contains(&"server.disk.pressure"));
    }

    #[test]
    fn bytes_as_gib_formats_one_decimal() {
        // 2 GiB = 2 * 1024^3 = 2_147_483_648
        assert_eq!(bytes_as_gib_text(2_147_483_648), "2.0 GiB");
        // Halfway between 1 and 2 GiB.
        assert_eq!(bytes_as_gib_text(1_610_612_736), "1.5 GiB");
        // 0 → "0.0 GiB" (don't special-case; uniform shape simplifies
        // the summary line).
        assert_eq!(bytes_as_gib_text(0), "0.0 GiB");
    }

    // C3 — fire-once contract for `check_user_traffic_limits`.
    // Uses a real SqliteInventory in tempdir to round-trip the
    // partial-UNIQUE dedup index.
    use tempfile::TempDir;
    use vpnctl_core::{User, UserId};
    use vpnctl_inventory::SqliteInventory;

    async fn fresh_inv() -> (TempDir, SqliteInventory) {
        let dir = TempDir::new().unwrap();
        let inv = SqliteInventory::open(&dir.path().join("inv.db"))
            .await
            .unwrap();
        (dir, inv)
    }

    fn user_with_id(id: &str) -> User {
        User {
            id: UserId(id.into()),
            uuid: format!("00000000-0000-0000-0000-{:012}", 7),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        }
    }

    #[tokio::test]
    async fn check_user_traffic_limits_skips_users_under_threshold() {
        let (_dir, inv) = fresh_inv().await;
        inv.add_user(&user_with_id("u")).await.unwrap();
        // 80% threshold, limit 100 GiB, used 1 GiB → 1% < 80%.
        inv.set_user_traffic_limit(
            &UserId("u".into()),
            Some(100 * 1024 * 1024 * 1024),
            Some(80),
        )
        .await
        .unwrap();
        check_user_traffic_limits(&inv).await.unwrap();
        // No alert row should have been inserted.
        let alerts = inv.recent_alerts(10, true).await.unwrap();
        assert!(
            alerts.is_empty(),
            "user under threshold must not produce an alert; got {alerts:?}"
        );
    }

    #[tokio::test]
    async fn check_user_traffic_limits_fires_once_per_condition() {
        let (_dir, inv) = fresh_inv().await;
        // FK chain: vpn_connection_stats(server_id) → servers(id),
        // and (user_id) → users(id). Seed both before recording.
        inv.add_server(&vpnctl_core::Server {
            id: ServerId("dummy".into()),
            address: "127.0.0.1".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![vpnctl_core::KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
        inv.add_user(&user_with_id("heavy")).await.unwrap();
        // 50% threshold, limit 100 bytes (tiny — easy to push past).
        inv.set_user_traffic_limit(&UserId("heavy".into()), Some(100), Some(50))
            .await
            .unwrap();
        // Seed bandwidth so used = 90 bytes (90% > 50% threshold).
        // Same writer the clash-api ingest uses — keeps zero drift
        // between test target and production target.
        inv.record_vpn_stats(
            &ServerId("dummy".into()),
            &[vpnctl_inventory::VpnStatsDelta {
                user_id: Some(UserId("heavy".into())),
                upload_bytes: 50,
                download_bytes: 40,
                active_connections: 0,
            }],
        )
        .await
        .unwrap();
        // First scan: must fire one alert.
        check_user_traffic_limits(&inv).await.unwrap();
        let alerts1 = inv.recent_alerts(10, true).await.unwrap();
        assert_eq!(alerts1.len(), 1, "must fire one alert on threshold cross");
        assert_eq!(alerts1[0].kind, "user.traffic_limit:heavy");
        assert_eq!(alerts1[0].severity, "warning");
        // Second scan immediately after: NO new alert (partial-UNIQUE
        // dedup). The single previously-fired alert is still the only
        // row.
        check_user_traffic_limits(&inv).await.unwrap();
        let alerts2 = inv.recent_alerts(10, true).await.unwrap();
        assert_eq!(
            alerts2.len(),
            1,
            "second scan must not fire duplicate alert; got {alerts2:?}"
        );
    }
}
