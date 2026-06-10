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
    /// For recovery events (`*.up` / `*.recovered`): the kind of the
    /// PAIRED condition alert this event closes. The dispatch loop
    /// auto-acks any open alert of that kind for the same server and
    /// inserts the recovery row pre-acked (alerts-cleanup 2026-06-10):
    /// before this, a down→up cycle left TWO open rows — the stale
    /// `*.down` (condition already gone) and an `*.up` info row that
    /// demanded a manual ack just to say «everything is fine».
    /// `None` for condition alerts (down / pressure / too_big).
    pub resolves: Option<&'static str>,
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
                resolves: None,
                severity: "critical",
                summary: "sing-box is no longer active".into(),
                payload: serde_json::json!({"prior": p, "current": c}),
            });
        } else if !p && c {
            out.push(AlertEvent {
                kind: "server.singbox.up",
                resolves: Some("server.singbox.down"),
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
                resolves: None,
                severity: "warning",
                summary: "fail2ban is no longer active".into(),
                payload: serde_json::json!({"prior": p, "current": c}),
            });
        } else if !p && c {
            out.push(AlertEvent {
                kind: "server.fail2ban.up",
                resolves: Some("server.fail2ban.down"),
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
                resolves: None,
                severity: "warning",
                summary: format!("disk usage crossed {DISK_PRESSURE_TRIGGER_PCT}% ({p}% → {c}%)"),
                payload: serde_json::json!({
                    "prior_pct": p, "current_pct": c, "threshold": DISK_PRESSURE_TRIGGER_PCT
                }),
            });
        } else if p >= DISK_PRESSURE_TRIGGER_PCT && c < DISK_PRESSURE_RECOVER_PCT {
            out.push(AlertEvent {
                kind: "server.disk.recovered",
                resolves: Some("server.disk.pressure"),
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
                resolves: None,
                severity: "warning",
                summary: format!("memory usage crossed {MEM_PRESSURE_TRIGGER_PCT}% ({p}% → {c}%)"),
                payload: serde_json::json!({
                    "prior_pct": p, "current_pct": c, "threshold": MEM_PRESSURE_TRIGGER_PCT
                }),
            });
        } else if p >= MEM_PRESSURE_TRIGGER_PCT && c < MEM_PRESSURE_RECOVER_PCT {
            out.push(AlertEvent {
                kind: "server.mem.recovered",
                resolves: Some("server.mem.pressure"),
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
                resolves: None,
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
            // Recovery events (alerts-cleanup 2026-06-10) first CLOSE
            // their paired condition alert, then land pre-acked: the
            // good news belongs in history (`?show=all`), not in the
            // open feed demanding a manual ack. Condition alerts keep
            // the original open-insert path.
            if let Some(resolved_kind) = ev.resolves {
                match inv.ack_open_alerts(resolved_kind, Some(&server.id)).await {
                    Ok(0) => {} // paired alert was never open (or already acked)
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
                    }
                    Err(e) => {
                        tracing::warn!(
                            target = "vpnctld::health_monitor",
                            server = %server.id.0,
                            resolved_kind,
                            error = %e,
                            "auto-resolve ack failed; stale condition alert stays open"
                        );
                    }
                }
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
            } else {
                inv.insert_alert(
                    ev.kind,
                    Some(&server.id),
                    ev.severity,
                    &ev.summary,
                    payload_str.as_deref(),
                )
                .await
            };
            match insert_res {
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
    Ok(())
}

/// Per-tick scan for `server.fingerprint.drift`. For each server with
/// a pinned `trusted_host_fingerprint`, fetches ALL the host keys the
/// server currently serves (`fetch_all_fingerprints`) and fires a
/// `warning`-severity alert — with `{previous, observed_keys}` payload
/// + Telegram push — only when the pinned key is no longer among them.
///
/// **Membership, not single-key equality + retry (post-kg 2026-06-06).**
/// A naive «picked key == pin» compare false-fired when a single
/// `ssh-keyscan` returned only a SUBSET of the keys (a per-algorithm
/// probe dropped under packet loss) and the dropped one was the pinned
/// key type. Asking «is the pin still AMONG the served keys?» plus a
/// short retry (a real change is absent from EVERY scan; a transient
/// incomplete scan recovers within a retry) removes the false positive
/// while preserving genuine rotation / MITM detection.
///
/// **Why warning, not critical:** legitimate SSH host-key rotation
/// is a normal operator workflow (kernel upgrade, distro reinstall,
/// VPS provider migration). The drift could also be an active MITM
/// — equally bad — but the alert can't tell the difference. Operator
/// triages, ack-and-rotate via the existing /admin/servers/{id}
/// set-fingerprint form OR ignores if expected.
///
/// **Servers without a pinned fingerprint are skipped** — there's
/// nothing to compare against; first-time pin goes through the
/// wizard's TOFU path or the operator's explicit «auto via ssh-
/// keyscan» button.
///
/// **Servers behind a ProxyJump are skipped** — `ssh-keyscan` makes
/// a direct TCP connection and doesn't honour ssh_config's
/// ProxyJump rules. Pinning those servers' fingerprints today
/// happens via the operator manually proxying; the daemon's drift
/// check stays silent rather than emit false-positive «unreachable»
/// alerts for jump-only hosts. Future work: route through
/// `ssh_subprocess` with the same ProxyJump config the probe uses.
///
/// **Cadence:** runs on every `scan_once` tick (10 min default).
/// `ssh-keyscan` on 3 servers takes < 1 second total; not worth
/// a separate cron.
pub async fn check_fingerprint_drift(
    inv: &SqliteInventory,
    servers: &[vpnctl_core::Server],
) -> Result<(), vpnctl_inventory::SqliteInventoryError> {
    for server in servers {
        // Skip if no pin to compare against.
        let Some(pinned) = server.trusted_host_fingerprint.as_deref() else {
            continue;
        };
        // Skip ProxyJump targets — see doc-comment.
        if server.jump_via.is_some() {
            continue;
        }
        // Skip if address is malformed enough that ssh-keyscan
        // would obviously fail. (Defensive — keeps the log clean.)
        if server.address.is_empty() {
            continue;
        }
        // Robust drift detection (post-kg 2026-06-06): fetch ALL of
        // the server's host keys and ask «is the pinned key still
        // among them?» rather than comparing one picked key against
        // the pin. A single `ssh-keyscan` can return only a SUBSET of
        // the keys under packet loss; if the dropped one happens to be
        // the pinned key type, a naive single-key compare false-fires.
        // We retry a few times and let `decide_drift` rule: a real key
        // change is absent from EVERY scan, while a transient
        // incomplete scan recovers within a retry. Worst case for a
        // genuinely-drifted or unreachable server is ~3 keyscans + 2
        // backoff sleeps serially on this tick — fine for a handful of
        // servers; revisit (concurrency / cap) if the fleet grows.
        let kind = format!("server.fingerprint.drift:{}", server.id.0);
        const DRIFT_SCAN_ATTEMPTS: usize = 3;
        let mut attempts: Vec<Option<Vec<String>>> = Vec::with_capacity(DRIFT_SCAN_ATTEMPTS);
        for attempt in 0..DRIFT_SCAN_ATTEMPTS {
            if attempt > 0 {
                // Brief backoff between retries — a transient
                // per-algorithm probe drop clears in seconds. Off the
                // hot path: only servers whose pin didn't match the
                // first scan ever reach a second attempt.
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            let addr = server.address.clone();
            let port = server.ssh_port;
            // ssh-keyscan is sync (shells out); spawn_blocking keeps
            // it off the tokio scheduler.
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
            // Early exit: the pinned key is already served — no need to
            // spend the remaining attempts. Keeps the healthy-server
            // common case at one keyscan per tick, as before.
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
                // Auto-recovery: the pinned key is still served. If an
                // operator accepted a new key via the web UI, or it
                // «recovered» on its own (key rotated back), close any
                // open drift alert. Silent ack (no `*.recovered` info
                // alert) — the audit_log keeps the timeline.
                match inv.ack_open_alerts(&kind, Some(&server.id)).await {
                    Ok(0) => {} // No open alert; nothing to recover.
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
                continue; // No drift, no fire.
            }
            // No scan succeeded at all — can't tell drift from an
            // outage. Stay silent and try again next tick (same posture
            // as the old per-scan error `continue`).
            DriftDecision::Inconclusive => continue,
            // Pinned key absent from every successful scan → real drift.
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
        });
        let payload_str = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string());
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
                crate::node_probe_poller::push_alert(inv, &kind, "warning", &summary).await;
            }
            Ok(None) => {
                // Already-open drift alert for this server. The
                // operator hasn't triaged yet; no point spamming
                // the same alert every 10 min.
            }
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

/// True if the pinned fingerprint is among the set of fingerprints the
/// server currently serves. The drift check fires only when this is
/// false — i.e. the pinned key is no longer one of the host's keys.
/// Robust to a single `ssh-keyscan` returning a different key TYPE
/// than the one originally pinned (the `kg` 2026-06-06 false positive:
/// a scan that returned only the rsa key tripped a drift against the
/// ed25519 pin).
fn pin_is_present(pinned: &str, observed: &[String]) -> bool {
    observed.iter().any(|fp| fp.as_str() == pinned)
}

/// Outcome of evaluating one server's host-key scans against its pin.
#[derive(Debug, PartialEq)]
enum DriftDecision {
    /// At least one scan returned the pinned key — trust intact. The
    /// caller auto-recovers (acks) any open drift alert.
    Matched,
    /// Every successful scan agreed the pinned key is gone → genuine
    /// drift (rotation or MITM). `observed` is the union of all keys
    /// seen across the scans, for the alert payload.
    Drift { observed: Vec<String> },
    /// No scan succeeded at all — host unreachable / keyscan failed on
    /// every attempt. Can't distinguish drift from an outage, so the
    /// caller stays silent this tick.
    Inconclusive,
}

/// Decide whether a server's host key has drifted, given the results
/// of one-or-more `ssh-keyscan` attempts. Each element is `Some(keys)`
/// for a successful scan (the SHA256 fingerprints the host served) or
/// `None` for a failed attempt.
///
/// Rules:
///   * pin present in ANY successful scan         → [`DriftDecision::Matched`]
///   * pin absent from every successful scan,
///     and ≥1 scan succeeded                      → [`DriftDecision::Drift`]
///   * no scan succeeded                           → [`DriftDecision::Inconclusive`]
///
/// Pure (no I/O) so the false-positive contract — a transient scan
/// that omits the pinned key type must NOT fire once a later scan
/// returns it — is unit-testable without a live SSH daemon. `observed`
/// in the `Drift` arm is the de-duplicated union across scans (so the
/// payload reflects every key seen, not just the last partial scan).
fn decide_drift(pinned: &str, attempts: &[Option<Vec<String>>]) -> DriftDecision {
    let mut any_success = false;
    let mut observed: Vec<String> = Vec::new();
    for keys in attempts.iter().flatten() {
        any_success = true;
        if pin_is_present(pinned, keys) {
            return DriftDecision::Matched;
        }
        for k in keys {
            if !observed.contains(k) {
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
        assert_eq!(
            evs[0].resolves,
            Some("server.singbox.down"),
            "recovery must name the paired condition it closes"
        );
    }

    /// Alerts-cleanup 2026-06-10 pin: every recovery event resolves its
    /// paired condition kind; every condition event resolves nothing.
    /// The dispatch loop keys auto-ack + born-acked insert on this.
    #[test]
    fn diff_rows_resolves_pairing_is_complete() {
        // (prev-state, cur-state) per metric chosen to fire each kind.
        let fire = |prev: NodeHealthRow, cur: NodeHealthRow| diff_rows(&prev, &cur);
        let cases: Vec<(Vec<AlertEvent>, &str, Option<&str>)> = vec![
            (
                fire(
                    row(10, Some(true), None, None, None, None, None, None),
                    row(0, Some(false), None, None, None, None, None, None),
                ),
                "server.singbox.down",
                None,
            ),
            (
                fire(
                    row(10, None, Some(true), None, None, None, None, None),
                    row(0, None, Some(false), None, None, None, None, None),
                ),
                "server.fail2ban.down",
                None,
            ),
            (
                fire(
                    row(10, None, Some(false), None, None, None, None, None),
                    row(0, None, Some(true), None, None, None, None, None),
                ),
                "server.fail2ban.up",
                Some("server.fail2ban.down"),
            ),
            (
                fire(
                    row(10, None, None, Some(80), Some(100), None, None, None),
                    row(0, None, None, Some(95), Some(100), None, None, None),
                ),
                "server.disk.pressure",
                None,
            ),
            (
                fire(
                    row(10, None, None, Some(95), Some(100), None, None, None),
                    row(0, None, None, Some(80), Some(100), None, None, None),
                ),
                "server.disk.recovered",
                Some("server.disk.pressure"),
            ),
        ];
        for (evs, kind, resolves) in cases {
            let ev = evs
                .iter()
                .find(|e| e.kind == kind)
                .unwrap_or_else(|| panic!("{kind} did not fire"));
            assert_eq!(ev.resolves, resolves, "pairing wrong for {kind}");
        }
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
    async fn check_user_traffic_limits_auto_recovers_when_usage_drops_below() {
        // Two-tick test: tick 1 fires (90% used vs 50% threshold);
        // operator raises the limit; tick 2 must auto-ack the open
        // warning (silent recovery — no info alert, just ack).
        let (_dir, inv) = fresh_inv().await;
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
        inv.add_user(&user_with_id("rocky")).await.unwrap();
        // Tiny limit + tiny usage → 90% on tick 1.
        inv.set_user_traffic_limit(&UserId("rocky".into()), Some(100), Some(50))
            .await
            .unwrap();
        inv.record_vpn_stats(
            &ServerId("dummy".into()),
            &[vpnctl_inventory::VpnStatsDelta {
                user_id: Some(UserId("rocky".into())),
                upload_bytes: 50,
                download_bytes: 40,
                active_connections: 0,
            }],
        )
        .await
        .unwrap();
        check_user_traffic_limits(&inv).await.unwrap();
        let unacked_before: Vec<_> = inv
            .recent_alerts(10, true)
            .await
            .unwrap()
            .into_iter()
            .filter(|a| a.acked_at.is_none())
            .collect();
        assert_eq!(unacked_before.len(), 1, "tick 1 must fire one alert");

        // Operator raises the limit so pct drops from 90% to ~0%.
        inv.set_user_traffic_limit(&UserId("rocky".into()), Some(1_000_000), Some(50))
            .await
            .unwrap();
        check_user_traffic_limits(&inv).await.unwrap();
        let unacked_after: Vec<_> = inv
            .recent_alerts(10, true)
            .await
            .unwrap()
            .into_iter()
            .filter(|a| a.acked_at.is_none())
            .collect();
        assert!(
            unacked_after.is_empty(),
            "tick 2 must auto-ack the open alert; got: {unacked_after:?}"
        );
    }

    #[test]
    fn pin_is_present_true_when_pinned_ed25519_among_served_keys() {
        // The kg 2026-06-06 incident shape: a healthy scan returns
        // BOTH the rsa and the ed25519 (pinned) key. Membership holds
        // → no drift, even though the rsa fingerprint differs from the
        // pin (the old single-key compare false-fired on exactly this).
        let pinned = "SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4";
        let served = vec![
            "SHA256:szQm1QS8dN6awI29eG1hLbKah/156RmJV1EpNFqlNwc".to_string(), // rsa
            "SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4".to_string(), // ed25519 (pinned)
        ];
        assert!(pin_is_present(pinned, &served));
    }

    #[test]
    fn pin_is_present_false_when_pinned_key_absent_from_partial_scan() {
        // The exact false-positive trigger: a transient scan returned
        // ONLY the rsa key, so the ed25519 pin is absent from THIS
        // scan. Membership is correctly false — it's the retry loop in
        // check_fingerprint_drift that prevents the false fire by
        // re-scanning before concluding drift.
        let pinned = "SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4";
        let served = vec![
            "SHA256:szQm1QS8dN6awI29eG1hLbKah/156RmJV1EpNFqlNwc".to_string(), // rsa only
        ];
        assert!(!pin_is_present(pinned, &served));
    }

    #[test]
    fn pin_is_present_false_on_empty_served_set() {
        // No keys came back at all → pin is not "present"; the caller
        // treats an all-empty result as inconclusive (no fire), not as
        // a confirmed drift.
        assert!(!pin_is_present("SHA256:whatever", &[]));
    }

    #[test]
    fn pin_is_present_true_on_genuine_single_key_match() {
        let pinned = "SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4";
        let served = vec![pinned.to_string()];
        assert!(pin_is_present(pinned, &served));
    }

    #[test]
    fn decide_drift_matched_when_a_later_scan_returns_the_pin() {
        // The kg 2026-06-06 sequence: attempt 1 was a partial scan
        // that returned only the rsa key (pin absent), attempt 2
        // returned both keys (pin present). Must resolve to Matched —
        // NO drift fired. Regression guard for the whole fix: under
        // the old single-key compare this exact sequence fired.
        let pinned = "SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4";
        let attempts = vec![
            Some(vec![
                "SHA256:szQm1QS8dN6awI29eG1hLbKah/156RmJV1EpNFqlNwc".to_string(),
            ]),
            Some(vec![
                "SHA256:szQm1QS8dN6awI29eG1hLbKah/156RmJV1EpNFqlNwc".to_string(),
                pinned.to_string(),
            ]),
        ];
        assert_eq!(decide_drift(pinned, &attempts), DriftDecision::Matched);
    }

    #[test]
    fn decide_drift_inconclusive_when_every_scan_failed() {
        // Host unreachable / keyscan failed on all attempts → can't
        // distinguish drift from an outage, so don't fire.
        let attempts: Vec<Option<Vec<String>>> = vec![None, None, None];
        assert_eq!(
            decide_drift("SHA256:whatever", &attempts),
            DriftDecision::Inconclusive
        );
    }

    #[test]
    fn decide_drift_fires_when_pin_absent_from_every_successful_scan() {
        // Genuine rotation/MITM: the pin never appears in any scan that
        // succeeded (one attempt failed mid-way, which must not mask
        // the drift). Fires with the new key in the observed payload.
        let pinned = "SHA256:OLDoldOLDoldOLDoldOLDoldOLDoldOLDoldOLDoldOL";
        let newkey = "SHA256:NEWnewNEWnewNEWnewNEWnewNEWnewNEWnewNEWnewNE";
        let attempts = vec![
            Some(vec![newkey.to_string()]),
            None,
            Some(vec![newkey.to_string()]),
        ];
        assert_eq!(
            decide_drift(pinned, &attempts),
            DriftDecision::Drift {
                observed: vec![newkey.to_string()]
            }
        );
    }

    #[test]
    fn decide_drift_unions_observed_keys_across_scans_without_dupes() {
        // The fired payload reflects ALL keys seen across retries
        // (deduped, order-preserved), not just the last scan.
        let pinned = "SHA256:PINpinPINpinPINpinPINpinPINpinPINpinPINpinPI";
        let attempts = vec![
            Some(vec!["SHA256:aaa".to_string(), "SHA256:bbb".to_string()]),
            Some(vec!["SHA256:bbb".to_string(), "SHA256:ccc".to_string()]),
        ];
        assert_eq!(
            decide_drift(pinned, &attempts),
            DriftDecision::Drift {
                observed: vec![
                    "SHA256:aaa".to_string(),
                    "SHA256:bbb".to_string(),
                    "SHA256:ccc".to_string()
                ]
            }
        );
    }

    #[tokio::test]
    async fn check_fingerprint_drift_skips_servers_without_pin() {
        // Server with `trusted_host_fingerprint = None` must NOT
        // trigger an ssh-keyscan. Verified indirectly: passing a
        // server with an unreachable address (TEST-NET-1) — if we
        // were calling ssh-keyscan, the function would spend time
        // / log debug. We just assert it returns Ok quickly + no
        // alert row created.
        let (_dir, inv) = fresh_inv().await;
        let s = vpnctl_core::Server {
            id: ServerId("no-pin".into()),
            address: "192.0.2.99".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![vpnctl_core::KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        };
        inv.add_server(&s).await.unwrap();
        let servers = vec![s];
        // Must return Ok and write zero alert rows.
        check_fingerprint_drift(&inv, &servers).await.unwrap();
        let alerts = inv.recent_alerts(10, true).await.unwrap();
        assert!(
            alerts.is_empty(),
            "no pin → no drift check → no alert; got: {alerts:?}"
        );
    }

    #[tokio::test]
    async fn check_fingerprint_drift_skips_jump_targets() {
        // Servers reachable only via ProxyJump get skipped (ssh-
        // keyscan can't traverse jump hosts; would always fail
        // → false-positive alerts).
        let (_dir, inv) = fresh_inv().await;
        let s = vpnctl_core::Server {
            id: ServerId("jumper".into()),
            address: "192.0.2.99".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![vpnctl_core::KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: Some("SHA256:abcdefghij".into()),
            hoster: "generic".into(),
            jump_via: Some(ServerId("bastion".into())),
            usage_coefficient: 1.0,
        };
        // Don't actually need to add bastion; check_fingerprint_drift
        // only looks at the server-being-checked's jump_via flag.
        let servers = vec![s];
        check_fingerprint_drift(&inv, &servers).await.unwrap();
        let alerts = inv.recent_alerts(10, true).await.unwrap();
        assert!(
            alerts.is_empty(),
            "jump-via target must be skipped; got: {alerts:?}"
        );
    }

    #[tokio::test]
    async fn fingerprint_drift_recovery_acks_open_alert_for_same_kind_and_server() {
        // Audit finding 2026-05-23 (commit b4608d2): the original
        // commit message claimed the auto-recovery branch was
        // «exercised implicitly» by the skip tests. It wasn't — the
        // skip tests return BEFORE reaching the membership/auto-recovery
        // branch. This test pins the SQL primitive that the recovery
        // path calls (`ack_open_alerts`) for the exact kind shape +
        // server_id binding used by `check_fingerprint_drift`. The
        // full ssh-keyscan round-trip can't be unit-tested without
        // a real SSH daemon — but the SQL contract here is the only
        // piece that could regress silently.
        let (_dir, inv) = fresh_inv().await;
        inv.add_server(&vpnctl_core::Server {
            id: ServerId("srv".into()),
            address: "203.0.113.10".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![vpnctl_core::KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: Some("SHA256:original".into()),
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
        // Seed an open drift alert exactly as the fire path would.
        let kind = "server.fingerprint.drift:srv";
        let opened = inv
            .insert_alert_if_no_unacked(
                kind,
                Some(&ServerId("srv".into())),
                "warning",
                "drift",
                None,
            )
            .await
            .unwrap();
        assert!(opened.is_some(), "seed must insert one open alert");
        // Now ack it via the SAME helper the recovery branch calls.
        let acked = inv
            .ack_open_alerts(kind, Some(&ServerId("srv".into())))
            .await
            .unwrap();
        assert_eq!(acked, 1, "recovery must ack exactly the one open alert");
        // Idempotency: re-running on a healthy server with no open
        // alert is a 0-rows-affected no-op.
        let acked_again = inv
            .ack_open_alerts(kind, Some(&ServerId("srv".into())))
            .await
            .unwrap();
        assert_eq!(acked_again, 0, "second ack must be no-op");
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
