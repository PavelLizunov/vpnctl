use vpnctl_inventory::NodeHealthRow;

/// Disk-pressure thresholds, with 5-pp hysteresis. `pub(crate)` so the
/// monitoring page's threshold table renders the SAME numbers the
/// monitor actually evaluates (single source of truth).
pub(crate) const DISK_PRESSURE_TRIGGER_PCT: u8 = 90;
pub(crate) const DISK_PRESSURE_RECOVER_PCT: u8 = 85;

/// Memory-pressure thresholds.
pub(crate) const MEM_PRESSURE_TRIGGER_PCT: u8 = 95;
pub(crate) const MEM_PRESSURE_RECOVER_PCT: u8 = 90;

/// sing-box log size threshold (bytes). 500 MiB — Pavel's earlier
/// disk-fill concern. The logrotate fragment we install in
/// `kernels::sing_box::ensure_installed` caps growth, but a freshly
/// bootstrapped node before the first rotation OR a node where the
/// fragment got blown away will eventually trip this.
pub(crate) const SINGBOX_LOG_TRIGGER_BYTES: u64 = 500 * 1024 * 1024;

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
/// Stateless — same input always produces the same output. The caller
/// uses the inventory's atomic `insert_alert_if_no_unacked` path for
/// condition events, so re-reading the same pair is a quiet no-op while
/// its alert remains open.
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
        } else if p >= DISK_PRESSURE_RECOVER_PCT && c < DISK_PRESSURE_RECOVER_PCT {
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
        } else if p >= MEM_PRESSURE_RECOVER_PCT && c < MEM_PRESSURE_RECOVER_PCT {
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
    // Both sides are level-triggered. Two below-threshold probes can land
    // before this scanner runs; the inventory history gate suppresses
    // repeated/orphan recovery events.
    if let (Some(p), Some(c)) = (prev.sing_box_log_bytes, cur.sing_box_log_bytes) {
        if c >= SINGBOX_LOG_TRIGGER_BYTES {
            out.push(AlertEvent {
                kind: "server.singbox.log.too_big",
                resolves: None,
                severity: "warning",
                summary: format!(
                    "sing-box log size is at least 500 MiB ({} → {} bytes)",
                    p, c
                ),
                payload: serde_json::json!({
                    "prior_bytes": p, "current_bytes": c,
                    "threshold_bytes": SINGBOX_LOG_TRIGGER_BYTES
                }),
            });
        } else if c < SINGBOX_LOG_TRIGGER_BYTES {
            out.push(AlertEvent {
                kind: "server.singbox.log.recovered",
                resolves: Some("server.singbox.log.too_big"),
                severity: "info",
                summary: format!("sing-box log size is under 500 MiB ({} → {} bytes)", p, c),
                payload: serde_json::json!({
                    "prior_bytes": p, "current_bytes": c,
                    "recover_threshold_bytes": SINGBOX_LOG_TRIGGER_BYTES
                }),
            });
        }
    }

    // ── sing-box restarts between probes (monotonic counter) ───────
    // `sing_box_active` only sees the state AT each sample, so a sing-box
    // that OOMs / crashes and is auto-restarted BETWEEN two probes reads
    // `active` at both and the down detector never fires. systemd's
    // monotonic `NRestarts` closes that gap: an INCREASE means one or more
    // restarts happened in the interval.
    //
    // Guard rails:
    //  * Both samples must carry a reading (`if let (Some, Some)`) — the
    //    first observation of a counter has no baseline to diff, so it is
    //    silent. This also means a pre-existing high counter on first pair
    //    (e.g. 5 → 5) does NOT alert; only a genuine increase does.
    //  * `c > p` only. A DECREASE (`c < p`) is a counter reset — host
    //    reboot or `systemctl reset-failed` — NOT a negative restart count;
    //    treat it as a no-op so a reboot doesn't fire a phantom alert.
    if let (Some(p), Some(c)) = (prev.sing_box_nrestarts, cur.sing_box_nrestarts)
        && c > p
    {
        out.push(AlertEvent {
            kind: "server.singbox.restarted",
            resolves: None,
            severity: "warning",
            summary: format!(
                "sing-box was restarted {} time(s) between probes (NRestarts {p} → {c}) — likely an OOM/crash; systemd auto-restarted it",
                c - p
            ),
            payload: serde_json::json!({
                "prior": p, "current": c, "delta": c - p
            }),
        });
    }

    out
}
