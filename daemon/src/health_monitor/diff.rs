use vpnctl_inventory::NodeHealthRow;

pub(crate) const DISK_PRESSURE_TRIGGER_PCT: u8 = 90;
pub(crate) const DISK_PRESSURE_RECOVER_PCT: u8 = 85;

pub(crate) const MEM_PRESSURE_TRIGGER_PCT: u8 = 95;
pub(crate) const MEM_PRESSURE_RECOVER_PCT: u8 = 90;

pub(crate) const SINGBOX_LOG_TRIGGER_BYTES: u64 = 500 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertEvent {
    pub kind: &'static str,
    pub severity: &'static str,
    pub summary: String,
    pub payload: serde_json::Value,
    pub resolves: Option<&'static str>,
}

pub(crate) fn is_one_shot_event(kind: &str) -> bool {
    kind == "server.singbox.restarted"
}

fn mem_used_pct(row: &NodeHealthRow) -> Option<u8> {
    let avail = row.mem_available_mib?;
    let total = row.mem_total_mib?;
    if total == 0 {
        return None;
    }
    let used_pct = 100u64.saturating_sub(avail.saturating_mul(100) / total);
    u8::try_from(used_pct.min(100)).ok()
}

fn disk_pct(row: &NodeHealthRow) -> Option<u8> {
    let used = row.disk_used_mib?;
    let total = row.disk_total_mib?;
    if total == 0 {
        return None;
    }
    let pct = used.saturating_mul(100) / total;
    u8::try_from(pct.min(100)).ok()
}

pub fn diff_rows(prev: &NodeHealthRow, cur: &NodeHealthRow) -> Vec<AlertEvent> {
    let mut out: Vec<AlertEvent> = Vec::new();

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

    if let (Some(p), Some(c)) = (prev.sing_box_nrestarts, cur.sing_box_nrestarts)
        && c > p
    {
        out.push(AlertEvent {
            kind: "server.singbox.restarted",
            resolves: None,
            severity: "warning",
            summary: format!(
                "sing-box crashed {} time(s) between probes (NRestarts {p} → {c}); systemd restarted it automatically",
                c - p
            ),
            payload: serde_json::json!({
                "prior": p, "current": c, "delta": c - p,
                "active": cur.sing_box_active
            }),
        });
    }

    out
}
