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
//! | sing_box_log_bytes is at least 500 MiB | warning | `server.singbox.log.too_big` |
//! | sing_box_log_bytes is below 500 MiB after a recorded warning | info | `server.singbox.log.recovered` |
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

mod diff;
mod fingerprint_drift;
mod poller;
mod remediation;
mod specialized_checks;

#[cfg(test)]
mod tests;

pub use diff::{AlertEvent, diff_rows};
pub(crate) use diff::{
    DISK_PRESSURE_TRIGGER_PCT, MEM_PRESSURE_TRIGGER_PCT, SINGBOX_LOG_TRIGGER_BYTES,
};
pub use fingerprint_drift::check_fingerprint_drift;
pub use poller::{scan_once, spawn_health_monitor};
pub use specialized_checks::{
    check_attribution_stall, check_sub_fetch_without_traffic, check_user_traffic_limits,
};
