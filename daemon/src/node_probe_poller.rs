//! Phase H chunk 4 — periodic SSH-probe scheduler.
//!
//! Sits between [`crate::node_probe::SshProbeClient`] (chunk 1, which
//! does ONE round-trip + parse) and
//! [`vpnctl_inventory::SqliteInventory::record_node_health`] (chunk 2,
//! which persists ONE row). This module is the runtime wiring: every
//! `VPNCTLD_NODE_PROBE_INTERVAL_SECS` it pulls one probe per sing-box
//! server and INSERTs the result. The `/admin/servers/{id}` page
//! (chunk 3) reads `latest_node_health` + `recent_node_health_for_server`
//! and is empty-state today; this fills it in.
//!
//! Structurally identical to [`crate::clash_poller`] — same robustness
//! contract:
//!   * **Per-server failures are isolated.** SSH unreachable, no deploy
//!     key, `ss` not installed, probe parser returns
//!     `ScriptDidNotComplete` — each one fails the ONE server's tick
//!     and continues to the next.
//!   * **Missing SSH key is a WARN, not a panic.** The empty-state on
//!     `/admin/servers/{id}` already mentions the prereq.
//!   * **No DiffEngine.** Unlike clash-api, node_health snapshots are
//!     INSERT-only (one row per tick); no in-memory state between
//!     ticks, so no `forget()` is needed and no leak guard.
//!   * **One tick per interval, sequentially per server.** Five
//!     servers × 1 s SSH each ≈ 5 s per tick. Default 5-min interval
//!     gives ~98% idle.
//!
//! ## Why a separate poller from clash_poller
//!
//! Different cadence concerns (clash is per-user traffic — useful
//! every 5 min; node_probe is service-up + disk + log size — fine at
//! 10 min if anything), different failure modes (clash is missing
//! when sing-box runs without `experimental.clash_api`; probe fails
//! when busybox lacks `ss`), different retention windows. Splitting
//! lets each evolve independently. They share the same SSH key path
//! and the same `SubprocessSshTransport` (Path C — bookworm-2.36-
//! native).
//!
//! Phase G alerts (next commit) reads `node_health` for state-change
//! detection (`sing_box_active` flipping `true → false` writes an
//! `admin_alerts` row).

mod alerts;
mod fail_state;
mod probe_inspector;
mod scheduler;

#[cfg(test)]
mod tests;

pub(crate) use alerts::{
    audit_alert_fire, auto_ack, push_alert, recover_alert, send_digest, server_subject,
};
pub use alerts::{build_alert_sink, dispatch_alerts};
pub(crate) use fail_state::DEFAULT_UNREACHABLE_THRESHOLD;
pub use fail_state::{FailState, UnreachableTransition};
pub use probe_inspector::ProbeOutcome;
pub(crate) use probe_inspector::{probe_one_server, probe_one_server_with_registry, probeable};
pub use scheduler::{purge_old, spawn_node_probe_poller};
