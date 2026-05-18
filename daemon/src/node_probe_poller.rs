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

use std::time::Duration;

use vpnctl_inventory::SqliteInventory;

/// Centralised "does this kernel expose the probe-able surface" check.
/// Today only `sing-box` answers — AmneziaWG nodes don't run systemd
/// `sing-box`, so the probe script's `systemctl is-active sing-box`
/// would just emit `unknown` noise. Used by BOTH `node_probe_poller`
/// (writes node_health) AND `health_monitor` (reads node_health) so
/// the two surfaces never disagree on what's in scope.
///
/// **TODO(amneziawg)**: when the AmneziaWG kernel ships, either teach
/// this fn to return `true` for it AND wire a per-kernel probe variant
/// (`wg show` instead of `systemctl is-active sing-box`), OR keep the
/// sing-box-only behaviour and add a sibling `probeable_amneziawg`.
/// Today's grep target: `fn probeable`.
pub(crate) fn probeable(server: &vpnctl_core::Server) -> bool {
    server.kernels.iter().any(|k| k.0 == "sing-box")
}

/// Realistic homelab cadence for telemetry. Slower than clash-api
/// (5 min) because node probe is "is the service alive + disk OK"
/// rather than "what's happening NOW with user traffic" — 10 min
/// is fine, halves SSH overhead vs co-cadence with clash.
///
/// Override via env `VPNCTLD_NODE_PROBE_INTERVAL_SECS`. Tests use
/// short intervals to validate the loop; production sticks with
/// the default.
const DEFAULT_INTERVAL_SECS: u64 = 10 * 60;

/// Spawn the node-probe poller. Returns the [`tokio::task::JoinHandle`]
/// so production (which discards) and tests (which assert spawn)
/// have the same interface, matching [`crate::clash_poller::spawn_clash_poller`].
///
/// **No feature gate required** — uses
/// [`crate::ssh_subprocess::SubprocessSshTransport`] which shells out
/// to the system `/usr/bin/ssh` binary (no glibc-2.38 hazard).
pub fn spawn_node_probe_poller(inv: SqliteInventory) -> tokio::task::JoinHandle<()> {
    use tokio::time::{MissedTickBehavior, interval};

    let interval_secs: u64 = std::env::var("VPNCTLD_NODE_PROBE_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_INTERVAL_SECS);

    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(interval_secs));
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // Drop the immediate first fire — daemon startup is hot;
        // gives the operator a grace period before the first probe.
        tick.tick().await;

        loop {
            tick.tick().await;
            let servers = match inv.list_servers().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        target = "vpnctld::node_probe",
                        error = %e,
                        "list_servers failed; skipping tick"
                    );
                    continue;
                }
            };
            for server in &servers {
                probe_one_server(&inv, server).await;
            }
        }
    })
}

/// Probe one server, insert the row. Pure side-effect, never panics.
/// Every error is logged at warn-or-info and swallowed.
async fn probe_one_server(inv: &SqliteInventory, server: &vpnctl_core::Server) {
    // Skip non-sing-box kernels for now via the centralised filter
    // (see `probeable` doc-comment for the AmneziaWG TODO). Once-per-
    // tick info log so the operator can grep + spot the no-op state
    // when a new kernel lands without probe support — debug is too
    // quiet (invisible by default).
    if !probeable(server) {
        tracing::info!(
            target = "vpnctld::node_probe",
            server = %server.id.0,
            kernels = ?server.kernels.iter().map(|k| k.0.as_str()).collect::<Vec<_>>(),
            "skipping probe — no probe-able kernel (today: sing-box only)"
        );
        return;
    }

    let key_path = std::env::var("VPNCTLD_DEPLOY_KEY")
        .unwrap_or_else(|_| "/var/lib/vpnctl/.ssh/id_ed25519".to_string());
    if !std::path::Path::new(&key_path).exists() {
        // Pre-deploy: same as clash_poller, log once per tick at info
        // (operator can grep) without spamming at warn.
        tracing::info!(
            target = "vpnctld::node_probe",
            server = %server.id.0,
            key = %key_path,
            "skipping: deploy SSH key not yet on the homelab host"
        );
        return;
    }

    let ssh = crate::ssh_subprocess::SubprocessSshTransport::new(
        server.address.clone(),
        server.ssh_user.clone(),
        std::path::PathBuf::from(&key_path),
    )
    .port(server.ssh_port);

    use crate::node_probe::{ProbeClient, SshProbeClient};
    let client = SshProbeClient::new(&ssh);
    let probe = match client.snapshot().await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::node_probe",
                server = %server.id.0,
                error = %e,
                "probe snapshot failed"
            );
            return;
        }
    };

    // Serialise the sorted (proto, port) set as a JSON array of
    // "proto/port" strings — matches `0007_node_health.sql` schema
    // doc-comment.
    let listening_json: Option<String> = if probe.listening.is_empty() {
        None
    } else {
        let v: Vec<String> = probe
            .listening
            .iter()
            .map(|(proto, port)| format!("{proto}/{port}"))
            .collect();
        serde_json::to_string(&v).ok()
    };

    let res = inv
        .record_node_health(
            &server.id,
            probe.sing_box_active,
            probe.fail2ban_active,
            probe.disk_used_mib,
            probe.disk_total_mib,
            probe.mem_available_mib,
            probe.mem_total_mib,
            probe.load_1min_x100,
            listening_json.as_deref(),
            probe.sing_box_log_bytes,
        )
        .await;

    match res {
        Ok(()) => tracing::info!(
            target = "vpnctld::node_probe",
            server = %server.id.0,
            sing_box = ?probe.sing_box_active,
            disk_pct = ?probe.disk_pct(),
            "node_health row persisted"
        ),
        Err(e) => tracing::warn!(
            target = "vpnctld::node_probe",
            server = %server.id.0,
            error = %e,
            "record_node_health failed"
        ),
    }
}

/// Convenience: cumulative "expire" pass over `node_health` rows
/// older than `days`. Wired into the existing retention scheduler in
/// `daemon::app::spawn_retention_purger`. Pure delegate; lives here
/// rather than inline in `app.rs` so the whole node-probe surface
/// (probe + poller + purge) stays in one place.
///
/// Returns the inventory crate's own `Result` so callers don't have
/// to import `sqlx` directly (vpnctld doesn't pull sqlx as a direct
/// dep — only the inventory crate does).
pub async fn purge_old(
    inv: &SqliteInventory,
    days: u32,
) -> std::result::Result<u64, vpnctl_inventory::SqliteInventoryError> {
    inv.purge_node_health_older_than(days).await
}

// ─── Tests ──────────────────────────────────────────────────────────
//
// Unit tests here cover the helpers that don't need a tokio runtime.
// The integration with the scheduler is covered by
// `daemon/tests/admin_smoke.rs::node_probe_poller_spawns_a_runnable_task`
// (added by the same commit that wires this into `app.rs`).

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// `purge_old` is a thin pass-through; this test asserts the
    /// signature compiles and returns `Ok(0)` on a fresh tempdir
    /// inventory (no rows = nothing to drop).
    #[tokio::test]
    async fn purge_old_on_empty_inv_returns_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let inv = SqliteInventory::open(&tmp.path().join("inv.db"))
            .await
            .unwrap();
        let dropped = purge_old(&inv, 30).await.unwrap();
        assert_eq!(dropped, 0);
    }

    /// Sanity: serializing the listening-ports set to JSON matches
    /// the on-disk format documented in `0007_node_health.sql`
    /// (sorted JSON array of `"proto/port"` strings).
    #[test]
    fn listening_ports_json_round_trip() {
        let mut s: BTreeSet<(String, u16)> = BTreeSet::new();
        s.insert(("tcp".into(), 443));
        s.insert(("udp".into(), 8443));
        s.insert(("tcp".into(), 22));
        let v: Vec<String> = s.iter().map(|(p, n)| format!("{p}/{n}")).collect();
        let json = serde_json::to_string(&v).unwrap();
        // BTreeSet sorts by (proto, port) lex: tcp/22 < tcp/443 < udp/8443.
        assert_eq!(json, r#"["tcp/22","tcp/443","udp/8443"]"#);
    }
}
