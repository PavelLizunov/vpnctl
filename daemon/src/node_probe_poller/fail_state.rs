use std::collections::{HashMap, HashSet};

use vpnctl_core::ServerId;

use super::ProbeOutcome;

/// Default number of consecutive SSH-probe failures before firing the
/// `server.unreachable` alert. Three ticks at the 10-min default
/// cadence ≈ 30 min ceiling on flapping noise. Override via env
/// `VPNCTLD_UNREACHABLE_THRESHOLD`.
pub(crate) const DEFAULT_UNREACHABLE_THRESHOLD: u32 = 3;

/// Transition emitted by [`FailState::observe`] when the consecutive-
/// failure counter crosses a meaningful threshold. The caller maps
/// this into `insert_alert_if_no_unacked` / `ack_open_alerts` calls
/// against the inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnreachableTransition {
    /// The counter just reached the threshold for the FIRST time
    /// since the last `Recovered` (or process start). Caller fires
    /// the `server.unreachable` alert.
    BecameUnreachable {
        consecutive_failures: u32,
        threshold: u32,
    },
    /// The server is STILL failing on a later tick (counter already ≥
    /// threshold and we've already fired once). The caller RE-ATTEMPTS
    /// the idempotent `insert_alert_if_no_unacked`: a no-op while the
    /// alert is open + unacked, but if the operator ACKED it while the
    /// server is still down, the insert re-opens a fresh alert. Without
    /// this, an ack permanently silenced a still-down server until a
    /// recovery reset the in-memory `fired` flag — the kg 2026-05-31
    /// incident (acked 21:09 UTC, probes still failing 21:11/21:16, no
    /// re-fire). The DB's partial-UNIQUE-on-unacked index is what makes
    /// this safe to emit every tick (dedup while open).
    StillUnreachable {
        consecutive_failures: u32,
        threshold: u32,
    },
    /// A previously-failed server just succeeded. Caller acks any
    /// open `server.unreachable` alert for this id.
    Recovered,
    /// Counter changed but no transition worth alerting on (e.g.
    /// failure #2 of 3, or repeated success after recovery already
    /// fired).
    NoChange,
}

/// In-memory per-server consecutive-SSH-failure counter. **Not**
/// persisted across daemon restarts — restart is operator-initiated
/// and rare; the counter resetting just means a flapping server
/// needs another N ticks to re-alert. Documented in the field's
/// doc so future-Pavel doesn't try to persist it.
#[derive(Debug)]
pub struct FailState {
    /// Per-server count of consecutive failures since the last
    /// success. `0` = last outcome was Ok / Skipped / NoDeployKey.
    counters: HashMap<ServerId, u32>,
    /// Per-server flag: `true` if we've already emitted a
    /// `BecameUnreachable` for this id and haven't seen a recovery
    /// yet. Prevents re-firing every tick once the threshold is
    /// crossed.
    fired: HashMap<ServerId, bool>,
    threshold: u32,
}

impl FailState {
    /// Construct with the env-resolved threshold (defaults to 3).
    pub fn new() -> Self {
        Self::with_threshold(
            std::env::var("VPNCTLD_UNREACHABLE_THRESHOLD")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_UNREACHABLE_THRESHOLD),
        )
    }

    /// Construct with an explicit threshold. Test-friendly.
    pub fn with_threshold(threshold: u32) -> Self {
        // Treat a zero threshold as 1 — a zero would mean "fire on
        // every failure" which is operator-hostile noise; clamp.
        let threshold = threshold.max(1);
        Self {
            counters: HashMap::new(),
            fired: HashMap::new(),
            threshold,
        }
    }

    /// Record one probe outcome for a server, returning the alert
    /// transition (if any). Pure state-machine; no I/O.
    pub fn observe(
        &mut self,
        server_id: &ServerId,
        outcome: &ProbeOutcome,
    ) -> UnreachableTransition {
        match outcome {
            ProbeOutcome::Ok(_) => self.recover(server_id),
            ProbeOutcome::SshFailed(_) => self.fail(server_id),
            // RowWriteFailed: the node IS reachable; don't count
            // toward unreachable. Treat as no-change (don't reset
            // the counter either — preserve in-flight detection).
            ProbeOutcome::RowWriteFailed => UnreachableTransition::NoChange,
            // Skipped / NoDeployKey: not a probe attempt; don't
            // affect counter or fired-flag.
            ProbeOutcome::Skipped | ProbeOutcome::NoDeployKey => UnreachableTransition::NoChange,
        }
    }

    fn fail(&mut self, server_id: &ServerId) -> UnreachableTransition {
        let counter = self.counters.entry(server_id.clone()).or_insert(0);
        *counter = counter.saturating_add(1);
        let reached = *counter >= self.threshold;
        let already_fired = self.fired.get(server_id).copied().unwrap_or(false);
        if reached && !already_fired {
            self.fired.insert(server_id.clone(), true);
            UnreachableTransition::BecameUnreachable {
                consecutive_failures: *counter,
                threshold: self.threshold,
            }
        } else if reached {
            // Already fired but STILL failing → re-assert so an
            // acked-but-still-down alert re-opens. The caller's insert
            // is idempotent (partial-UNIQUE on unacked), so this is a
            // no-op while the alert is open and a re-fire after an ack.
            UnreachableTransition::StillUnreachable {
                consecutive_failures: *counter,
                threshold: self.threshold,
            }
        } else {
            // Below threshold (e.g. failure #2 of 3) — not yet alertable.
            UnreachableTransition::NoChange
        }
    }

    /// Drop in-memory entries for server ids that are no longer in
    /// the current inventory snapshot. Caller passes the live set
    /// from `list_servers()`. Prevents (a) unbounded HashMap growth
    /// on server churn (b) the stale-state bug where re-adding a
    /// previously-deleted server with the same id silently inherits
    /// `fired=true` and the next N failures don't alert.
    ///
    /// Bug-hunt agent 2026-05-18 finding.
    pub fn prune(&mut self, live_ids: &HashSet<ServerId>) {
        self.counters.retain(|k, _| live_ids.contains(k));
        self.fired.retain(|k, _| live_ids.contains(k));
    }

    fn recover(&mut self, server_id: &ServerId) -> UnreachableTransition {
        let was_failing = self.counters.get(server_id).copied().unwrap_or(0) > 0;
        let had_fired = self.fired.get(server_id).copied().unwrap_or(false);
        self.counters.insert(server_id.clone(), 0);
        self.fired.insert(server_id.clone(), false);
        // Emit `Recovered` only when there's something for the
        // caller to ack — either the alert had fired, OR the counter
        // was above zero (so a future tick MIGHT have fired). Repeat
        // successes after a stable recovery return NoChange.
        if had_fired {
            UnreachableTransition::Recovered
        } else if was_failing {
            // Counter was non-zero but threshold not crossed →
            // operator never saw an alert; nothing to ack.
            UnreachableTransition::NoChange
        } else {
            UnreachableTransition::NoChange
        }
    }
}

impl Default for FailState {
    fn default() -> Self {
        Self::new()
    }
}
