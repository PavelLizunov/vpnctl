use std::collections::{HashMap, HashSet};

use vpnctl_core::ServerId;

use super::ProbeOutcome;

pub(crate) const DEFAULT_UNREACHABLE_THRESHOLD: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnreachableTransition {
    BecameUnreachable {
        consecutive_failures: u32,
        threshold: u32,
    },
    StillUnreachable {
        consecutive_failures: u32,
        threshold: u32,
    },
    Recovered,
    NoChange,
}

#[derive(Debug)]
pub struct FailState {
    counters: HashMap<ServerId, u32>,
    fired: HashMap<ServerId, bool>,
    threshold: u32,
}

impl FailState {
    pub fn new() -> Self {
        Self::with_threshold(
            std::env::var("VPNCTLD_UNREACHABLE_THRESHOLD")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_UNREACHABLE_THRESHOLD),
        )
    }

    pub fn with_threshold(threshold: u32) -> Self {
        let threshold = threshold.max(1);
        Self {
            counters: HashMap::new(),
            fired: HashMap::new(),
            threshold,
        }
    }

    pub fn observe(
        &mut self,
        server_id: &ServerId,
        outcome: &ProbeOutcome,
    ) -> UnreachableTransition {
        match outcome {
            ProbeOutcome::Ok(_) => self.recover(server_id),
            ProbeOutcome::SshFailed(_) => self.fail(server_id),
            ProbeOutcome::RowWriteFailed => UnreachableTransition::NoChange,
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
            UnreachableTransition::StillUnreachable {
                consecutive_failures: *counter,
                threshold: self.threshold,
            }
        } else {
            UnreachableTransition::NoChange
        }
    }

    pub fn prune(&mut self, live_ids: &HashSet<ServerId>) {
        self.counters.retain(|k, _| live_ids.contains(k));
        self.fired.retain(|k, _| live_ids.contains(k));
    }

    fn recover(&mut self, server_id: &ServerId) -> UnreachableTransition {
        let had_fired = self.fired.get(server_id).copied().unwrap_or(false);
        self.counters.insert(server_id.clone(), 0);
        self.fired.insert(server_id.clone(), false);
        if had_fired {
            UnreachableTransition::Recovered
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
