//! Live stage of a single-server redeploy, shared by every viewer tab.
//!
//! The SSE stream is best-effort: a tab may reconnect, another tab may have
//! started the deploy, or an automatic redeploy may overtake the page. This
//! registry keeps the observable stage independent of any one subscriber so
//! the status fragment remains truthful after a lost stream or a page return.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use chrono::{DateTime, Utc};
use vpnctl_inventory::SqliteInventory;

const FINISHED_TTL: std::time::Duration = std::time::Duration::from_secs(30 * 60);
const MAX_FINISHED: usize = 256;

static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeployOutcome {
    Running,
    Succeeded,
    Failed,
}

#[derive(Clone, Debug)]
pub(crate) struct DeployActivity {
    pub(crate) generation: u64,
    pub(crate) outcome: DeployOutcome,
    pub(crate) stage_phase: Option<&'static str>,
    pub(crate) stage_message: Option<String>,
    pub(crate) stage_at: Option<DateTime<Utc>>,
    pub(crate) started_at: DateTime<Utc>,
    pub(crate) finished_at: Option<DateTime<Utc>>,
    pub(crate) last_error: Option<String>,
}

struct Entry {
    activity: DeployActivity,
}

#[derive(Default)]
struct Registry {
    entries: Mutex<HashMap<String, Entry>>,
}

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(Registry::default)
}

fn entries() -> std::sync::MutexGuard<'static, HashMap<String, Entry>> {
    registry()
        .entries
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn cleanup(entries: &mut HashMap<String, Entry>, now: DateTime<Utc>) {
    entries.retain(|_, entry| {
        entry
            .activity
            .finished_at
            .is_none_or(|at| (now - at).to_std().is_ok_and(|age| age < FINISHED_TTL))
    });
    while entries
        .values()
        .filter(|entry| entry.activity.finished_at.is_some())
        .count()
        > MAX_FINISHED
    {
        let oldest = entries
            .iter()
            .filter_map(|(key, entry)| entry.activity.finished_at.map(|at| (key.clone(), at)))
            .min_by_key(|(_, at)| *at)
            .map(|(key, _)| key);
        if let Some(key) = oldest {
            entries.remove(&key);
        } else {
            break;
        }
    }
}

/// Inventory-scoped key, mirroring the autodeploy coordination identity so two
/// inventories cannot observe each other's deploy stage in one process.
pub(super) fn activity_key(inv: &SqliteInventory, server_id: &str) -> String {
    let identity = inv.coordination_identity();
    format!("{}:{identity}{server_id}", identity.len())
}

pub(crate) fn deploy_activity(inv: &SqliteInventory, server_id: &str) -> Option<DeployActivity> {
    deploy_activity_for_key(&activity_key(inv, server_id))
}

fn deploy_activity_for_key(key: &str) -> Option<DeployActivity> {
    let mut entries = entries();
    cleanup(&mut entries, Utc::now());
    entries.get(key).map(|entry| entry.activity.clone())
}

#[derive(Debug)]
pub(crate) struct DeployActivityHandle {
    key: String,
    generation: u64,
    finished: bool,
}

impl DeployActivityHandle {
    pub(crate) fn start(inv: &SqliteInventory, server_id: &str) -> Self {
        Self::start_for_key(activity_key(inv, server_id))
    }

    fn start_for_key(key: String) -> Self {
        let now = Utc::now();
        let generation = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
        let mut entries = entries();
        cleanup(&mut entries, now);
        entries.insert(
            key.clone(),
            Entry {
                activity: DeployActivity {
                    generation,
                    outcome: DeployOutcome::Running,
                    stage_phase: None,
                    stage_message: None,
                    stage_at: None,
                    started_at: now,
                    finished_at: None,
                    last_error: None,
                },
            },
        );
        Self {
            key,
            generation,
            finished: false,
        }
    }

    pub(crate) fn stage(&self, phase: &'static str, message: &str) {
        let mut entries = entries();
        let Some(entry) = entries.get_mut(&self.key) else {
            return;
        };
        if entry.activity.generation != self.generation
            || entry.activity.outcome != DeployOutcome::Running
        {
            return;
        }
        entry.activity.stage_phase = Some(phase);
        entry.activity.stage_message = Some(message.to_string());
        entry.activity.stage_at = Some(Utc::now());
    }

    pub(crate) fn succeed(&mut self) {
        self.finish(DeployOutcome::Succeeded, None);
    }

    pub(crate) fn fail(&mut self, message: &str) {
        self.finish(DeployOutcome::Failed, Some(message));
    }

    fn finish(&mut self, outcome: DeployOutcome, error: Option<&str>) {
        self.finished = true;
        let mut entries = entries();
        let Some(entry) = entries.get_mut(&self.key) else {
            return;
        };
        if entry.activity.generation != self.generation {
            return;
        }
        let now = Utc::now();
        entry.activity.outcome = outcome;
        entry.activity.finished_at = Some(now);
        if let Some(error) = error {
            entry.activity.last_error = Some(error.to_string());
            entry.activity.stage_at = Some(now);
        }
        cleanup(&mut entries, now);
    }
}

impl Drop for DeployActivityHandle {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.finish(
            DeployOutcome::Failed,
            Some("deployment stopped before reporting completion"),
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn key(name: &str) -> String {
        format!("test-{name}-{}", std::process::id())
    }

    #[test]
    fn newer_operation_wins_and_old_terminal_event_is_ignored() {
        let key = key("generation");
        let mut first = DeployActivityHandle::start_for_key(key.clone());
        first.stage("install", "installing kernel");
        let mut second = DeployActivityHandle::start_for_key(key.clone());

        first.fail("late failure from the replaced operation");
        let current = deploy_activity_for_key(&key).expect("current activity");
        assert_eq!(current.outcome, DeployOutcome::Running);
        assert_eq!(current.generation, second.generation);
        assert_ne!(current.generation, first.generation);

        second.succeed();
        let current = deploy_activity_for_key(&key).expect("finished activity");
        assert_eq!(current.outcome, DeployOutcome::Succeeded);
        assert!(current.finished_at.is_some());
    }

    #[test]
    fn dropped_handle_is_an_explicit_interruption() {
        let key = key("drop");
        {
            let _handle = DeployActivityHandle::start_for_key(key.clone());
        }
        let current = deploy_activity_for_key(&key).expect("interrupted activity");
        assert_eq!(current.outcome, DeployOutcome::Failed);
        assert!(
            current
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("stopped before reporting completion"))
        );
    }
}
