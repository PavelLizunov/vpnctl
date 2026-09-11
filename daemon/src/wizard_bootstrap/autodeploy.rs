//! Process-local scheduling only. Applied/pending truth remains in inventory's
//! revision-checked deploy audit, including after a daemon restart.
use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::{Semaphore, watch};
use tokio_stream::StreamExt;
use vpnctl_core::{Registry, Server};
use vpnctl_inventory::SqliteInventory;

use super::{BootstrapEvent, DEPLOY_ALREADY_RUNNING_PREFIX, DEPLOY_KEY_ABSENT_MSG, run_redeploy};

const MAX_PASSES: usize = 4;
const FAILURE_TTL: Duration = Duration::from_secs(15 * 60);
const MAX_FAILURES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AutodeployPhase {
    Queued,
    Running,
    Failed,
}

/// A sanitized operation hint, NOT deployment/readiness evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutodeployStatus {
    pub phase: AutodeployPhase,
    pub message: &'static str,
}

/// Read a transient automatic-operation hint. `None` means unobserved, never
/// "applied": use the canonical inventory audit/pending query for that claim.
/// Successes disappear immediately; failures expire after 15 minutes and the
/// oldest are evicted above 256. Active workers are never evicted.
pub fn autodeploy_status(inv: &SqliteInventory, server_id: &str) -> Option<AutodeployStatus> {
    coordinator().status(&coordination_key(inv, server_id))
}

fn coordination_key(inv: &SqliteInventory, server_id: &str) -> String {
    let identity = inv.coordination_identity();
    // Length prefix makes (inventory, server) unambiguous even with colons or
    // arbitrary path characters. Never expose this internal key in UI/logs.
    format!("{}:{identity}{server_id}", identity.len())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    Contention,
    Stale,
    MissingKey,
    Deploy,
    Interrupted,
    Exhausted,
}

impl Failure {
    fn message(self) -> &'static str {
        match self {
            Self::Contention => {
                "Another node operation is busy; changes remain pending. Retry this server."
            }
            Self::Stale | Self::Exhausted => {
                "Deployment inputs kept changing; changes remain pending. Retry this server."
            }
            Self::MissingKey => DEPLOY_KEY_ABSENT_MSG,
            Self::Deploy => {
                "Deployment failed; changes remain pending. Retry this server or review its deployment log."
            }
            Self::Interrupted => {
                "Deployment did not finish; changes remain pending. Retry this server."
            }
        }
    }

    fn retryable(self) -> bool {
        matches!(self, Self::Contention | Self::Stale)
    }
}

type Outcome = Result<(), Failure>;
type Completion = watch::Receiver<Option<Outcome>>;

struct Entry {
    token: Arc<()>,
    dirty: bool,
    status: AutodeployStatus,
    finished: Option<Instant>,
    completion: watch::Sender<Option<Outcome>>,
}

#[derive(Default)]
struct Coordinator {
    entries: Mutex<HashMap<String, Entry>>,
}

impl Coordinator {
    fn entries(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn cleanup(entries: &mut HashMap<String, Entry>, now: Instant) {
        entries.retain(|_, entry| {
            entry
                .finished
                .is_none_or(|at| now.duration_since(at) < FAILURE_TTL)
        });
        // ponytail: a tiny capped terminal cache; active entries scale only with
        // requested servers, never with the number of mutation requests.
        while entries
            .values()
            .filter(|entry| entry.finished.is_some())
            .count()
            > MAX_FAILURES
        {
            let oldest = entries
                .iter()
                .filter_map(|(id, entry)| entry.finished.map(|at| (id.clone(), at)))
                .min_by_key(|(_, at)| *at)
                .map(|(id, _)| id);
            if let Some(id) = oldest {
                entries.remove(&id);
            } else {
                break;
            }
        }
    }

    fn status(&self, id: &str) -> Option<AutodeployStatus> {
        let mut entries = self.entries();
        Self::cleanup(&mut entries, Instant::now());
        entries.get(id).map(|entry| entry.status.clone())
    }

    /// Registration and retirement share this mutex: a racing request either
    /// dirties the existing worker or installs its successor, never disappears.
    fn request(self: &Arc<Self>, id: String) -> (Completion, Option<Worker>) {
        let mut entries = self.entries();
        Self::cleanup(&mut entries, Instant::now());
        if let Some(entry) = entries
            .get_mut(&id)
            .filter(|entry| entry.finished.is_none())
        {
            entry.dirty = true;
            return (entry.completion.subscribe(), None);
        }
        let token = Arc::new(());
        let (completion, receiver) = watch::channel(None);
        entries.insert(
            id.clone(),
            Entry {
                token: Arc::clone(&token),
                dirty: true,
                status: AutodeployStatus {
                    phase: AutodeployPhase::Queued,
                    message: "Changes saved; deployment queued.",
                },
                finished: None,
                completion,
            },
        );
        (
            receiver,
            Some(Worker {
                coordinator: Arc::clone(self),
                id,
                token,
            }),
        )
    }
}

struct Worker {
    coordinator: Arc<Coordinator>,
    id: String,
    token: Arc<()>,
}

impl Worker {
    fn begin(&self) {
        if let Some(entry) = self.coordinator.entries().get_mut(&self.id) {
            entry.dirty = false;
            entry.status = AutodeployStatus {
                phase: AutodeployPhase::Running,
                message: "Applying saved configuration.",
            };
        }
    }

    /// Returns true only for a bounded followup. Completion is published under
    /// the same mutex as removal, so waiters cannot observe a lost retirement.
    fn finish(&self, result: Outcome, pass: usize) -> bool {
        let mut entries = self.coordinator.entries();
        let Some(entry) = entries.get_mut(&self.id) else {
            return false;
        };
        let followup = entry.dirty || result.is_err_and(Failure::retryable);
        if followup && pass < MAX_PASSES {
            entry.status = AutodeployStatus {
                phase: AutodeployPhase::Queued,
                message: "Changes pending; deployment followup queued.",
            };
            return true;
        }
        let result = if entry.dirty && result.is_ok() {
            Err(Failure::Exhausted)
        } else {
            result
        };
        entry.completion.send_replace(Some(result));
        if let Err(failure) = result {
            entry.finished = Some(Instant::now());
            entry.status = AutodeployStatus {
                phase: AutodeployPhase::Failed,
                message: failure.message(),
            };
        } else {
            entries.remove(&self.id);
        }
        Coordinator::cleanup(&mut entries, Instant::now());
        false
    }

    async fn run<F, Fut, D, Delay>(self, mut attempt: F, mut delay: D)
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Outcome>,
        D: FnMut() -> Delay,
        Delay: Future<Output = ()>,
    {
        for pass in 1..=MAX_PASSES {
            self.begin();
            let result = attempt().await;
            if !self.finish(result, pass) {
                return;
            }
            delay().await;
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let mut entries = self.coordinator.entries();
        if let Some(entry) = entries.get_mut(&self.id)
            && Arc::ptr_eq(&entry.token, &self.token)
            && entry.finished.is_none()
        {
            entry
                .completion
                .send_replace(Some(Err(Failure::Interrupted)));
            entry.finished = Some(Instant::now());
            entry.status = AutodeployStatus {
                phase: AutodeployPhase::Failed,
                message: Failure::Interrupted.message(),
            };
        }
        Coordinator::cleanup(&mut entries, Instant::now());
    }
}

fn coordinator() -> &'static Arc<Coordinator> {
    static COORDINATOR: OnceLock<Arc<Coordinator>> = OnceLock::new();
    COORDINATOR.get_or_init(|| Arc::new(Coordinator::default()))
}

fn fleet_permits() -> &'static Semaphore {
    static PERMITS: OnceLock<Semaphore> = OnceLock::new();
    PERMITS.get_or_init(|| {
        Semaphore::new(
            std::env::var("VPNCTL_FLEET_CONCURRENCY")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(4)
                .max(1),
        )
    })
}

async fn attempt(
    server: Server,
    inv: SqliteInventory,
    registry: Arc<Registry>,
    key: PathBuf,
) -> Outcome {
    if !key.exists() {
        return Err(Failure::MissingKey);
    }
    let _permit = fleet_permits()
        .acquire()
        .await
        .map_err(|_| Failure::Interrupted)?;
    let mut stream = Box::pin(run_redeploy(server, inv, registry, key));
    let mut terminal = None;
    while let Some(event) = stream.next().await {
        match event {
            BootstrapEvent::Ok { .. } => {
                terminal = Some(Ok(()));
            }
            BootstrapEvent::Error { phase, message } => {
                terminal = Some(Err(
                    if phase == "deploy" && message.starts_with(DEPLOY_ALREADY_RUNNING_PREFIX) {
                        Failure::Contention
                    } else if matches!(phase, "deploy" | "apply")
                        && message.starts_with("inventory changed")
                    {
                        Failure::Stale
                    } else {
                        Failure::Deploy
                    },
                ));
            }
            BootstrapEvent::Step { .. } => {}
        }
    }
    terminal.unwrap_or(Err(Failure::Interrupted))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "autodeploy_tests.rs"]
mod tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "autodeploy_pipeline_tests.rs"]
mod pipeline_tests;

/// Register all requests NOW, before returning the completion future. Dropping
/// the future does not cancel deployment; concurrent batches share workers.
pub fn queue_servers_redeploy(
    servers: Vec<Server>,
    inv: &SqliteInventory,
    registry: &Arc<Registry>,
    key: &std::path::Path,
) -> impl Future<Output = Vec<String>> + Send + 'static + use<> {
    let mut pending = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for server in servers {
        if !seen.insert(server.id.0.clone()) {
            continue;
        }
        let (completion, worker) = coordinator().request(coordination_key(inv, &server.id.0));
        pending.push((server.id.0.clone(), completion));
        if let Some(worker) = worker {
            let inv = inv.clone();
            let registry = Arc::clone(registry);
            let key = key.to_path_buf();
            tokio::spawn(worker.run(
                move || {
                    attempt(
                        server.clone(),
                        inv.clone(),
                        Arc::clone(&registry),
                        key.clone(),
                    )
                },
                || tokio::time::sleep(Duration::from_secs(5)),
            ));
        }
    }
    async move {
        let mut errors = Vec::new();
        for (id, mut completion) in pending {
            let result = loop {
                if let Some(result) = *completion.borrow_and_update() {
                    break result;
                }
                if completion.changed().await.is_err() {
                    break Err(Failure::Interrupted);
                }
            };
            if let Err(failure) = result {
                errors.push(format!("{id}: {}", failure.message()));
            }
        }
        errors.sort();
        errors
    }
}
