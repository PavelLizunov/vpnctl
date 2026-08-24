use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use vpnctl_inventory::NodeOperationLock;

/// Process-wide set of server-ids with a deploy IN FLIGHT. Guards the
/// node-touching deploy paths (`run_redeploy` via the single-server SSE
/// button + the deploy-all pass, AND the synchronous `server_deploy`
/// POST handler) against running two pipelines that render + restart the
/// SAME node at once — possible today from two browser tabs, a curl, a
/// page reload, or a single-deploy overlapping a deploy-all. Per-server
/// (not daemon-wide) so unrelated nodes still deploy in parallel.
pub(super) fn deploy_inflight() -> &'static Mutex<HashSet<String>> {
    static INFLIGHT: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    INFLIGHT.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Lock the in-flight set, recovering the guard if a previous holder
/// panicked (poison) — we never `unwrap()` a poisoned lock.
pub(super) fn lock_inflight() -> std::sync::MutexGuard<'static, HashSet<String>> {
    deploy_inflight()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// RAII permit for deploying one server. Acquired with
/// [`DeployGuard::try_acquire`]; the server-id is removed from the
/// in-flight set on drop — so a pipeline that returns early, errors, or
/// is cancelled never leaks a permanent lock.
///
/// `pub` (not `pub(crate)`) since 2026-06-10 so integration tests can
/// hold a permit while exercising the handlers that contend on it
/// (`server_deploy`, `server_delete`, the SSE redeploy).
#[derive(Debug)]
pub struct DeployGuard {
    server_id: String,
    _process_lock: NodeOperationLock,
}

impl DeployGuard {
    /// Try to claim the per-server deploy permit. Returns `None` if a
    /// deploy of `server_id` is already in flight (the caller should
    /// refuse rather than start a second concurrent node restart).
    pub fn try_acquire(server_id: &str) -> Option<Self> {
        let mut set = lock_inflight();
        if set.contains(server_id) {
            return None;
        }
        let process_lock = match NodeOperationLock::try_acquire(server_id) {
            Ok(Some(lock)) => lock,
            Ok(None) => return None,
            Err(error) => {
                tracing::warn!(
                    server = server_id,
                    error = %error,
                    "could not acquire node operation lock; refusing concurrent operation"
                );
                return None;
            }
        };
        set.insert(server_id.to_string());
        Some(Self {
            server_id: server_id.to_string(),
            _process_lock: process_lock,
        })
    }

    /// Read-only hint for background probes. A race after this check is
    /// harmless because quality alerts require consecutive bad samples.
    pub(crate) fn is_active(server_id: &str) -> bool {
        if lock_inflight().contains(server_id) {
            return true;
        }
        !matches!(NodeOperationLock::try_acquire(server_id), Ok(Some(_)))
    }
}

impl Drop for DeployGuard {
    fn drop(&mut self) {
        lock_inflight().remove(&self.server_id);
    }
}

/// Skip/error copy shared between the deploy pipelines and the
/// grant/revoke auto-deploy dispatcher (`admin.rs`), so the dispatcher's
/// string checks can't drift from what the pipeline actually emits.
pub(crate) const DEPLOY_KEY_ABSENT_MSG: &str = "deploy key absent; see /admin/settings/system";
pub(crate) const DEPLOY_ALREADY_RUNNING_PREFIX: &str = "deploy already running";
