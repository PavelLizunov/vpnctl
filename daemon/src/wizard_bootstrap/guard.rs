use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use vpnctl_inventory::NodeOperationLock;

pub(super) fn deploy_inflight() -> &'static Mutex<HashSet<String>> {
    static INFLIGHT: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    INFLIGHT.get_or_init(|| Mutex::new(HashSet::new()))
}

pub(super) fn lock_inflight() -> std::sync::MutexGuard<'static, HashSet<String>> {
    deploy_inflight()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Debug)]
pub struct DeployGuard {
    server_id: String,
    _process_lock: NodeOperationLock,
}

impl DeployGuard {
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

pub(crate) const DEPLOY_KEY_ABSENT_MSG: &str = "deploy key absent; see /admin/settings/system";
pub(crate) const DEPLOY_ALREADY_RUNNING_PREFIX: &str = "deploy already running";
