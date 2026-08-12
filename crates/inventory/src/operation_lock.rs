//! Cross-process per-server lock for node-changing operations.
//!
//! The daemon's in-memory deploy guard prevents two browser actions from
//! touching one node concurrently, but cannot see the systemd-driven CLI
//! updater. This advisory file lock is shared by daemon deploys, CLI deploys,
//! and `update-kernels` so only one of those operations can own a server.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use fs2::FileExt;

const LOCK_DIR_ENV: &str = "VPNCTLD_NODE_LOCK_DIR";

#[derive(Debug)]
pub struct NodeOperationLock {
    file: File,
}

impl NodeOperationLock {
    /// Try to acquire the shared lock for `server_id` without waiting.
    /// `Ok(None)` means another deploy/update process owns it.
    pub fn try_acquire(server_id: &str) -> io::Result<Option<Self>> {
        Self::try_acquire_in(default_lock_dir(), server_id)
    }

    fn try_acquire_in(dir: impl AsRef<Path>, server_id: &str) -> io::Result<Option<Self>> {
        validate_server_id(server_id)?;
        std::fs::create_dir_all(dir.as_ref())?;
        let path = dir.as_ref().join(format!("{server_id}.lock"));
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)?;
        match FileExt::try_lock_exclusive(&file) {
            Ok(()) => Ok(Some(Self { file })),
            Err(error) if lock_is_contended(&error) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

fn lock_is_contended(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
        || cfg!(windows) && matches!(error.raw_os_error(), Some(32 | 33))
}

impl Drop for NodeOperationLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

fn default_lock_dir() -> PathBuf {
    if let Some(path) = std::env::var_os(LOCK_DIR_ENV) {
        return PathBuf::from(path);
    }
    if cfg!(all(target_os = "linux", not(debug_assertions))) {
        PathBuf::from("/var/lib/vpnctl/locks")
    } else {
        std::env::temp_dir().join("vpnctl-node-locks")
    }
}

fn validate_server_id(server_id: &str) -> io::Result<()> {
    if !server_id.is_empty()
        && server_id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "server id is not safe for an operation-lock filename",
        ))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn same_server_is_exclusive_and_drop_releases() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = NodeOperationLock::try_acquire_in(dir.path(), "de").expect("first lock");
        assert!(first.is_some());
        assert!(
            NodeOperationLock::try_acquire_in(dir.path(), "de")
                .expect("contended lock")
                .is_none()
        );
        drop(first);
        assert!(
            NodeOperationLock::try_acquire_in(dir.path(), "de")
                .expect("released lock")
                .is_some()
        );
    }

    #[test]
    fn different_servers_do_not_block_each_other() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _de = NodeOperationLock::try_acquire_in(dir.path(), "de")
            .expect("de lock")
            .expect("de permit");
        assert!(
            NodeOperationLock::try_acquire_in(dir.path(), "fi")
                .expect("fi lock")
                .is_some()
        );
    }

    #[test]
    fn unsafe_server_id_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(NodeOperationLock::try_acquire_in(dir.path(), "../de").is_err());
    }
}
