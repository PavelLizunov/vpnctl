use async_trait::async_trait;
use std::fmt;

use crate::error::Result;

/// Минимальный SSH-контракт: что-нибудь, что умеет дёрнуть команду.
/// Реальная impl — в `vpnctl-ssh` поверх `russh`. В тестах — мок.
#[async_trait]
pub trait SshTransport: fmt::Debug + Send + Sync {
    /// Execute a managed-node command with the transport's privileged semantics.
    async fn exec(&self, cmd: &str) -> Result<String>;
    /// Execute as the SSH login user. Home/key bootstrap operations use this
    /// path so a non-root login does not accidentally target `/root`.
    async fn exec_unprivileged(&self, cmd: &str) -> Result<String>;
    async fn upload(&self, path: &str, content: &[u8]) -> Result<()>;
    async fn read_file(&self, path: &str) -> Result<Vec<u8>>;
}
