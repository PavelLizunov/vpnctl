use async_trait::async_trait;
use std::fmt;

use crate::error::Result;

#[allow(clippy::double_must_use)]
#[async_trait]
pub trait SshTransport: fmt::Debug + Send + Sync {
    /// Connected target port, independent of any jump host; absent for unknown transports.
    fn target_port(&self) -> Option<u16> {
        None
    }

    async fn exec(&self, cmd: &str) -> Result<String>;
    async fn exec_unprivileged(&self, cmd: &str) -> Result<String>;
    async fn upload(&self, path: &str, content: &[u8]) -> Result<()>;
    async fn read_file(&self, path: &str) -> Result<Vec<u8>>;
}
