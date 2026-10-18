use async_trait::async_trait;
use std::fmt;

use crate::error::Result;

#[allow(clippy::double_must_use)]
#[async_trait]
pub trait SshTransport: fmt::Debug + Send + Sync {
    async fn exec(&self, cmd: &str) -> Result<String>;
    async fn exec_unprivileged(&self, cmd: &str) -> Result<String>;
    async fn upload(&self, path: &str, content: &[u8]) -> Result<()>;
    async fn read_file(&self, path: &str) -> Result<Vec<u8>>;
}
