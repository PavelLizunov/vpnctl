use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::error::Result;
use crate::id::{KernelId, ProtocolId};
use crate::models::{RenderCtx, User};
use crate::protocol::Protocol;
use crate::transport::SshTransport;

#[allow(clippy::double_must_use)]
#[async_trait]
pub trait Kernel: fmt::Debug + Send + Sync {
    fn id(&self) -> KernelId;

    fn supported_protocols(&self) -> Vec<ProtocolId>;

    fn version_requirement(&self) -> Option<KernelVersionRequirement> {
        None
    }

    async fn ensure_installed(&self, ssh: &dyn SshTransport) -> Result<()>;

    fn render_config(
        &self,
        ctx: &RenderCtx<'_>,
        users: &[User],
        protocols: &[&dyn Protocol],
    ) -> Result<Vec<u8>>;

    async fn apply_config(&self, ssh: &dyn SshTransport, config: &[u8]) -> Result<()>;

    async fn open_firewall(
        &self,
        _ssh: &dyn SshTransport,
        _ctx: &RenderCtx<'_>,
        _protocols: &[&dyn Protocol],
    ) -> Result<()> {
        Ok(())
    }

    async fn restart(&self, ssh: &dyn SshTransport) -> Result<()>;
    async fn status(&self, ssh: &dyn SshTransport) -> Result<KernelStatus>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelStatus {
    pub active: bool,
    pub version: Option<String>,
    pub uptime_seconds: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelVersionPolicy {
    Floor,
    Pin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelVersionRequirement {
    pub policy: KernelVersionPolicy,
    pub value: &'static str,
}
