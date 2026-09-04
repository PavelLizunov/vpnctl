use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::error::Result;
use crate::id::{KernelId, ProtocolId};
use crate::models::{RenderCtx, User};
use crate::protocol::Protocol;
use crate::transport::SshTransport;

#[async_trait]
pub trait Kernel: fmt::Debug + Send + Sync {
    fn id(&self) -> KernelId;

    /// Список протоколов, которые это ядро вообще способно поднять.
    fn supported_protocols(&self) -> Vec<ProtocolId>;

    /// Version target managed by [`Kernel::ensure_installed`]. `None`
    /// means the kernel has no machine-comparable managed version.
    fn version_requirement(&self) -> Option<KernelVersionRequirement> {
        None
    }

    /// Проверка готовности (есть ли пакет в репо, есть ли systemd-юнит).
    async fn ensure_installed(&self, ssh: &dyn SshTransport) -> Result<()>;

    /// Сгенерировать серверный конфиг. `ctx` несёт сервер и его секреты,
    /// `users` — все пользователи с грантом на этот сервер, `protocols` —
    /// набор включённых протоколов (в порядке, в котором они должны
    /// появиться в inbound'ах).
    fn render_config(
        &self,
        ctx: &RenderCtx<'_>,
        users: &[User],
        protocols: &[&dyn Protocol],
    ) -> Result<Vec<u8>>;

    /// Залить новый конфиг + перезагрузить.
    async fn apply_config(&self, ssh: &dyn SshTransport, config: &[u8]) -> Result<()>;

    /// Открыть хост-фаервол под порты, которые биндят включённые
    /// `protocols` — источник правды `Protocol::effective_listen_ports()`
    /// (тот же набор, что у cross-protocol port-conflict guard'а), т.е.
    /// с учётом пер-серверных оверрайдов портов из `ctx.secrets`. Чтобы
    /// свежий `deploy` был доступен СРАЗУ, без ручного `ufw allow`
    /// (иначе смысл автоматизации теряется).
    ///
    /// DEFAULT — no-op: ядра без управляемого хост-фаервола, или
    /// управляющие им инлайн (amneziawg через wg-quick PostUp
    /// iptables), наследуют пустую реализацию.
    ///
    /// Контракт — **best-effort**: невозможность открыть фаервол (нет
    /// `ufw`; cloud-firewall хост вроде DigitalOcean, где ingress правит
    /// апстрим-firewall, а не локальный ufw) НЕ должна валить deploy —
    /// конфиг к этому моменту уже применён. Вызывающий логирует ошибку и
    /// продолжает.
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

/// How [`Kernel::ensure_installed`] interprets its managed version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelVersionPolicy {
    /// Installed versions at or above the value are accepted.
    Floor,
    /// The installed build must match the value exactly.
    Pin,
}

/// Registry-owned version metadata rendered by the admin UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelVersionRequirement {
    pub policy: KernelVersionPolicy,
    pub value: &'static str,
}
