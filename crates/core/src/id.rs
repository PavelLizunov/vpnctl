use serde::{Deserialize, Serialize};
use std::fmt;

/// Стабильный строковый id (типа `"sing-box"`, `"caddy"`).
/// Нельзя перепутать с другим `Id` благодаря newtype-обёртке.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KernelId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProtocolId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServerId(pub String);

macro_rules! impl_display_for_id {
    ($($t:ty),+ $(,)?) => {
        $(impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        })+
    };
}
impl_display_for_id!(KernelId, ProtocolId, ServerId, UserId);
