use crate::id::{KernelId, ProtocolId, ServerId};

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("no kernel assigned to this server (`{kernels}`) supports protocol `{protocol}`")]
    UnsupportedProtocol {
        kernels: String,
        protocol: ProtocolId,
    },
    #[error("kernel `{0}` is already registered")]
    DuplicateKernel(KernelId),
    #[error("protocol `{0}` is already registered")]
    DuplicateProtocol(ProtocolId),
    #[error("missing required secret `{key}` for server `{server}`")]
    MissingSecret { server: ServerId, key: String },
    #[error("ssh transport error: {0}")]
    Transport(String),
    #[error("config render error: {0}")]
    Render(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, CoreError>;
