//! SSH-транспорт. Два варианта:
//!
//! - `MockTransport` (`mock.rs`) — для unit-тестов: запоминает заливки,
//!   отдаёт стабильные ответы на `exec`.
//! - `RusshTransport` (`russh_transport.rs`) — реальный SSH-клиент поверх
//!   `russh`, с timeout и проверкой fingerprint host key.

pub mod mock;
pub mod subprocess;

#[cfg(feature = "russh")]
pub mod russh_transport;

pub use mock::MockTransport;
pub use subprocess::{
    SubprocessSshTransport, ensure_deploy_key, public_key_path, read_public_key, ssh_safety_opts,
};

#[cfg(feature = "russh")]
pub use russh_transport::{RusshTransport, RusshTransportBuilder};
