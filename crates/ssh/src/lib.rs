//! SSH-транспорт. Два варианта:
//!
//! - `MockTransport` (`mock.rs`) — для unit-тестов: запоминает заливки,
//!   отдаёт стабильные ответы на `exec`.
//! - `RusshTransport` (`russh_transport.rs`) — реальный SSH-клиент поверх
//!   `russh`, с timeout и проверкой fingerprint host key.

pub mod mock;
pub mod russh_transport;

pub use mock::MockTransport;
pub use russh_transport::{RusshTransport, RusshTransportBuilder};
