//! `vpnctl-core` — фундамент: типы, идентификаторы, ошибки и два главных трейта.
//!
//! Архитектурный принцип: разделяем «что бежит на сервере» (`Kernel`) и
//! «какой формат пакетов мы предъявляем клиенту» (`Protocol`).
//! Это позволяет добавлять новое ядро (например, caddy) **не трогая**
//! existing inventory / cli / ssh / crypto-слои.

pub mod humanize;
pub mod shell;
pub mod url_host;
pub mod version;

mod error;
mod id;
mod kernel;
mod models;
mod protocol;
mod registry;
mod transport;

pub use error::*;
pub use id::*;
pub use kernel::*;
pub use models::*;
pub use protocol::*;
pub use registry::*;
pub use transport::*;
pub use version::build_version;
