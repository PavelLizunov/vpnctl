//! User-detail admin handlers: the per-user page with its five tabs
//! (Overview / Delivery / Access / Activity / Traffic) plus the
//! overview summary card.
//!
//! Extracted from `legacy.rs` as part of the admin submodules
//! refactor.

mod overview;
mod render;
mod routes;
mod tabs;
mod types;

pub(crate) use self::routes::*;
