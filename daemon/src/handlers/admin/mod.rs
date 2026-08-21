//! Admin Handlers Module Entry Point

// Axum Response is the established handler error type across this module.
#![allow(clippy::result_large_err)]

pub(crate) mod alerts;
pub(crate) mod audit;
pub(crate) mod backup;
pub(crate) mod boosty;
pub(crate) mod helpers;
pub(crate) mod legacy;
pub(crate) mod monitoring;
pub(crate) mod search;
pub(crate) mod server_actions;
pub(crate) mod servers;
pub(crate) mod ui;
pub(crate) mod user_access;
pub(crate) mod user_actions;
pub(crate) mod user_detail;
pub(crate) mod users;

pub(crate) use alerts::*;
pub(crate) use audit::*;
pub(crate) use backup::*;
pub(crate) use boosty::*;
pub(crate) use helpers::*;
pub(crate) use legacy::*;
pub(crate) use monitoring::*;
pub(crate) use search::*;
pub(crate) use server_actions::*;
pub(crate) use servers::*;
pub(crate) use user_access::*;
pub(crate) use user_actions::*;
pub(crate) use user_detail::*;
pub(crate) use users::*;
