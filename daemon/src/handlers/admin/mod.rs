//! Admin Handlers Module Entry Point

pub(crate) mod helpers;
pub(crate) mod legacy;
pub(crate) mod servers;
pub(crate) mod ui;
pub(crate) mod user_access;
pub(crate) mod user_actions;
pub(crate) mod user_detail;
pub(crate) mod users;

pub(crate) use helpers::*;
pub(crate) use legacy::*;
pub(crate) use servers::*;
pub(crate) use ui::*;
pub(crate) use user_access::*;
pub(crate) use user_actions::*;
pub(crate) use user_detail::*;
pub(crate) use users::*;
