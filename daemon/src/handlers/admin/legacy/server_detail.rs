//! Admin UI legacy handlers — server detail page and sub-tab sections.

mod activity;
mod config;
mod drift;
mod grants;
mod render;
mod routes;
mod telemetry;
mod types;

pub(crate) use self::config::user_detail_per_protocol_grid;
pub(crate) use self::grants::{grant_protocol_disable, grant_protocol_enable};
pub(crate) use self::routes::{
    server_detail, server_detail_activity, server_detail_grants_tab, server_detail_protocols_tab,
    server_detail_setup,
};
pub(crate) use self::telemetry::status_tile;
pub(crate) use self::types::detail_tabs;
