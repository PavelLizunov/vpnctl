//! Admin UI integration smoke tests.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "admin_smoke/common.rs"]
mod common;

#[path = "admin_smoke/alerts_health.rs"]
mod alerts_health;
#[path = "admin_smoke/dashboard.rs"]
mod dashboard;
#[path = "admin_smoke/grants.rs"]
mod grants;
#[path = "admin_smoke/monitoring.rs"]
mod monitoring;
#[path = "admin_smoke/server_detail.rs"]
mod server_detail;
#[path = "admin_smoke/servers.rs"]
mod servers;
#[path = "admin_smoke/settings_integrations.rs"]
mod settings_integrations;
#[path = "admin_smoke/shell_nav.rs"]
mod shell_nav;
#[path = "admin_smoke/user_detail.rs"]
mod user_detail;
#[path = "admin_smoke/users.rs"]
mod users;
#[path = "admin_smoke/wizard.rs"]
mod wizard;
