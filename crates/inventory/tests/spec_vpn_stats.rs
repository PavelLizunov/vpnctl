//! Spec for `record_vpn_stats`, `recent_vpn_stats_for_user`,
//! `recent_vpn_stats_for_server`, `purge_vpn_stats_older_than` on
//! `SqliteInventory`. Written from spec only — impl NOT consulted.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "spec_vpn_stats/common.rs"]
mod common;
#[path = "spec_vpn_stats/core.rs"]
mod core;
#[path = "spec_vpn_stats/rollups.rs"]
mod rollups;
#[path = "spec_vpn_stats/sessions.rs"]
mod sessions;
