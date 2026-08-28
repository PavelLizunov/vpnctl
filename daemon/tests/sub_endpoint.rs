//! End-to-end tests of the /sub/<token> endpoint against the REAL
//! `vpnctld::router()` (no shim — addresses critical review-finding
//! that shim-tests cannot detect regressions in the production handler).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "sub_endpoint/client_detour.rs"]
mod client_detour;
#[path = "sub_endpoint/common.rs"]
mod common;
#[path = "sub_endpoint/payloads.rs"]
mod payloads;
#[path = "sub_endpoint/rate_limiting.rs"]
mod rate_limiting;
