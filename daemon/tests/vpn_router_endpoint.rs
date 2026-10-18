#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "vpn_router_endpoint/common.rs"]
mod common;

#[path = "vpn_router_endpoint/client_detour_capability.rs"]
mod client_detour_capability;
#[path = "vpn_router_endpoint/core_http.rs"]
mod core_http;
#[path = "vpn_router_endpoint/protocols.rs"]
mod protocols;
