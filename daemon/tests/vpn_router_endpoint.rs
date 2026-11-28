#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "vpn_router_endpoint/common.rs"]
mod common;

#[path = "vpn_router_endpoint/client_detour_capability.rs"]
mod client_detour_capability;
#[path = "vpn_router_endpoint/core_http.rs"]
mod core_http;
#[path = "vpn_router_endpoint/dnstt.rs"]
mod dnstt;
#[path = "vpn_router_endpoint/protocols.rs"]
mod protocols;
#[path = "vpn_router_endpoint/trusttunnel_mieru.rs"]
mod trusttunnel_mieru;
#[path = "vpn_router_endpoint/turnrelay.rs"]
mod turnrelay;
