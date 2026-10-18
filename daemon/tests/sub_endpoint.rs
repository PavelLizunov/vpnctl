#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "sub_endpoint/awg_compatibility.rs"]
mod awg_compatibility;
#[path = "sub_endpoint/client_detour.rs"]
mod client_detour;
#[path = "sub_endpoint/common.rs"]
mod common;
#[path = "sub_endpoint/mihomo.rs"]
mod mihomo;
#[path = "sub_endpoint/payloads.rs"]
mod payloads;
#[path = "sub_endpoint/rate_limiting.rs"]
mod rate_limiting;
