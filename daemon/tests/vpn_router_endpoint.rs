//! End-to-end tests of the ninitux compatibility endpoint
//! `GET /api/v1/app/config/{device_id}` against the real `vpnctld::router()`.
//!
//! Covers:
//!   * HTTP 200 ALWAYS — anti-fingerprinting against probes that would
//!     otherwise tell a missing device_id from a valid one via the
//!     status code.
//!   * UA-based content negotiation: VPN clients get `text/plain`
//!     raw base64; browsers / curl / custom apps get the JSON wrapper.
//!   * Malformed device_id (non-32-hex) returns the SAME shape as a
//!     valid-but-unregistered device — never leaks via status code or
//!     body length.
//!   * JSON wrapper byte-shape: keys appear in declared order
//!     (`status, app, version, update_available, config, check_interval,
//!     timestamp`), compact (no whitespace), `config: null` literal
//!     when missing.
//!   * Base64 decodes to newline-joined vless:// URIs in the order
//!     `servers_for_user` returned (deterministic).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "vpn_router_endpoint/common.rs"]
mod common;

#[path = "vpn_router_endpoint/client_detour_capability.rs"]
mod client_detour_capability;
#[path = "vpn_router_endpoint/core_http.rs"]
mod core_http;
#[path = "vpn_router_endpoint/protocols.rs"]
mod protocols;
