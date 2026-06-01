//! Spec for `SqliteInventory::is_known_server_address` — the membership
//! check the subscription rate-limiter uses to EXEMPT our own VPN-egress
//! IPs from the per-IP bucket (Pavel 2026-06-01: many users connected to
//! one node all egress its IP, so a per-IP limit would throttle them as
//! a group). Contract: exact-match on `servers.address`, false for
//! unknown / empty.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tempfile::TempDir;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
use vpnctl_inventory::SqliteInventory;

#[tokio::test]
async fn is_known_server_address_matches_registered_address_only() {
    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    inv.add_server(&Server {
        id: ServerId("de".into()),
        address: "104.194.156.93".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();

    // Registered egress IP → known (exempt from per-IP throttle).
    assert!(inv.is_known_server_address("104.194.156.93").await.unwrap());
    // A real client IP → not known (per-IP throttle applies).
    assert!(!inv.is_known_server_address("203.0.113.50").await.unwrap());
    // Empty / junk → not known, no error.
    assert!(!inv.is_known_server_address("").await.unwrap());
}
