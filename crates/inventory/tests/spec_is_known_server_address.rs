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

#[tokio::test]
async fn server_id_for_address_returns_clashing_id_backing_the_dup_guard() {
    // Backs the add-server duplicate-address guard (quick-add + wizard):
    // a second inventory record for one physical node fights over its
    // `users[]` and the second deploy trips the DG-1 user-removal guard
    // (the `us` / `us1` incident, 2026-07-08).
    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mk = |id: &str, addr: &str| Server {
        id: ServerId(id.into()),
        address: addr.into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&mk("us", "130.94.19.7")).await.unwrap();

    // Registered address → returns the clashing id (guard rejects the dup).
    assert_eq!(
        inv.server_id_for_address("130.94.19.7").await.unwrap(),
        Some("us".to_string())
    );
    // Unknown / empty address → None (guard lets the add through).
    assert_eq!(
        inv.server_id_for_address("203.0.113.50").await.unwrap(),
        None
    );
    assert_eq!(inv.server_id_for_address("").await.unwrap(), None);

    // If a duplicate ever slipped in (pre-guard data), the helper is
    // deterministic: lowest id by `ORDER BY id`.
    inv.add_server(&mk("us1", "130.94.19.7")).await.unwrap();
    assert_eq!(
        inv.server_id_for_address("130.94.19.7").await.unwrap(),
        Some("us".to_string())
    );
}
