#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tempfile::TempDir;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
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

    assert!(inv.is_known_server_address("104.194.156.93").await.unwrap());
    assert!(!inv.is_known_server_address("203.0.113.50").await.unwrap());
    assert!(!inv.is_known_server_address("").await.unwrap());
}

#[tokio::test]
async fn canonicalises_ipv6_and_resolves_hostnames() {
    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    for (id, address) in [("v6", "2001:0db8:0:0::1"), ("local", "localhost")] {
        inv.add_server(&Server {
            id: ServerId(id.into()),
            address: address.into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    }

    assert!(inv.is_known_server_address("2001:db8::1").await.unwrap());
    let resolved = inv.refresh_server_resolved_addresses().await.unwrap();
    assert!(!resolved.is_empty());
    for ip in resolved {
        assert!(inv.is_known_server_address(&ip.to_string()).await.unwrap());
    }
}

#[tokio::test]
async fn adding_expanded_ipv6_backfills_existing_canonical_access_rows() {
    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let uid = UserId("u".into());
    inv.add_user(&User {
        id: uid.clone(),
        uuid: "00000000-0000-0000-0000-000000000002".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    inv.log_sub_access(&uid, "2001:db8::1", None, 200, 1)
        .await
        .unwrap();
    inv.add_server(&Server {
        id: ServerId("v6".into()),
        address: "2001:0db8:0:0::1".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    let aggregates = inv.sub_access_aggregates_for_user(&uid, 30).await.unwrap();
    assert_eq!(aggregates.egress_rows, 1);
    assert_eq!(aggregates.total_rows, 0);
}

#[tokio::test]
async fn server_id_for_address_returns_clashing_id_backing_the_dup_guard() {
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

    assert_eq!(
        inv.server_id_for_address("130.94.19.7").await.unwrap(),
        Some("us".to_string())
    );
    assert_eq!(
        inv.server_id_for_address("203.0.113.50").await.unwrap(),
        None
    );
    assert_eq!(inv.server_id_for_address("").await.unwrap(), None);

    inv.add_server(&mk("us1", "130.94.19.7")).await.unwrap();
    assert_eq!(
        inv.server_id_for_address("130.94.19.7").await.unwrap(),
        Some("us".to_string())
    );
}

#[tokio::test]
async fn duplicate_address_lookup_compares_canonical_ips_and_case_insensitive_hostnames() {
    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    for (id, address) in [
        ("v6", "2001:0db8:0:0:0:0:0:1"),
        ("dns", "LOCALHOST"),
        ("v4", "192.0.2.1"),
    ] {
        inv.add_server(&Server {
            id: ServerId(id.into()),
            address: address.into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    }
    for (address, expected) in [
        ("2001:db8::1", Some("v6")),
        ("2001:0db8:0000:0:0:0:0:1", Some("v6")),
        ("localhost", Some("dns")),
        ("LocalHost", Some("dns")),
        ("192.0.2.1", Some("v4")),
        ("192.0.2.2", None),
        ("2001:db8::2", None),
        ("other.invalid", None),
    ] {
        assert_eq!(
            inv.server_id_for_address(address).await.unwrap().as_deref(),
            expected
        );
    }
}
