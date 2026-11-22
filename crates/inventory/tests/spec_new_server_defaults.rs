#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::{Value, json};
use tempfile::TempDir;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
use vpnctl_inventory::SqliteInventory;

async fn open() -> (TempDir, SqliteInventory) {
    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    (dir, inv)
}

fn srv(id: &str, address: &str) -> Server {
    Server {
        id: ServerId(id.into()),
        address: address.into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

async fn audit_len(inv: &SqliteInventory) -> usize {
    inv.recent_audit(100).await.unwrap().len()
}

#[tokio::test]
async fn duplicate_secret_key_rolls_back_server_and_audit() {
    let (_dir, inv) = open().await;
    let s = srv("fixture-dup-key", "198.51.100.20");
    let before = audit_len(&inv).await;

    assert!(
        inv.register_server_with_secrets(
            &s,
            "admin",
            &[("fixture.alpha", "one"), ("fixture.alpha", "two")],
        )
        .await
        .is_err()
    );
    assert!(inv.get_server(&s.id).await.unwrap().is_none());
    assert!(
        inv.get_server_secret(&s.id, "fixture.alpha")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(audit_len(&inv).await, before);
}

#[tokio::test]
async fn successful_registration_writes_one_audit_and_repeat_never_mutates() {
    let (_dir, inv) = open().await;
    let s = srv("fixture-register", "198.51.100.30");
    let values = [("fixture.alpha", "one"), ("fixture.beta", "two")];
    let before = audit_len(&inv).await;

    inv.register_server_with_secrets(&s, "admin", &values)
        .await
        .unwrap();

    let audit = inv.recent_audit(100).await.unwrap();
    assert_eq!(audit.len(), before + 1);
    assert_eq!(audit[0].action, "server.register");
    assert_eq!(audit[0].actor, "admin");
    assert_eq!(audit[0].target.as_deref(), Some(s.id.0.as_str()));
    for (key, value) in values {
        assert_eq!(
            inv.get_server_secret(&s.id, key).await.unwrap().as_deref(),
            Some(value)
        );
    }

    assert!(
        inv.register_server_with_secrets(&s, "admin", &[("fixture.alpha", "changed")])
            .await
            .is_err()
    );
    assert_eq!(
        inv.get_server_secret(&s.id, "fixture.alpha")
            .await
            .unwrap()
            .as_deref(),
        Some("one")
    );
    assert_eq!(
        inv.get_server(&s.id).await.unwrap().unwrap().address,
        "198.51.100.30"
    );
    let clash = srv("fixture-clash", "198.51.100.30");
    assert!(
        inv.register_server_with_secrets(&clash, "admin", &[("fixture.alpha", "three")])
            .await
            .is_err()
    );
    assert!(inv.get_server(&clash.id).await.unwrap().is_none());
    assert_eq!(audit_len(&inv).await, before + 1);
}

#[tokio::test]
async fn bandwidth_default_is_idempotent_and_rejects_invalid_input() {
    let (_dir, inv) = open().await;
    let policy = json!({"enabled": true, "note": "fixture"});
    let policy_text = policy.to_string();
    assert_eq!(inv.get_new_server_bandwidth_default().await.unwrap(), None);

    assert!(
        inv.set_new_server_bandwidth_default_as("admin", 120, &policy_text)
            .await
            .unwrap()
    );
    let audit = inv.recent_audit(100).await.unwrap();
    let rows: Vec<_> = audit
        .iter()
        .filter(|row| row.action == "settings.server_bandwidth_default.set")
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].actor, "admin");

    assert!(
        !inv.set_new_server_bandwidth_default_as("admin", 120, &policy_text)
            .await
            .unwrap()
    );
    for bad in ["not-json", "[1,2,3]"] {
        assert!(
            inv.set_new_server_bandwidth_default_as("admin", 120, bad)
                .await
                .is_err()
        );
    }
    assert!(
        inv.set_new_server_bandwidth_default_as("admin", 0, &policy_text)
            .await
            .is_err()
    );

    let (mbps, stored) = inv
        .get_new_server_bandwidth_default()
        .await
        .unwrap()
        .expect("failed sets must keep the previous default");
    assert_eq!(mbps, 120);
    assert_eq!(serde_json::from_str::<Value>(&stored).unwrap(), policy);
    assert_eq!(audit_len(&inv).await, audit.len());
}
