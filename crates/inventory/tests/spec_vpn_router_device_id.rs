#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use tempfile::TempDir;

use vpnctl_core::{User, UserId};
use vpnctl_inventory::{SqliteInventory, SqliteInventoryError};

fn db_path(dir: &TempDir) -> PathBuf {
    dir.path().join("inventory.db")
}

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&db_path(dir)).await.expect("open")
}

fn user(id: &str) -> User {
    User {
        id: UserId(id.to_string()),
        uuid: format!("global-uuid-of-{id}"),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

const VALID_DEVICE_ID: &str = "a92b915032b48a2ed45ef72f4171e5f4";
const ALT_DEVICE_ID: &str = "deadbeefdeadbeefdeadbeefdeadbeef";

#[tokio::test]
async fn find_by_device_id_returns_none_when_unknown() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let got = inv
        .find_user_by_vpn_router_device_id(VALID_DEVICE_ID)
        .await
        .unwrap();
    assert!(got.is_none());
}

#[tokio::test]
async fn set_then_find_round_trip() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_user(&user("alice")).await.unwrap();
    inv.set_vpn_router_device_id(&UserId("alice".into()), VALID_DEVICE_ID)
        .await
        .unwrap();

    let got = inv
        .find_user_by_vpn_router_device_id(VALID_DEVICE_ID)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.id.0, "alice");
    assert_eq!(got.uuid, "global-uuid-of-alice");
}

#[tokio::test]
async fn set_rejects_malformed_device_id() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_user(&user("alice")).await.unwrap();

    for bad in [
        "",
        "tooshort",
        "DEADBEEFDEADBEEFDEADBEEFDEADBEEF",
        "g0000000000000000000000000000000",
        "a92b915032b48a2ed45ef72f4171e5f4z",
    ] {
        let err = inv
            .set_vpn_router_device_id(&UserId("alice".into()), bad)
            .await
            .expect_err(&format!("must refuse {bad:?}"));
        match err {
            SqliteInventoryError::Invalid(m) => {
                assert!(
                    m.contains("not 32 lowercase hex chars"),
                    "got: {m} for {bad:?}"
                );
            }
            other => panic!("expected Invalid, got: {other:?} for {bad:?}"),
        }
    }
}

#[tokio::test]
async fn set_on_missing_user_returns_invalid() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let err = inv
        .set_vpn_router_device_id(&UserId("nobody".into()), VALID_DEVICE_ID)
        .await
        .expect_err("must refuse missing user");
    match err {
        SqliteInventoryError::Invalid(m) => {
            assert!(m.contains("no such user: nobody"), "got: {m}");
        }
        other => panic!("expected Invalid, got: {other:?}"),
    }
}

#[tokio::test]
async fn duplicate_device_id_returns_already_exists_not_raw_sqlx() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_user(&user("alice")).await.unwrap();
    inv.add_user(&user("bob")).await.unwrap();
    inv.set_vpn_router_device_id(&UserId("alice".into()), VALID_DEVICE_ID)
        .await
        .unwrap();

    let err = inv
        .set_vpn_router_device_id(&UserId("bob".into()), VALID_DEVICE_ID)
        .await
        .expect_err("must refuse duplicate device_id");
    match err {
        SqliteInventoryError::AlreadyExists(s) => {
            assert!(
                s.contains(VALID_DEVICE_ID),
                "expected AlreadyExists with device_id, got: {s}"
            );
        }
        other => panic!("expected AlreadyExists, got: {other:?}"),
    }

    let owner = inv
        .find_user_by_vpn_router_device_id(VALID_DEVICE_ID)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(owner.id.0, "alice");
}

#[tokio::test]
async fn rotation_to_different_value_for_same_user_succeeds() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_user(&user("alice")).await.unwrap();
    inv.set_vpn_router_device_id(&UserId("alice".into()), VALID_DEVICE_ID)
        .await
        .unwrap();
    inv.set_vpn_router_device_id(&UserId("alice".into()), ALT_DEVICE_ID)
        .await
        .unwrap();

    assert!(
        inv.find_user_by_vpn_router_device_id(VALID_DEVICE_ID)
            .await
            .unwrap()
            .is_none()
    );
    let got = inv
        .find_user_by_vpn_router_device_id(ALT_DEVICE_ID)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.id.0, "alice");
}

#[tokio::test]
async fn audit_payload_has_alphabetical_key_order_for_byte_equality_with_python() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_user(&user("alice")).await.unwrap();
    inv.set_vpn_router_device_id(&UserId("alice".into()), VALID_DEVICE_ID)
        .await
        .unwrap();
    inv.set_vpn_router_device_id(&UserId("alice".into()), ALT_DEVICE_ID)
        .await
        .unwrap();

    let recent = inv.recent_audit(10).await.unwrap();
    let row = recent
        .iter()
        .find(|r| {
            r.action == "user.set_vpn_router_device_id"
                && r.payload
                    .as_ref()
                    .and_then(|p| p["new_vpn_router_device_id"].as_str())
                    == Some(ALT_DEVICE_ID)
        })
        .expect("second set_vpn_router_device_id audit row");
    let payload = row.payload.as_ref().unwrap();
    assert_eq!(
        payload["old_vpn_router_device_id"],
        serde_json::json!(VALID_DEVICE_ID)
    );
    assert_eq!(
        payload["new_vpn_router_device_id"],
        serde_json::json!(ALT_DEVICE_ID)
    );

    let s = serde_json::to_string(payload).unwrap();
    let new_pos = s.find("\"new_vpn_router_device_id\"").unwrap();
    let old_pos = s.find("\"old_vpn_router_device_id\"").unwrap();
    assert!(
        new_pos < old_pos,
        "alphabetical order: 'new_…' must come before 'old_…': {s}"
    );
}
