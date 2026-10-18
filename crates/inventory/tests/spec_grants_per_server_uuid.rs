#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use tempfile::TempDir;

use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctl_inventory::{SqliteInventory, SqliteInventoryError};

fn db_path(dir: &TempDir) -> PathBuf {
    dir.path().join("inventory.db")
}

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&db_path(dir)).await.expect("open")
}

fn server(id: &str) -> Server {
    Server {
        id: ServerId(id.to_string()),
        address: format!("{id}.example.com"),
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

#[tokio::test]
async fn grants_render_with_users_uuid_until_an_override_is_set() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-x")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();

    let peers = inv
        .users_for_server(&ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].id.0, "alice");
    assert_eq!(peers[0].uuid, "global-uuid-of-alice");

    let got = inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(got.as_deref(), Some("global-uuid-of-alice"));
}

#[tokio::test]
async fn override_changes_only_the_per_server_render_not_user_identity() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-x")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();

    inv.set_grant_client_uuid(
        &UserId("alice".into()),
        &ServerId("vps-x".into()),
        "12345678-1234-1234-1234-123456789abc",
    )
    .await
    .unwrap();

    let peers = inv
        .users_for_server(&ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(peers[0].uuid, "12345678-1234-1234-1234-123456789abc");

    let got = inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(got.as_deref(), Some("12345678-1234-1234-1234-123456789abc"));

    let alice = inv
        .get_user(&UserId("alice".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(alice.uuid, "global-uuid-of-alice");
}

#[tokio::test]
async fn override_on_one_server_does_not_leak_to_other_servers() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-de")).await.unwrap();
    inv.add_server(&server("vps-is")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-de".into()))
        .await
        .unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-is".into()))
        .await
        .unwrap();

    inv.set_grant_client_uuid(
        &UserId("alice".into()),
        &ServerId("vps-de".into()),
        "deadbeef-0000-0000-0000-de00de00de00",
    )
    .await
    .unwrap();

    let de = inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("vps-de".into()))
        .await
        .unwrap();
    assert_eq!(de.as_deref(), Some("deadbeef-0000-0000-0000-de00de00de00"));
    let is = inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("vps-is".into()))
        .await
        .unwrap();
    assert_eq!(is.as_deref(), Some("global-uuid-of-alice"));

    let peers_is = inv
        .users_for_server(&ServerId("vps-is".into()))
        .await
        .unwrap();
    assert_eq!(peers_is[0].uuid, "global-uuid-of-alice");
}

#[tokio::test]
async fn client_uuid_for_returns_none_when_no_grant() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-x")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();

    let got = inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(got, None);
}

#[tokio::test]
async fn set_grant_client_uuid_errors_when_no_grant() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-x")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();

    let err = inv
        .set_grant_client_uuid(
            &UserId("alice".into()),
            &ServerId("vps-x".into()),
            "11111111-2222-3333-4444-555555555555",
        )
        .await
        .expect_err("must refuse when grant doesn't exist");
    match err {
        SqliteInventoryError::Invalid(m) => {
            assert!(
                m.contains("no grant for user=alice server=vps-x"),
                "got: {m}"
            );
        }
        other => panic!("expected Invalid, got: {other:?}"),
    }
}

#[tokio::test]
async fn set_grant_client_uuid_is_idempotent_same_value() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-x")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();

    inv.set_grant_client_uuid(
        &UserId("alice".into()),
        &ServerId("vps-x".into()),
        "0000beef-1111-2222-3333-444444444444",
    )
    .await
    .unwrap();
    inv.set_grant_client_uuid(
        &UserId("alice".into()),
        &ServerId("vps-x".into()),
        "0000beef-1111-2222-3333-444444444444",
    )
    .await
    .unwrap();

    let got = inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(got.as_deref(), Some("0000beef-1111-2222-3333-444444444444"));
}

#[tokio::test]
async fn revoke_then_grant_resets_client_uuid_to_null() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-x")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    inv.set_grant_client_uuid(
        &UserId("alice".into()),
        &ServerId("vps-x".into()),
        "99999999-aaaa-bbbb-cccc-dddddddddddd",
    )
    .await
    .unwrap();
    assert_eq!(
        inv.client_uuid_for(&UserId("alice".into()), &ServerId("vps-x".into()))
            .await
            .unwrap()
            .as_deref(),
        Some("99999999-aaaa-bbbb-cccc-dddddddddddd")
    );

    inv.revoke(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();

    let got = inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(got.as_deref(), Some("global-uuid-of-alice"));
}

#[tokio::test]
async fn re_grant_on_existing_row_does_not_clear_override() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-x")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    inv.set_grant_client_uuid(
        &UserId("alice".into()),
        &ServerId("vps-x".into()),
        "11111111-2222-3333-4444-555555555555",
    )
    .await
    .unwrap();

    inv.grant(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();

    let got = inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(got.as_deref(), Some("11111111-2222-3333-4444-555555555555"));
}

#[tokio::test]
async fn set_grant_client_uuid_rejects_malformed_uuid() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-x")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();

    for bad in ["", "  ", "not-a-uuid", "11111111-2222-3333-4444"] {
        let res = inv
            .set_grant_client_uuid(&UserId("alice".into()), &ServerId("vps-x".into()), bad)
            .await;
        match res {
            Err(SqliteInventoryError::Invalid(m)) => {
                assert!(
                    m.contains("not a valid UUID"),
                    "expected 'not a valid UUID' diagnostic for bad={bad:?}, got: {m}"
                );
            }
            Err(other) => {
                panic!("expected Invalid for bad={bad:?}, got: {other:?}");
            }
            Ok(()) => panic!("expected Err for bad={bad:?}, but the write succeeded"),
        }
    }

    let got = inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(
        got.as_deref(),
        Some("global-uuid-of-alice"),
        "rejected writes must not have side-effects on the column"
    );
}

#[tokio::test]
async fn set_grant_client_uuid_writes_audit_row_with_old_and_new_uuid() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-x")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();

    inv.set_grant_client_uuid(
        &UserId("alice".into()),
        &ServerId("vps-x".into()),
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    )
    .await
    .unwrap();

    let recent = inv.recent_audit(10).await.unwrap();
    let row = recent
        .iter()
        .find(|r| r.action == "grant.set_client_uuid")
        .expect("grant.set_client_uuid audit row must be written");
    assert_eq!(row.target.as_deref(), Some("alice"));
    let payload = row.payload.as_ref().expect("payload must be present");
    assert_eq!(payload["server_id"], serde_json::json!("vps-x"));
    assert_eq!(payload["old_client_uuid"], serde_json::Value::Null);
    assert_eq!(
        payload["new_client_uuid"],
        serde_json::json!("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    );

    inv.set_grant_client_uuid(
        &UserId("alice".into()),
        &ServerId("vps-x".into()),
        "11111111-2222-3333-4444-555555555555",
    )
    .await
    .unwrap();
    let recent = inv.recent_audit(10).await.unwrap();
    let row = recent
        .iter()
        .find(|r| {
            r.action == "grant.set_client_uuid"
                && r.payload
                    .as_ref()
                    .and_then(|p| p["new_client_uuid"].as_str())
                    == Some("11111111-2222-3333-4444-555555555555")
        })
        .expect("second grant.set_client_uuid audit row must be present");
    let payload = row.payload.as_ref().unwrap();
    assert_eq!(
        payload["old_client_uuid"],
        serde_json::json!("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    );
}

#[tokio::test]
async fn remove_user_cascades_to_grant_and_client_uuid() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-x")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    inv.set_grant_client_uuid(
        &UserId("alice".into()),
        &ServerId("vps-x".into()),
        "11111111-2222-3333-4444-555555555555",
    )
    .await
    .unwrap();

    inv.remove_user(&UserId("alice".into())).await.unwrap();

    let got = inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(got, None);
    let peers = inv
        .users_for_server(&ServerId("vps-x".into()))
        .await
        .unwrap();
    assert!(
        peers.is_empty(),
        "peers list must be empty after user delete"
    );
}

#[tokio::test]
async fn fresh_grant_starts_with_null_client_uuid() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-x")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();

    use sqlx::Row;
    let url = format!("sqlite://{}?mode=ro", db_path(&dir).display());
    let raw = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let row = sqlx::query(
        "SELECT client_uuid FROM grants WHERE user_id = 'alice' AND server_id = 'vps-x'",
    )
    .fetch_one(&raw)
    .await
    .unwrap();
    let raw_value: Option<String> = row.try_get("client_uuid").unwrap();
    assert_eq!(
        raw_value, None,
        "fresh grant must have NULL client_uuid; if this test starts \
         failing, an implementation change is auto-populating the column \
         on insert — that breaks the «override» semantics (operator can no \
         longer distinguish «never overridden» from «explicitly set to \
         users.uuid»)"
    );

    let public = inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(public.as_deref(), Some("global-uuid-of-alice"));
    raw.close().await;
}

#[tokio::test]
async fn user_with_per_server_uuid_swaps_only_when_override_differs() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-x")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    let alice = inv
        .get_user(&UserId("alice".into()))
        .await
        .unwrap()
        .unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();

    let got = inv
        .user_with_per_server_uuid(&alice, &ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(got.uuid, "global-uuid-of-alice");
    assert_eq!(got.id, alice.id);

    inv.set_grant_client_uuid(
        &UserId("alice".into()),
        &ServerId("vps-x".into()),
        "11111111-2222-3333-4444-555555555555",
    )
    .await
    .unwrap();
    let got = inv
        .user_with_per_server_uuid(&alice, &ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(got.uuid, "11111111-2222-3333-4444-555555555555");
    assert_eq!(alice.uuid, "global-uuid-of-alice");

    let got = inv
        .user_with_per_server_uuid(&alice, &ServerId("nope".into()))
        .await
        .unwrap();
    assert_eq!(got.uuid, "global-uuid-of-alice");
}

#[test]
fn with_per_server_uuid_replaces_uuid_field_only() {
    let alice = user("alice");
    let mut expected = alice.clone();
    expected.uuid = "per-server-replacement".to_string();

    let got = alice.with_per_server_uuid("per-server-replacement");

    assert_eq!(got.id, expected.id);
    assert_eq!(got.uuid, "per-server-replacement");
    assert_eq!(got.tuic_password, alice.tuic_password);
    assert_eq!(got.wireguard_pubkey, alice.wireguard_pubkey);
    assert_eq!(got.wireguard_private, alice.wireguard_private);
    assert_eq!(got.sub_token, alice.sub_token);

    assert_eq!(alice.uuid, "global-uuid-of-alice");
}
