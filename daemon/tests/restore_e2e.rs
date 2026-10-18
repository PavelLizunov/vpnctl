#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Registry, Server, ServerId, User, UserId};
use vpnctl_inventory::{SqliteInventory, restore_from, snapshot_to};
use vpnctl_kernels::SingBox;
use vpnctl_protocols::VlessReality;
use vpnctld::{AppState, router};

const TEST_DEVICE_ID: &str = "feedfacefeedfacefeedfacefeedface";

async fn seed_state(db_path: &std::path::Path) -> AppState {
    let inv = SqliteInventory::open(db_path).await.unwrap();
    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();

    for sid in ["de", "is"] {
        let server = Server {
            id: ServerId(sid.into()),
            address: format!("{sid}.example.com"),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        };
        inv.add_server(&server).await.unwrap();
        inv.set_server_secret(&server.id, "vless.public_key", &format!("PUB_{sid}"))
            .await
            .unwrap();
        inv.set_server_secret(&server.id, "vless.short_id", "12345678")
            .await
            .unwrap();
    }

    let user = User {
        id: UserId("e2e-restore-tester".into()),
        uuid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    };
    inv.add_user(&user).await.unwrap();
    inv.set_vpn_router_device_id(&user.id, TEST_DEVICE_ID)
        .await
        .unwrap();
    inv.grant(&user.id, &ServerId("de".into())).await.unwrap();
    inv.grant(&user.id, &ServerId("is".into())).await.unwrap();

    let (state, _writer) = vpnctld::make_app_state_for_tests(inv, Arc::new(reg));
    state
}

async fn fetch_config_json(app: axum::Router, device_id: &str) -> Value {
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/app/config/{device_id}"))
                .header("user-agent", "Mozilla/5.0 e2e-restore-test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "subscription must always 200"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice::<Value>(&body).expect("response must be JSON")
}

fn strip_timestamp(mut v: Value) -> Value {
    if let Value::Object(m) = &mut v {
        m.remove("timestamp");
    }
    v
}

#[tokio::test]
async fn restore_preserves_subscription_byte_for_byte_after_post_snapshot_mutation() {
    let dir = TempDir::new().unwrap();
    let live_db = dir.path().join("live.db");

    let state = seed_state(&live_db).await;
    let pre = strip_timestamp(fetch_config_json(router(state.clone()), TEST_DEVICE_ID).await);
    assert!(
        pre.get("config").is_some_and(|c| !c.is_null()),
        "pre response must have non-null config (test seed broken): {pre:?}"
    );

    let snap_path = dir.path().join("snapshot.bak");
    snapshot_to(&state.inv, &snap_path).await.unwrap();
    assert!(snap_path.exists());
    assert!(snap_path.metadata().unwrap().len() > 0);

    state
        .inv
        .regenerate_sub_token(&UserId("e2e-restore-tester".into()))
        .await
        .unwrap();
    state
        .inv
        .revoke(&UserId("e2e-restore-tester".into()), &ServerId("is".into()))
        .await
        .unwrap();

    let post = strip_timestamp(fetch_config_json(router(state.clone()), TEST_DEVICE_ID).await);
    assert_ne!(
        pre, post,
        "post-mutation response must differ from pre — mutation choice is wrong"
    );

    let restored_db = dir.path().join("restored.db");
    restore_from(&snap_path, &restored_db).await.unwrap();
    assert!(restored_db.exists());

    let restored_state = seed_state_open_only(&restored_db).await;

    let restored =
        strip_timestamp(fetch_config_json(router(restored_state.clone()), TEST_DEVICE_ID).await);
    assert_eq!(
        pre, restored,
        "restored response must be byte-identical to pre-mutation \
         (this is the contract that ensures mobile clients survive a \
         disaster-recovery restore without re-importing their QR)"
    );
}

async fn seed_state_open_only(db_path: &std::path::Path) -> AppState {
    let inv = SqliteInventory::open(db_path).await.unwrap();
    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    let (state, _writer) = vpnctld::make_app_state_for_tests(inv, Arc::new(reg));
    state
}

#[tokio::test]
async fn restore_e2e_proves_user_count_preserved() {
    let dir = TempDir::new().unwrap();
    let live_db = dir.path().join("live.db");
    let state = seed_state(&live_db).await;

    let users_before = state.inv.list_users().await.unwrap().len();
    let grants_before = state.inv.count_grants().await.unwrap();
    let servers_before = state.inv.list_servers().await.unwrap().len();

    let snap_path = dir.path().join("snapshot.bak");
    snapshot_to(&state.inv, &snap_path).await.unwrap();
    let restored_db = dir.path().join("restored.db");
    restore_from(&snap_path, &restored_db).await.unwrap();
    let restored_inv = SqliteInventory::open(&restored_db).await.unwrap();

    assert_eq!(restored_inv.list_users().await.unwrap().len(), users_before);
    assert_eq!(restored_inv.count_grants().await.unwrap(), grants_before);
    assert_eq!(
        restored_inv.list_servers().await.unwrap().len(),
        servers_before
    );
}
