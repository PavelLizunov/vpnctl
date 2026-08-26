//! End-to-end operator test verifying snapshot and restore preserving
//! user, grant, protocol visibility, grant protocol/uuid overrides, and
//! app/sub artifact SHA256 digests byte-for-byte.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Registry, Server, ServerId, User, UserId};
use vpnctl_inventory::{SqliteInventory, restore_from, snapshot_to};
use vpnctl_kernels::SingBox;
use vpnctl_protocols::{TuicV5, VlessReality};
use vpnctld::{AppState, router};

const ALICE_DEVICE_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ALICE_SUB_TOKEN: &str = "sub-token-alice-1234567890abcdef";
const ALICE_GLOBAL_UUID: &str = "11111111-1111-1111-1111-111111111111";
const ALICE_DE_OVERRIDE_UUID: &str = "33333333-3333-3333-3333-333333333333";

const BOB_DEVICE_ID: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const BOB_SUB_TOKEN: &str = "sub-token-bob-abcdef1234567890ab";
const BOB_GLOBAL_UUID: &str = "22222222-2222-2222-2222-222222222222";

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn build_registry() -> Registry {
    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    reg.register_protocol(Box::new(TuicV5::new())).unwrap();
    reg
}

async fn seed_live_state(db_path: &std::path::Path) -> AppState {
    let inv = SqliteInventory::open(db_path).await.unwrap();
    let reg = build_registry();

    // 1. Servers: `de` and `is` with vless+reality and tuic-v5 enabled.
    for sid in ["de", "is"] {
        let server = Server {
            id: ServerId(sid.into()),
            address: format!("{sid}.example.com"),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![
                ProtocolId("vless+reality".into()),
                ProtocolId("tuic-v5".into()),
            ],
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

    // 2. Protocol visibility: hide tuic-v5 on server `de`
    inv.set_server_protocol_hidden(&ServerId("de".into()), &ProtocolId("tuic-v5".into()), true)
        .await
        .unwrap();

    // 3. User Alice (active)
    let alice = User {
        id: UserId("alice".into()),
        uuid: ALICE_GLOBAL_UUID.into(),
        tuic_password: Some("alice-tuic-pass".into()),
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: Some(ALICE_SUB_TOKEN.into()),
        vpn_router_device_id: Some(ALICE_DEVICE_ID.into()),
        disabled: false,
    };
    inv.add_user(&alice).await.unwrap();
    inv.grant(&alice.id, &ServerId("de".into())).await.unwrap();
    inv.grant(&alice.id, &ServerId("is".into())).await.unwrap();

    // Alice overrides:
    // a) Per-server client UUID override on `de`
    inv.set_grant_client_uuid(&alice.id, &ServerId("de".into()), ALICE_DE_OVERRIDE_UUID)
        .await
        .unwrap();

    // b) Per-grant protocol deny override on `is` for tuic-v5
    inv.set_grant_protocol_override(
        &alice.id,
        &ServerId("is".into()),
        &ProtocolId("tuic-v5".into()),
        true,
    )
    .await
    .unwrap();

    // 4. User Bob (disabled)
    let bob = User {
        id: UserId("bob".into()),
        uuid: BOB_GLOBAL_UUID.into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: Some(BOB_SUB_TOKEN.into()),
        vpn_router_device_id: Some(BOB_DEVICE_ID.into()),
        disabled: true,
    };
    inv.add_user(&bob).await.unwrap();
    inv.grant(&bob.id, &ServerId("de".into())).await.unwrap();

    let (state, _writer) = vpnctld::make_app_state_for_tests(inv, Arc::new(reg));
    state
}

async fn open_existing_state(db_path: &std::path::Path) -> AppState {
    let inv = SqliteInventory::open(db_path).await.unwrap();
    let reg = build_registry();
    let (state, _writer) = vpnctld::make_app_state_for_tests(inv, Arc::new(reg));
    state
}

/// Fetch app config via `/api/v1/app/config/<device_id>` and return the config payload
/// as well as the SHA256 digest of the config base64 string.
async fn fetch_app_artifact_digest(app: axum::Router, device_id: &str) -> (String, String) {
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/app/config/{device_id}"))
                .header("user-agent", "Mozilla/5.0 operator-restore-test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "app config endpoint must return 200"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let val: Value = serde_json::from_slice(&body).expect("response must be valid JSON");
    let config_b64 = val["config"].as_str().unwrap_or("").to_string();
    let digest = sha256_hex(config_b64.as_bytes());
    (config_b64, digest)
}

/// Fetch sing-box subscription via `/sub/<token>` and return raw bytes + SHA256 digest.
async fn fetch_sub_singbox_digest(app: axum::Router, token: &str) -> (Vec<u8>, String) {
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/sub/{token}"))
                .header("user-agent", "sing-box")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "sub endpoint must return 200"
    );
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    let digest = sha256_hex(&body);
    (body, digest)
}

/// Fetch v2ray-style subscription via `/sub/<token>` and return raw bytes + SHA256 digest.
async fn fetch_sub_v2ray_digest(app: axum::Router, token: &str) -> (Vec<u8>, String) {
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/sub/{token}"))
                .header("user-agent", "v2rayN/6.62")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "v2ray sub endpoint must return 200"
    );
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    let digest = sha256_hex(&body);
    (body, digest)
}

#[tokio::test]
async fn operator_restore_preserves_user_grant_visibility_override_and_digests() {
    let dir = TempDir::new().unwrap();
    let live_db = dir.path().join("live.db");
    let snap_path = dir.path().join("snapshot.bak");
    let restored_db = dir.path().join("restored.db");

    // ── 1. Seed live state and capture pre-snapshot metrics & digests ─
    let state = seed_live_state(&live_db).await;

    // Verify initial users
    let alice_before = state
        .inv
        .get_user(&UserId("alice".into()))
        .await
        .unwrap()
        .expect("alice exists");
    assert_eq!(alice_before.uuid, ALICE_GLOBAL_UUID);
    assert_eq!(
        alice_before.tuic_password.as_deref(),
        Some("alice-tuic-pass")
    );
    assert_eq!(alice_before.sub_token.as_deref(), Some(ALICE_SUB_TOKEN));
    assert_eq!(
        alice_before.vpn_router_device_id.as_deref(),
        Some(ALICE_DEVICE_ID)
    );
    assert!(!alice_before.disabled);

    let bob_before = state
        .inv
        .get_user(&UserId("bob".into()))
        .await
        .unwrap()
        .expect("bob exists");
    assert_eq!(bob_before.uuid, BOB_GLOBAL_UUID);
    assert!(bob_before.disabled);

    // Verify initial grants and counts
    let grants_count_before = state.inv.count_grants().await.unwrap();
    assert_eq!(grants_count_before, 3); // alice -> de, is; bob -> de

    let alice_servers_before = state
        .inv
        .servers_for_user(&UserId("alice".into()))
        .await
        .unwrap();
    assert_eq!(alice_servers_before.len(), 2);

    // Verify visibility pre-snapshot
    let de_tuic_hidden = state
        .inv
        .is_server_protocol_hidden(&ServerId("de".into()), &ProtocolId("tuic-v5".into()))
        .await
        .unwrap();
    assert!(de_tuic_hidden, "tuic-v5 on server de is hidden");

    let is_tuic_hidden = state
        .inv
        .is_server_protocol_hidden(&ServerId("is".into()), &ProtocolId("tuic-v5".into()))
        .await
        .unwrap();
    assert!(!is_tuic_hidden, "tuic-v5 on server is is not hidden");

    // Verify overrides pre-snapshot
    let alice_overrides = state
        .inv
        .list_protocol_overrides_for_user(&UserId("alice".into()))
        .await
        .unwrap();
    assert_eq!(
        alice_overrides.get(&(ServerId("is".into()), ProtocolId("tuic-v5".into()))),
        Some(&true),
        "alice has protocol override disabling tuic-v5 on is"
    );

    let alice_de_uuid = state
        .inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("de".into()))
        .await
        .unwrap();
    assert_eq!(
        alice_de_uuid.as_deref(),
        Some(ALICE_DE_OVERRIDE_UUID),
        "alice has per-server uuid override on de"
    );

    let alice_is_uuid = state
        .inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("is".into()))
        .await
        .unwrap();
    assert_eq!(
        alice_is_uuid.as_deref(),
        Some(ALICE_GLOBAL_UUID),
        "alice has no per-server uuid override on is (falls back to global uuid)"
    );

    // Verify visible protocols for subscription
    let alice_de_visible = state
        .inv
        .visible_protocols_for_subscription(&UserId("alice".into()), &ServerId("de".into()))
        .await
        .unwrap();
    assert_eq!(
        alice_de_visible,
        vec![ProtocolId("vless+reality".into())],
        "only vless+reality visible on de (tuic hidden)"
    );

    let alice_is_visible = state
        .inv
        .visible_protocols_for_subscription(&UserId("alice".into()), &ServerId("is".into()))
        .await
        .unwrap();
    assert_eq!(
        alice_is_visible,
        vec![ProtocolId("vless+reality".into())],
        "only vless+reality visible on is (tuic disabled by override)"
    );

    // Capture pre-snapshot artifact digests
    let (app_cfg_pre, app_digest_pre) =
        fetch_app_artifact_digest(router(state.clone()), ALICE_DEVICE_ID).await;
    assert!(
        !app_cfg_pre.is_empty(),
        "alice app config must not be empty"
    );

    let (sub_singbox_pre, sub_singbox_digest_pre) =
        fetch_sub_singbox_digest(router(state.clone()), ALICE_SUB_TOKEN).await;
    assert!(!sub_singbox_pre.is_empty());

    let (sub_v2ray_pre, sub_v2ray_digest_pre) =
        fetch_sub_v2ray_digest(router(state.clone()), ALICE_SUB_TOKEN).await;
    assert!(!sub_v2ray_pre.is_empty());

    // ── 2. Create snapshot ───────────────────────────────────────────
    snapshot_to(&state.inv, &snap_path).await.unwrap();
    assert!(snap_path.exists());
    assert!(snap_path.metadata().unwrap().len() > 0);

    // ── 3. Mutate live DB (proving post-mutation drifts digests) ───────
    // a) Mutate Alice grant: revoke on `de`
    state
        .inv
        .revoke(&UserId("alice".into()), &ServerId("de".into()))
        .await
        .unwrap();

    // b) Mutate visibility: unhide tuic-v5 on `de`
    state
        .inv
        .set_server_protocol_hidden(&ServerId("de".into()), &ProtocolId("tuic-v5".into()), false)
        .await
        .unwrap();

    // c) Mutate Alice sub token
    state
        .inv
        .regenerate_sub_token(&UserId("alice".into()))
        .await
        .unwrap();

    // Verify post-mutation digests differ
    let (_app_cfg_post, app_digest_post) =
        fetch_app_artifact_digest(router(state.clone()), ALICE_DEVICE_ID).await;
    assert_ne!(
        app_digest_pre, app_digest_post,
        "app artifact digest must change after live mutation"
    );

    // ── 4. Restore snapshot to new DB ────────────────────────────────
    restore_from(&snap_path, &restored_db).await.unwrap();
    assert!(restored_db.exists());

    // ── 5. Open restored DB and verify full state preservation ────────
    let restored_state = open_existing_state(&restored_db).await;

    // Verify user preservation
    let alice_restored = restored_state
        .inv
        .get_user(&UserId("alice".into()))
        .await
        .unwrap()
        .expect("alice exists in restored db");
    assert_eq!(alice_restored.uuid, ALICE_GLOBAL_UUID);
    assert_eq!(
        alice_restored.tuic_password.as_deref(),
        Some("alice-tuic-pass")
    );
    assert_eq!(
        alice_restored.sub_token.as_deref(),
        Some(ALICE_SUB_TOKEN),
        "sub_token preserved after restore"
    );
    assert_eq!(
        alice_restored.vpn_router_device_id.as_deref(),
        Some(ALICE_DEVICE_ID),
        "vpn_router_device_id preserved after restore"
    );
    assert!(!alice_restored.disabled);

    let bob_restored = restored_state
        .inv
        .get_user(&UserId("bob".into()))
        .await
        .unwrap()
        .expect("bob exists in restored db");
    assert_eq!(bob_restored.uuid, BOB_GLOBAL_UUID);
    assert_eq!(bob_restored.sub_token.as_deref(), Some(BOB_SUB_TOKEN));
    assert_eq!(
        bob_restored.vpn_router_device_id.as_deref(),
        Some(BOB_DEVICE_ID)
    );
    assert!(bob_restored.disabled, "bob disabled flag preserved");

    // Verify grants count & relationships
    let grants_count_restored = restored_state.inv.count_grants().await.unwrap();
    assert_eq!(
        grants_count_restored, grants_count_before,
        "grants count preserved"
    );

    let alice_servers_restored = restored_state
        .inv
        .servers_for_user(&UserId("alice".into()))
        .await
        .unwrap();
    assert_eq!(
        alice_servers_restored.len(),
        alice_servers_before.len(),
        "alice granted servers preserved"
    );

    // Verify protocol visibility preserved
    let de_tuic_hidden_restored = restored_state
        .inv
        .is_server_protocol_hidden(&ServerId("de".into()), &ProtocolId("tuic-v5".into()))
        .await
        .unwrap();
    assert_eq!(
        de_tuic_hidden_restored, de_tuic_hidden,
        "server protocol visibility preserved"
    );

    let is_tuic_hidden_restored = restored_state
        .inv
        .is_server_protocol_hidden(&ServerId("is".into()), &ProtocolId("tuic-v5".into()))
        .await
        .unwrap();
    assert_eq!(
        is_tuic_hidden_restored, is_tuic_hidden,
        "server protocol visibility on is preserved"
    );

    // Verify protocol overrides preserved
    let alice_overrides_restored = restored_state
        .inv
        .list_protocol_overrides_for_user(&UserId("alice".into()))
        .await
        .unwrap();
    assert_eq!(
        alice_overrides_restored.get(&(ServerId("is".into()), ProtocolId("tuic-v5".into()))),
        Some(&true),
        "grant protocol override preserved"
    );

    let alice_de_uuid_restored = restored_state
        .inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("de".into()))
        .await
        .unwrap();
    assert_eq!(
        alice_de_uuid_restored.as_deref(),
        Some(ALICE_DE_OVERRIDE_UUID),
        "per-server client_uuid override preserved"
    );

    let alice_is_uuid_restored = restored_state
        .inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("is".into()))
        .await
        .unwrap();
    assert_eq!(
        alice_is_uuid_restored.as_deref(),
        Some(ALICE_GLOBAL_UUID),
        "absence of per-server uuid override on is preserved"
    );

    let alice_de_visible_restored = restored_state
        .inv
        .visible_protocols_for_subscription(&UserId("alice".into()), &ServerId("de".into()))
        .await
        .unwrap();
    assert_eq!(
        alice_de_visible_restored, alice_de_visible,
        "visible protocols for subscription on de preserved"
    );

    let alice_is_visible_restored = restored_state
        .inv
        .visible_protocols_for_subscription(&UserId("alice".into()), &ServerId("is".into()))
        .await
        .unwrap();
    assert_eq!(
        alice_is_visible_restored, alice_is_visible,
        "visible protocols for subscription on is preserved"
    );

    // ── 6. Verify App and Sub artifact digests byte-for-byte ─────────
    let (app_cfg_restored, app_digest_restored) =
        fetch_app_artifact_digest(router(restored_state.clone()), ALICE_DEVICE_ID).await;
    assert_eq!(
        app_cfg_restored, app_cfg_pre,
        "restored app config base64 must match pre-snapshot exactly"
    );
    assert_eq!(
        app_digest_restored, app_digest_pre,
        "restored app artifact sha256 digest must match pre-snapshot"
    );

    let (sub_singbox_restored, sub_singbox_digest_restored) =
        fetch_sub_singbox_digest(router(restored_state.clone()), ALICE_SUB_TOKEN).await;
    assert_eq!(
        sub_singbox_restored, sub_singbox_pre,
        "restored sing-box sub config must match pre-snapshot exactly"
    );
    assert_eq!(
        sub_singbox_digest_restored, sub_singbox_digest_pre,
        "restored sing-box sub sha256 digest must match pre-snapshot"
    );

    let (sub_v2ray_restored, sub_v2ray_digest_restored) =
        fetch_sub_v2ray_digest(router(restored_state.clone()), ALICE_SUB_TOKEN).await;
    assert_eq!(
        sub_v2ray_restored, sub_v2ray_pre,
        "restored v2ray sub config must match pre-snapshot exactly"
    );
    assert_eq!(
        sub_v2ray_digest_restored, sub_v2ray_digest_pre,
        "restored v2ray sub sha256 digest must match pre-snapshot"
    );
}
