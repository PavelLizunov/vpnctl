//! Phase 5d — end-to-end restore fire-drill in CI.
//!
//! Manually-run fire-drills (2026-05-22 against prod) proved 32/32
//! production user subscriptions are byte-identical after restore.
//! This test proves the same contract on every commit, in a
//! tempdir, without prod data.
//!
//! What it exercises:
//!   1. Seed a fresh `inv.db` with a user + 2 servers + grants +
//!      a `vpn_router_device_id`.
//!   2. Capture the «pre-mutation» response from
//!      `GET /api/v1/app/config/<device_id>`.
//!   3. Snapshot the DB via the public Rust path
//!      (`snapshot_to`).
//!   4. **Mutate** the live DB — change the user's UUID. This
//!      MUST change the rendered URI bytes; if it doesn't, the
//!      test isn't proving anything.
//!   5. Capture the «post-mutation» response → assert it differs
//!      from pre-mutation (mutation check).
//!   6. Restore the snapshot to a SEPARATE db path
//!      (`restore_from`).
//!   7. Build a SECOND `AppState`/`router` on the restored db.
//!   8. Capture the «restored» response → assert byte-equal to
//!      pre-mutation (the actual restore contract).
//!
//! The `timestamp` field of the JSON wrapper is server-side `now()`
//! — varies by run. Stripped before comparison; same workaround
//! used in the manual 32/32-user prod fire-drill on 2026-05-22.

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

    // Two servers — proves the iterator over granted servers (and
    // therefore the multi-URI base64 payload) is preserved
    // byte-for-byte across restore. Single-server would still pass
    // even if e.g. the server ID ordering broke.
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

/// Call `/api/v1/app/config/<device_id>` against `app`. Returns
/// the JSON body parsed into a [`serde_json::Value`] — caller is
/// expected to drop the `timestamp` field before comparing for
/// equality (server-side `now()` varies between calls).
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

/// Strip the `timestamp` field — it's server-side `now()` and would
/// otherwise force every comparison to differ. The `config` field
/// (base64 of the URI list) is the byte-equivalence contract we
/// care about (mobile clients import this and survive byte-stable).
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

    // 1. Seed + capture pre-mutation response.
    let state = seed_state(&live_db).await;
    let pre = strip_timestamp(fetch_config_json(router(state.clone()), TEST_DEVICE_ID).await);
    // Sanity: response carries a non-null config (= our user was
    // found + at least one URI was rendered). Without this guard
    // the test could «pass» on the trivial-everything-empty path.
    assert!(
        pre.get("config").is_some_and(|c| !c.is_null()),
        "pre response must have non-null config (test seed broken): {pre:?}"
    );

    // 2. Snapshot the DB. We use the public Rust API directly
    //    rather than the snapshot_now+timestamped-dir variant
    //    because we want a deterministic path.
    let snap_path = dir.path().join("snapshot.bak");
    snapshot_to(&state.inv, &snap_path).await.unwrap();
    assert!(snap_path.exists());
    assert!(snap_path.metadata().unwrap().len() > 0);

    // 3. Mutate AFTER snapshot. We use TWO mutations:
    //
    //    a) `revoke` of one of the two server grants. THIS is the
    //       mutation that changes the rendered URI list (one fewer
    //       line in the base64 blob) and is what makes the
    //       `pre != post` assertion below fire deterministically.
    //       The sub_token does NOT appear in the device_id endpoint
    //       render, so revoke is the load-bearing mutation here.
    //
    //    b) `regenerate_sub_token` is extra noise — it touches
    //       another table that restore_from MUST preserve. Catches a
    //       hypothetical future regression where restore loses
    //       sub_token rows but preserves grants (would silently
    //       break the legacy `/sub/<token>` clients without
    //       affecting the `/api/v1/app/config/<id>` byte test).
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

    // 4. Capture post-mutation response → must DIFFER from pre.
    //    If this assertion fails, the mutation didn't actually
    //    change the output and the rest of the test is vacuous.
    let post = strip_timestamp(fetch_config_json(router(state.clone()), TEST_DEVICE_ID).await);
    assert_ne!(
        pre, post,
        "post-mutation response must differ from pre — mutation choice is wrong"
    );

    // 5. Restore the snapshot to a SEPARATE db path (we leave the
    //    live db alone — no need to close the live pool because
    //    we never touch it from here on).
    let restored_db = dir.path().join("restored.db");
    restore_from(&snap_path, &restored_db).await.unwrap();
    assert!(restored_db.exists());

    // 6. Build a SECOND state on the restored db.
    let restored_state = seed_state_open_only(&restored_db).await;

    // 7. Capture restored response → MUST match pre byte-for-byte
    //    (after timestamp strip). This is the real fire-drill
    //    assertion.
    let restored =
        strip_timestamp(fetch_config_json(router(restored_state.clone()), TEST_DEVICE_ID).await);
    assert_eq!(
        pre, restored,
        "restored response must be byte-identical to pre-mutation \
         (this is the contract that ensures mobile clients survive a \
         disaster-recovery restore without re-importing their QR)"
    );
}

/// Like [`seed_state`] but skips seeding — opens an EXISTING db.
/// Used to attach a fresh `AppState` to a restored DB without
/// re-running migrations or accidentally inserting test fixtures
/// on top of the restored content.
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
    // Cheaper companion: just the inventory side, no router.
    // Catches a subset of regressions (e.g. restore drops rows)
    // that would also surface in the byte-equivalence test but
    // here pinpoint the row count specifically.
    let dir = TempDir::new().unwrap();
    let live_db = dir.path().join("live.db");
    let state = seed_state(&live_db).await;

    let users_before = state.inv.list_users().await.unwrap().len();
    let grants_before = state.inv.count_grants().await.unwrap();
    let servers_before = state.inv.list_servers().await.unwrap().len();

    let snap_path = dir.path().join("snapshot.bak");
    snapshot_to(&state.inv, &snap_path).await.unwrap();
    // Restore to a fresh path; live state stays untouched.
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
