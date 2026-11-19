#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tower::ServiceExt;
use vpnctl_core::{Registry, Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;

const OLD: &str = "11111111-aaaa-4111-8111-111111111111";
const REPLACEMENT: &str = "22222222-bbbb-4222-8222-222222222222";

async fn rotate(app: &Router, user: &str, body: String, origin: &str) -> StatusCode {
    let request = Request::post(format!("/admin/users/{user}/uuid/rotate"))
        .header("host", "example.test")
        .header("origin", origin)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    app.clone().oneshot(request).await.unwrap().status()
}

#[tokio::test]
async fn operator_rotation_validates_form_and_queues_only_granted_servers() {
    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let user = UserId("fixture-user".into());
    inv.add_user(&User {
        id: user.clone(),
        uuid: OLD.into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    for id in ["granted", "unrelated"] {
        inv.add_server(&Server {
            id: ServerId(id.into()),
            address: "127.0.0.1".into(),
            ssh_port: 9,
            ssh_user: "fixture-user".into(),
            kernels: Vec::new(),
            enabled_protocols: Vec::new(),
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    }
    inv.grant(&user, &ServerId("granted".into())).await.unwrap();
    let (state, writer) = vpnctld::make_app_state_for_tests(inv.clone(), Arc::new(Registry::new()));
    let app = vpnctld::router(state);
    let trusted = "http://example.test";
    let expected = format!("{:x}", Sha256::digest(OLD));
    let form = format!("expected_sha256={expected}&replacement={REPLACEMENT}");

    assert_eq!(
        rotate(&app, &user.0, form.clone(), "http://other.example").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        rotate(
            &app,
            &user.0,
            format!("expected_sha256={expected}&replacement=invalid"),
            trusted,
        )
        .await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        rotate(&app, "missing-user", form.clone(), trusted).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(inv.get_user(&user).await.unwrap().unwrap().uuid, OLD);

    assert_eq!(
        rotate(&app, &user.0, form, trusted).await,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        inv.get_user(&user).await.unwrap().unwrap().uuid,
        REPLACEMENT
    );
    assert_eq!(
        rotate(
            &app,
            &user.0,
            format!("expected_sha256={expected}"),
            trusted
        )
        .await,
        StatusCode::CONFLICT
    );

    let deploy = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let entries = inv.recent_audit(20).await.unwrap();
            if let Some(entry) = entries
                .into_iter()
                .find(|entry| entry.action == "user.autodeploy")
            {
                break entry;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("rotation should enqueue targeted redeploy");
    assert_eq!(deploy.target.as_deref(), Some(user.0.as_str()));
    assert_eq!(
        deploy.payload.unwrap()["servers"],
        serde_json::json!(["granted"])
    );

    let current = format!("{:x}", Sha256::digest(REPLACEMENT));
    assert_eq!(
        rotate(&app, &user.0, format!("expected_sha256={current}"), trusted).await,
        StatusCode::SEE_OTHER
    );
    assert_ne!(
        inv.get_user(&user).await.unwrap().unwrap().uuid,
        REPLACEMENT
    );
    writer.abort();
}
