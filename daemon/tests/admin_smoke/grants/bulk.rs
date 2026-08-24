//! Bulk grant and revoke tests for users and servers.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
use vpnctld::router;

use crate::common::state;

// ── D1 — default-grant-all-servers on user create ───────────────────
//
// Pre-2026-05-22 POST /admin/users created a user with ZERO grants,
// then operator had to drill into each server. New default: a
// `grant_all=1` checkbox (checked by default in the form) triggers
// a bulk grant immediately after add_user. Two tests pin the contract:
//   1. grant_all=1 (default) → user is granted on every registered server.
//   2. grant_all omitted → user is granted on ZERO servers (pre-D1
//      behavior preserved for explicit opt-out).

#[tokio::test]
async fn user_create_with_grant_all_grants_every_registered_server() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    // Seed 2 servers so we can assert the grant count is 2 (not 0, not 1).
    for sid_s in ["alpha", "bravo"] {
        st.inv
            .add_server(&Server {
                id: ServerId(sid_s.into()),
                address: format!("203.0.113.{}", if sid_s == "alpha" { 1 } else { 2 }),
                ssh_port: 22,
                ssh_user: "root".into(),
                kernels: vec![KernelId("sing-box".into())],
                enabled_protocols: vec![],
                trusted_host_fingerprint: None,
                hoster: "generic".into(),
                jump_via: None,
                usage_coefficient: 1.0,
            })
            .await
            .unwrap();
    }
    let app = router(st.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("id=newbie&grant_all=1"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    // Both servers must now have a grant for `newbie`!.
    let granted_servers = st
        .inv
        .servers_for_user(&vpnctl_core::UserId("newbie".into()))
        .await
        .unwrap();
    let mut granted_ids: Vec<String> = granted_servers.iter().map(|s| s.id.0.clone()).collect();
    granted_ids.sort();
    assert_eq!(
        granted_ids,
        vec!["alpha".to_string(), "bravo".to_string()],
        "grant_all=1 must grant access on EVERY registered server"
    );
}

#[tokio::test]
async fn user_create_without_grant_all_grants_zero_servers() {
    // Explicit opt-out: form posts WITHOUT grant_all field at all.
    // Old behaviour preserved — user created with zero grants.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&Server {
            id: ServerId("solo".into()),
            address: "203.0.113.5".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(st.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("id=optout"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let granted = st
        .inv
        .servers_for_user(&vpnctl_core::UserId("optout".into()))
        .await
        .unwrap();
    assert!(
        granted.is_empty(),
        "user created without grant_all checkbox must have zero grants; got: {granted:?}"
    );
}

#[tokio::test]
async fn user_create_with_grant_all_renders_checked_checkbox_in_form() {
    // The form on /admin/users must render the checkbox CHECKED by
    // default so the operator's «one click» path produces a granted
    // user.
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/users")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    // The form must include the checkbox + it must be checked.
    assert!(
        html.contains(r#"name="grant_all""#),
        "user form must include grant_all checkbox"
    );
    assert!(
        html.contains(r#"checked="checked""#) || html.contains("checked=\"checked\""),
        "checkbox must default to CHECKED — found no checked attribute in the form"
    );
}

// ── B2 — bulk grant/revoke on /admin/servers/<id> ──────────────────
//
// Grant-all: no confirm, idempotent, grants every ungranted user.
// Revoke-all: requires confirm=<server-id>, revokes every granted.

#[tokio::test]
async fn server_grant_all_users_grants_every_ungranted() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&Server {
            id: ServerId("srv".into()),
            address: "203.0.113.20".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    for (idx, id) in ["alice", "bob", "carol"].iter().enumerate() {
        st.inv
            .add_user(&User {
                id: UserId((*id).into()),
                uuid: format!("00000000-0000-0000-0000-{:012}", 90 + idx),
                tuic_password: None,
                wireguard_pubkey: None,
                wireguard_private: None,
                sub_token: None,
                vpn_router_device_id: None,
                disabled: false,
            })
            .await
            .unwrap();
    }
    let app = router(st.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/srv/grants/_grant-all")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let granted = st
        .inv
        .users_for_server(&ServerId("srv".into()))
        .await
        .unwrap();
    let mut ids: Vec<String> = granted.iter().map(|u| u.id.0.clone()).collect();
    ids.sort();
    assert_eq!(ids, vec!["alice", "bob", "carol"]);
    // Summary audit row must have been written.
    let audit = st.inv.recent_audit(20).await.unwrap();
    let row = audit
        .iter()
        .find(|e| e.action == "server.grants.bulk_grant")
        .expect("bulk_grant audit row required");
    let payload = row.payload.as_ref().unwrap();
    assert_eq!(payload["granted"].as_u64(), Some(3));
    assert_eq!(payload["already_granted"].as_u64(), Some(0));
    assert_eq!(payload["failed"].as_u64(), Some(0));
    // Audit-finding follow-up (2026-05-23): disabled users skipped.
    // None of the 3 seeded users are disabled → counter is 0.
    assert_eq!(payload["skipped_disabled"].as_u64(), Some(0));
}

#[tokio::test]
async fn server_grant_all_skips_disabled_users() {
    // Audit-finding follow-up (2026-05-23, b4608d2 review): bulk
    // grant must NOT silently grant access to soft-paused users
    // (B1.user mental-model preservation).
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&Server {
            id: ServerId("srv".into()),
            address: "203.0.113.30".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    st.inv
        .add_user(&User {
            id: UserId("alive".into()),
            uuid: "00000000-0000-0000-0000-000000000201".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    st.inv
        .add_user(&User {
            id: UserId("paused".into()),
            uuid: "00000000-0000-0000-0000-000000000202".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: true,
        })
        .await
        .unwrap();
    let app = router(st.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/srv/grants/_grant-all")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let granted = st
        .inv
        .users_for_server(&ServerId("srv".into()))
        .await
        .unwrap();
    let ids: Vec<String> = granted.iter().map(|u| u.id.0.clone()).collect();
    assert_eq!(ids, vec!["alive"], "paused user must NOT be granted");
    let audit = st.inv.recent_audit(20).await.unwrap();
    let row = audit
        .iter()
        .find(|e| e.action == "server.grants.bulk_grant")
        .expect("audit row required");
    let payload = row.payload.as_ref().unwrap();
    assert_eq!(payload["granted"].as_u64(), Some(1));
    assert_eq!(payload["skipped_disabled"].as_u64(), Some(1));
}

#[tokio::test]
async fn server_revoke_all_users_requires_confirm_match() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&Server {
            id: ServerId("srv".into()),
            address: "203.0.113.21".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    st.inv
        .add_user(&User {
            id: UserId("u".into()),
            uuid: "00000000-0000-0000-0000-000000000088".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    st.inv
        .grant(&UserId("u".into()), &ServerId("srv".into()))
        .await
        .unwrap();
    let app = router(st.clone());

    // Wrong confirm → 400, grant survives.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/srv/grants/_revoke-all")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("confirm=WRONG"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let still_granted = st
        .inv
        .users_for_server(&ServerId("srv".into()))
        .await
        .unwrap();
    assert_eq!(still_granted.len(), 1, "wrong-confirm must NOT revoke");

    // Correct confirm → 303, grant gone, summary audit row.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/srv/grants/_revoke-all")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("confirm=srv"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let after = st
        .inv
        .users_for_server(&ServerId("srv".into()))
        .await
        .unwrap();
    assert!(
        after.is_empty(),
        "correct confirm must revoke; got {after:?}"
    );
    let audit = st.inv.recent_audit(20).await.unwrap();
    let row = audit
        .iter()
        .find(|e| e.action == "server.grants.bulk_revoke")
        .expect("bulk_revoke audit row required");
    assert_eq!(row.payload.as_ref().unwrap()["revoked"].as_u64(), Some(1));
}

#[tokio::test]
async fn server_detail_revoke_all_uses_data_confirm_prompt_not_inline_js() {
    // The revoke-all (destructive typed-confirm) form must wire its
    // prompt via data-attributes for admin.js, NOT an inline onsubmit —
    // CSP `script-src 'self'` blocks inline handlers, which left the
    // hidden `confirm` field empty and the POST rejected (the live bug
    // on `kg` 2026-06-06: "bulk-revoke confirm mismatch: form sent ''").
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&Server {
            id: ServerId("srv".into()),
            address: "203.0.113.22".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    st.inv
        .add_user(&User {
            id: UserId("u".into()),
            uuid: "00000000-0000-0000-0000-000000000099".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    st.inv
        .grant(&UserId("u".into()), &ServerId("srv".into()))
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/srv/grants")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    // The revoke-all form must POST to the bulk endpoint…
    assert!(
        html.contains(r#"action="/admin/servers/srv/grants/_revoke-all""#),
        "revoke-all form must render (one granted user seeded)"
    );
    // …carry the typed-confirm data-attributes admin.js consumes…
    assert!(
        html.contains("data-confirm-prompt="),
        "revoke-all must carry data-confirm-prompt for admin.js"
    );
    assert!(
        html.contains(r#"data-confirm-match="srv""#),
        "revoke-all must require typing the server id (data-confirm-match)"
    );
    // …keep the hidden confirm field admin.js populates + backend checks…
    assert!(
        html.contains(r#"name="confirm""#),
        "revoke-all must keep the hidden confirm field"
    );
    // …and use NO inline onsubmit (CSP script-src 'self' blocks it).
    assert!(
        !html.contains("onsubmit="),
        "revoke-all must not use an inline onsubmit handler"
    );
}
