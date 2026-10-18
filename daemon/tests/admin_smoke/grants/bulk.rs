use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
use vpnctld::router;

use crate::common::state;

#[tokio::test]
async fn user_create_with_grant_all_grants_every_registered_server() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
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
    assert!(
        html.contains(r#"name="grant_all""#),
        "user form must include grant_all checkbox"
    );
    assert!(
        html.contains(r#"checked="checked""#) || html.contains("checked=\"checked\""),
        "checkbox must default to CHECKED — found no checked attribute in the form"
    );
}

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
    let audit = st.inv.recent_audit(20).await.unwrap();
    let row = audit
        .iter()
        .find(|e| e.action == "server.grants.bulk_grant")
        .expect("bulk_grant audit row required");
    let payload = row.payload.as_ref().unwrap();
    assert_eq!(payload["granted"].as_u64(), Some(3));
    assert_eq!(payload["already_granted"].as_u64(), Some(0));
    assert_eq!(payload["failed"].as_u64(), Some(0));
    assert_eq!(payload["skipped_disabled"].as_u64(), Some(0));
}

#[tokio::test]
async fn server_grant_all_skips_disabled_users() {
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
    assert!(
        html.contains(r#"action="/admin/servers/srv/grants/_revoke-all""#),
        "revoke-all form must render (one granted user seeded)"
    );
    assert!(
        html.contains("data-confirm-prompt="),
        "revoke-all must carry data-confirm-prompt for admin.js"
    );
    assert!(
        html.contains(r#"data-confirm-match="srv""#),
        "revoke-all must require typing the server id (data-confirm-match)"
    );
    assert!(
        html.contains(r#"name="confirm""#),
        "revoke-all must keep the hidden confirm field"
    );
    assert!(
        !html.contains("onsubmit="),
        "revoke-all must not use an inline onsubmit handler"
    );
}
