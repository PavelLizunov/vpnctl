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
    assert_eq!(resp.status(), StatusCode::OK);
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
    assert_eq!(resp.status(), StatusCode::OK);
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
    assert_eq!(resp.status(), StatusCode::OK);
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

#[tokio::test]
async fn revoke_all_also_removes_disabled_users_grants() {
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
    for (id, uuid, disabled) in [
        ("alice", "00000000-0000-0000-0000-0000000000a1", false),
        ("bob", "00000000-0000-0000-0000-0000000000b1", true),
    ] {
        st.inv
            .add_user(&User {
                id: UserId(id.into()),
                uuid: uuid.into(),
                tuic_password: None,
                wireguard_pubkey: None,
                wireguard_private: None,
                sub_token: None,
                vpn_router_device_id: None,
                disabled,
            })
            .await
            .unwrap();
        st.inv
            .grant(&UserId(id.into()), &ServerId("srv".into()))
            .await
            .unwrap();
    }

    let resp = router(st.clone())
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
    assert_eq!(resp.status(), StatusCode::OK);
    let left = st
        .inv
        .grant_dates_for_server(&ServerId("srv".into()))
        .await
        .unwrap();
    assert!(
        left.is_empty(),
        "a disabled user's grant must not survive revoke-all: {left:?}"
    );
}

fn inject_grant_failure(dir: &TempDir, sql: &str) {
    let status = std::process::Command::new("python3")
        .args(["-c", "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.executescript(sys.argv[2]); c.commit(); c.close()"])
        .arg(dir.path().join("inv.db"))
        .arg(sql)
        .status()
        .unwrap();
    assert!(status.success(), "temporary grant fault injection failed");
}

#[tokio::test]
async fn revoke_handlers_preserve_grants_when_audit_fails() {
    for (path, body, expected_status) in [
        (
            "/admin/users/u0/grants/s0/revoke",
            "",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            "/admin/servers/s0/grants/u0/revoke",
            "",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            "/admin/servers/s0/grants/_revoke-all",
            "confirm=s0",
            StatusCode::OK,
        ),
    ] {
        let dir = TempDir::new().unwrap();
        let st = state(&dir).await;
        crate::common::seed(&st.inv, 1, 1, &[(0, 0)]).await;
        inject_grant_failure(
            &dir,
            "CREATE TRIGGER fail_revoke_audit BEFORE INSERT ON audit_log
             WHEN NEW.action = 'user.revoke'
             BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;",
        );
        let resp = router(st.clone())
            .oneshot(
                crate::common::add_same_origin(Request::builder().method("POST").uri(path))
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), expected_status, "{path}");
        assert_eq!(st.inv.count_grants().await.unwrap(), 1, "{path}");
        assert!(st.inv.recent_audit(10).await.unwrap().is_empty(), "{path}");
    }
}

#[tokio::test]
async fn grant_all_result_reports_uuid_conflict_and_success_counts() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    crate::common::seed(&st.inv, 1, 3, &[(0, 0)]).await;
    // u0's imported UUID reserves u1's global UUID on this server.
    st.inv
        .set_grant_client_uuid(
            &UserId("u0".into()),
            &ServerId("s0".into()),
            "00000000-0000-0000-0000-000000000001",
        )
        .await
        .unwrap();
    let resp = router(st.clone())
        .oneshot(
            crate::common::add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s0/grants/_grant-all"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&bytes).unwrap();
    assert!(html.contains("Granted: 1; already granted: 1; disabled users skipped: 0; failed: 1."));
    assert!(html.contains("<b>u1</b>: "));
    assert!(html.contains("already used by user u0"));
    assert!(html.contains("Back to server access"));
    assert!(html.contains(
        "These counts describe saved access changes. Check deployment status on the server page."
    ));
    let ids: Vec<_> = st
        .inv
        .grant_dates_for_server(&ServerId("s0".into()))
        .await
        .unwrap()
        .into_iter()
        .map(|(uid, _)| uid.0)
        .collect();
    assert_eq!(ids, ["u0", "u2"]);
}

#[tokio::test]
async fn revoke_all_result_reports_partial_failure_and_escapes_reason() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    crate::common::seed(&st.inv, 1, 2, &[(0, 0), (1, 0)]).await;
    inject_grant_failure(
        &dir,
        "CREATE TRIGGER fail_one_revoke BEFORE DELETE ON grants
         WHEN OLD.user_id = 'u1'
         BEGIN SELECT RAISE(ABORT, 'blocked <user>'); END;",
    );
    let resp = router(st.clone())
        .oneshot(
            crate::common::add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s0/grants/_revoke-all"),
            )
            .body(Body::from("confirm=s0"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&bytes).unwrap();
    assert!(html.contains("Revoked: 1; failed: 1."));
    assert!(html.contains("<b>u1</b>: "));
    assert!(html.contains("blocked &lt;user&gt;"));
    assert!(!html.contains("blocked <user>"));
    let remaining = st
        .inv
        .grant_dates_for_server(&ServerId("s0".into()))
        .await
        .unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].0.0, "u1");
    let rows = st.inv.recent_audit(20).await.unwrap();
    let revokes: Vec<_> = rows.iter().filter(|r| r.action == "user.revoke").collect();
    assert_eq!(revokes.len(), 1);
    assert_eq!(revokes[0].target.as_deref(), Some("u0"));
}

#[tokio::test]
async fn bulk_no_op_results_do_not_write_mutation_audit() {
    for (action, body, grants, summary) in [
        (
            "_grant-all",
            "",
            vec![(0, 0)],
            "Granted: 0; already granted: 1; disabled users skipped: 0; failed: 0.",
        ),
        (
            "_revoke-all",
            "confirm=s0",
            vec![],
            "Revoked: 0; failed: 0.",
        ),
    ] {
        let dir = TempDir::new().unwrap();
        let st = state(&dir).await;
        crate::common::seed(&st.inv, 1, 1, &grants).await;
        let resp = router(st.clone())
            .oneshot(
                crate::common::add_same_origin(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/admin/servers/s0/grants/{action}")),
                )
                .body(Body::from(body))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(std::str::from_utf8(&bytes).unwrap().contains(summary));
        assert!(st.inv.recent_audit(10).await.unwrap().is_empty());
    }
}
