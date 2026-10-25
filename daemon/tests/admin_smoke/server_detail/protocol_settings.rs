use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::TempDir;
use tower::ServiceExt;
use vpnctl_core::{ProtocolId, RenderCtx, ServerId};
use vpnctld::{AppState, router};

use crate::common::*;

async fn fixture(dir: &TempDir) -> AppState {
    let s = state(dir).await;
    seed(&s.inv, 2, 0, &[]).await;
    s.inv
        .add_server_protocol(&ServerId("s0".into()), &ProtocolId("hysteria2".into()))
        .await
        .unwrap();
    for (key, value) in [
        ("vless.public_key", "fixture-public-key"),
        ("vless.short_id", "deadbeef"),
        ("hysteria2.obfs.password", "fixture-old-obfs"),
    ] {
        s.inv
            .set_server_secret(&ServerId("s0".into()), key, value)
            .await
            .unwrap();
    }
    s.inv
        .audit("test", "server.deploy", Some("s0"), None)
        .await
        .unwrap();
    s
}

async fn post(s: &AppState, suffix: &str, body: &str) -> axum::response::Response {
    router(s.clone())
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri(format!("/admin/servers/s0/{suffix}"))
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from(body.to_owned()))
            .unwrap(),
        )
        .await
        .unwrap()
}

async fn share_links(s: &AppState) -> (String, String) {
    let sid = ServerId("s0".into());
    let server = s.inv.get_server(&sid).await.unwrap().unwrap();
    let secrets = s.inv.list_server_secrets(&sid).await.unwrap();
    let ctx = RenderCtx::new(&server, &secrets);
    let mut user = mk_user("fixture", false);
    user.tuic_password = Some("fixture-client-password".into());
    let link = |id: &str| {
        s.registry
            .protocol(&ProtocolId(id.into()))
            .unwrap()
            .share_link(&ctx, &user)
            .unwrap()
    };
    (link("vless+reality"), link("hysteria2"))
}

#[tokio::test]
async fn protocol_settings_forms_render_localized_values_without_obfs_password() {
    let dir = TempDir::new().unwrap();
    let s = fixture(&dir).await;
    let en = fetch_html(router(s.clone()), "/admin/servers/s0/protocols").await;
    assert!(en.contains(r#"name="sni" maxlength="253" required value="yahoo.com""#));
    assert!(en.contains(r#"action="/admin/servers/s0/hysteria2-obfs-rotate""#));
    assert!(en.contains("refresh their subscription after the deploy"));
    assert!(!en.contains("fixture-old-obfs"));
    s.inv
        .set_server_secret(&ServerId("s0".into()), "vless.sni", "www.example.org")
        .await
        .unwrap();
    let ru = fetch_html_with_cookie(
        router(s.clone()),
        "/admin/servers/s0/protocols",
        "vpnctl_lang=ru",
    )
    .await;
    assert!(ru.contains(r#"value="www.example.org""#));
    assert!(ru.contains("домен рукопожатия"));
    assert!(ru.contains("сменить пароль обфускации"));
    assert!(ru.contains("при обновлении подписки после деплоя"));
    assert!(!ru.contains("fixture-old-obfs"));
    let disabled = fetch_html(router(s), "/admin/servers/s1/protocols").await;
    assert!(!disabled.contains("/hysteria2-obfs-rotate"));
}

#[tokio::test]
async fn reality_sni_save_audits_changes_only_and_preserves_other_link_bytes() {
    let dir = TempDir::new().unwrap();
    let s = fixture(&dir).await;
    let sid = ServerId("s0".into());
    let before = share_links(&s).await;
    assert_eq!(
        before.0.as_bytes(),
        b"vless://uuid-fixture@10.0.0.0:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=yahoo.com&fp=randomized&pbk=fixture-public-key&sid=deadbeef&type=tcp&packetEncoding=xudp#fixture"
    );
    assert_eq!(
        before.1.as_bytes(),
        b"hysteria2://fixture-client-password@10.0.0.0:8444/?sni=10.0.0.0&insecure=1&obfs=salamander&obfs-password=fixture-old-obfs#fixture"
    );
    let resp = post(
        &s,
        "reality-config",
        "listen_port=&sni=%20www.example.org%20",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(resp.headers()["location"], "/admin/servers/s0/protocols");
    assert_eq!(
        s.inv
            .get_server_secret(&sid, "vless.sni")
            .await
            .unwrap()
            .as_deref(),
        Some("www.example.org")
    );
    assert!(s.inv.server_pending_deploy(&sid).await.unwrap());
    let audit = s.inv.recent_audit(1).await.unwrap();
    assert_eq!(audit[0].action, "server.reality.set");
    assert_eq!(audit[0].target.as_deref(), Some("s0"));
    assert_eq!(
        audit[0].payload,
        Some(serde_json::json!({"keys": ["vless.sni"]}))
    );
    let after = share_links(&s).await;
    assert_eq!(
        after.0.as_bytes(),
        before
            .0
            .replace("sni=yahoo.com&", "sni=www.example.org&")
            .as_bytes()
    );
    assert_eq!(after.1.as_bytes(), before.1.as_bytes());

    s.inv
        .audit("test", "server.deploy", Some("s0"), None)
        .await
        .unwrap();
    let latest = s.inv.recent_audit(1).await.unwrap()[0].id;
    assert_eq!(
        post(&s, "reality-config", "listen_port=&sni=www.example.org")
            .await
            .status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(s.inv.recent_audit(1).await.unwrap()[0].id, latest);
    assert!(!s.inv.server_pending_deploy(&sid).await.unwrap());
    assert_eq!(share_links(&s).await, after);

    // Existing port-only callers preserve the stored SNI.
    assert_eq!(
        post(&s, "reality-config", "listen_port=8443")
            .await
            .status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        s.inv
            .get_server_secret(&sid, "vless.sni")
            .await
            .unwrap()
            .as_deref(),
        Some("www.example.org")
    );
}

#[tokio::test]
async fn reality_sni_rejects_invalid_hostnames_without_mutations() {
    let dir = TempDir::new().unwrap();
    let s = fixture(&dir).await;
    let sid = ServerId("s0".into());
    let before = s.inv.list_server_secrets(&sid).await.unwrap();
    let latest = s.inv.recent_audit(1).await.unwrap()[0].id;
    let long_label = format!("{}.org", "a".repeat(64));
    let long_name = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(63)
    );
    for sni in [
        "",
        "example..org",
        "-bad.org",
        "bad-.org",
        "bad_name.org",
        "127.0.0.1",
        "::1",
        "https://example.org",
        "example.org%26evil=1",
        "bad%0A.org",
        "bad%20name.org",
        "пример.рф",
        &long_label,
        &long_name,
    ] {
        assert_eq!(
            post(&s, "reality-config", &format!("listen_port=8443&sni={sni}"))
                .await
                .status(),
            StatusCode::BAD_REQUEST,
            "SNI: {sni}"
        );
    }
    assert_eq!(
        post(&s, "reality-config", "listen_port=0&sni=valid.example.org")
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(s.inv.list_server_secrets(&sid).await.unwrap(), before);
    assert_eq!(s.inv.recent_audit(1).await.unwrap()[0].id, latest);
}

#[tokio::test]
async fn hysteria2_rotation_generates_secret_audits_and_preserves_other_link_bytes() {
    let dir = TempDir::new().unwrap();
    let s = fixture(&dir).await;
    let sid = ServerId("s0".into());
    let mut previous = "fixture-old-obfs".to_owned();
    for _ in 0..2 {
        s.inv
            .audit("test", "server.deploy", Some("s0"), None)
            .await
            .unwrap();
        assert!(!s.inv.server_pending_deploy(&sid).await.unwrap());
        let before = share_links(&s).await;
        let resp = post(&s, "hysteria2-obfs-rotate", "password=browser-supplied").await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers()["location"], "/admin/servers/s0/protocols");
        let password = s
            .inv
            .get_server_secret(&sid, "hysteria2.obfs.password")
            .await
            .unwrap()
            .unwrap();
        assert_ne!(password, previous);
        assert_ne!(password, "browser-supplied");
        assert_eq!(password.len(), 32);
        assert!(
            password
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        );
        assert!(s.inv.server_pending_deploy(&sid).await.unwrap());
        let audit = s.inv.recent_audit(1).await.unwrap();
        assert_eq!(audit[0].action, "server.secret.set");
        assert_eq!(audit[0].target.as_deref(), Some("s0"));
        assert_eq!(
            audit[0].payload,
            Some(serde_json::json!({"keys": ["hysteria2.obfs.password"]}))
        );
        let html = fetch_html(router(s.clone()), "/admin/servers/s0/protocols").await;
        assert!(!html.contains(&password));
        let after = share_links(&s).await;
        assert_ne!(after.1.as_bytes(), before.1.as_bytes());
        assert_eq!(after.0.as_bytes(), before.0.as_bytes());
        assert_eq!(
            after.1.as_bytes(),
            before
                .1
                .replace(
                    &format!("obfs-password={previous}#"),
                    &format!("obfs-password={password}#")
                )
                .as_bytes()
        );
        previous = password;
    }
}

#[tokio::test]
async fn protocol_settings_posts_require_csrf_and_existing_enabled_server() {
    let dir = TempDir::new().unwrap();
    let s = fixture(&dir).await;
    let before = s
        .inv
        .list_server_secrets(&ServerId("s0".into()))
        .await
        .unwrap();
    let latest = s.inv.recent_audit(1).await.unwrap()[0].id;
    for suffix in ["reality-config", "hysteria2-obfs-rotate"] {
        for origin in [None, Some("https://evil.example")] {
            let mut req = Request::builder()
                .method("POST")
                .uri(format!("/admin/servers/s0/{suffix}"))
                .header("host", SAME_ORIGIN_HOST);
            if let Some(origin) = origin {
                req = req.header("origin", origin);
            }
            let resp = router(s.clone())
                .oneshot(
                    req.body(Body::from("listen_port=&sni=example.org"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        }
        let resp = router(s.clone())
            .oneshot(
                add_same_origin(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/admin/servers/missing/{suffix}")),
                )
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
    assert_eq!(
        s.inv
            .list_server_secrets(&ServerId("s0".into()))
            .await
            .unwrap(),
        before
    );
    assert_eq!(s.inv.recent_audit(1).await.unwrap()[0].id, latest);
    s.inv
        .remove_server_protocol(&ServerId("s0".into()), &ProtocolId("hysteria2".into()))
        .await
        .unwrap();
    let latest = s.inv.recent_audit(1).await.unwrap()[0].id;
    assert_eq!(
        post(&s, "hysteria2-obfs-rotate", "").await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        s.inv
            .get_server_secret(&ServerId("s0".into()), "hysteria2.obfs.password")
            .await
            .unwrap()
            .as_deref(),
        Some("fixture-old-obfs")
    );
    assert_eq!(s.inv.recent_audit(1).await.unwrap()[0].id, latest);
}
