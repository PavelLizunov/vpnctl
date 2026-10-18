use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::UserId;
use vpnctld::router;

use crate::common::*;

#[tokio::test]
async fn admin_unmatched_paths_do_not_leak_admin_fingerprint() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    for path in [
        "/etc/passwd",
        "/",
        "/foo",
        "/.env",
        "/wp-login.php",
        "/api/v2/something",
    ] {
        let req = Request::builder().uri(path).body(Body::empty()).unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let headers = resp.headers().clone();
        assert!(
            headers.get("content-security-policy").is_none(),
            "GET {path} leaks CSP header (admin fingerprint)"
        );
        assert!(
            headers.get("x-frame-options").is_none(),
            "GET {path} leaks X-Frame-Options (admin fingerprint)"
        );
        assert!(
            headers.get("permissions-policy").is_none(),
            "GET {path} leaks Permissions-Policy (admin fingerprint)"
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let s = String::from_utf8_lossy(&body);
        assert!(
            !s.contains("vpnctl admin"),
            "GET {path} leaks 'vpnctl admin' in body: {s}"
        );

        let req = Request::builder()
            .uri(path)
            .method("POST")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("x=1"))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let s = String::from_utf8_lossy(&body);
        assert!(
            !s.contains("vpnctl admin"),
            "POST {path} leaks 'vpnctl admin' in body: {s}"
        );
        assert!(
            !s.contains("csrf"),
            "POST {path} leaks CSRF copy in body: {s}"
        );
    }

    let req = Request::builder()
        .uri("/admin")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get("content-security-policy").is_some(),
        "admin pages MUST still carry CSP — security-headers layer broken"
    );
}

#[tokio::test]
async fn admin_responses_carry_security_headers() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let headers = resp.headers();
    let csp = headers
        .get("content-security-policy")
        .expect("CSP must be set on /admin/* responses")
        .to_str()
        .unwrap();
    assert!(
        csp.contains("default-src 'self'"),
        "CSP must default to self"
    );
    assert!(
        csp.contains("script-src 'self'") && !csp.contains("script-src 'self' 'unsafe-inline'"),
        "script-src MUST NOT include 'unsafe-inline' — XSS defense: {csp}"
    );
    assert!(
        csp.contains("frame-ancestors 'none'"),
        "frame-ancestors must be 'none' — clickjacking defense: {csp}"
    );
    assert!(
        csp.contains("object-src 'none'"),
        "object-src must be 'none' — legacy plugin/PDF defense: {csp}"
    );
    assert_eq!(
        headers
            .get("x-content-type-options")
            .map(|v| v.to_str().unwrap()),
        Some("nosniff")
    );
    assert_eq!(
        headers.get("x-frame-options").map(|v| v.to_str().unwrap()),
        Some("DENY")
    );
    assert_eq!(
        headers.get("referrer-policy").map(|v| v.to_str().unwrap()),
        Some("same-origin")
    );
    let perm = headers
        .get("permissions-policy")
        .expect("Permissions-Policy must be set")
        .to_str()
        .unwrap();
    assert!(
        perm.contains("camera=()")
            && perm.contains("microphone=()")
            && perm.contains("geolocation=()"),
        "Permissions-Policy must block sensor / device APIs: {perm}"
    );
}

#[tokio::test]
async fn no_operator_facing_output_asks_for_manual_ssh_edit() {
    use vpnctld::alert_sink::classify_ssh_failure;

    let msg = classify_ssh_failure(
        "ssh transport error: ssh root@1.2.3.4:22 exit=Some(255) \
         stderr=root@1.2.3.4: Permission denied (publickey,password).",
    );
    assert!(
        !msg.contains("echo '<paste>'") && !msg.contains(">> ~/.ssh/authorized_keys"),
        "classify_ssh_failure MUST NOT instruct manual authorized_keys edit: {msg}"
    );
    assert!(
        msg.contains("push deploy key"),
        "classify_ssh_failure SHOULD point at the «push deploy key» button: {msg}"
    );

    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/settings/system")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body_bytes).unwrap();
    assert!(
        !html.contains("echo '<paste>' >> ~/.ssh/authorized_keys"),
        "Deploy SSH key section MUST NOT contain the manual echo …>> instruction"
    );
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/alerts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body_bytes).unwrap();
    assert!(
        !html.contains("ssh into the node out-of-band"),
        "alerts page must NOT ask operator to ssh into the node"
    );
}

#[tokio::test]
async fn admin_csrf_post_without_origin_is_403() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/tweak/theme")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("value=foxed"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "POST without Origin must be rejected by CSRF middleware"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    assert!(
        s.starts_with("vpnctl admin: csrf"),
        "CSRF reject body must use unified prefix, got: {s:?}"
    );
}

#[tokio::test]
async fn admin_csrf_post_with_mismatched_origin_is_403() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    let before = s
        .inv
        .get_user(&UserId("u0".into()))
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .unwrap();

    let app = router(s.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users/u0/sub-token/regenerate")
                .header("host", "test.example")
                .header("origin", "http://evil.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "cross-origin POST must be rejected by CSRF middleware"
    );
    let after = s
        .inv
        .get_user(&UserId("u0".into()))
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .unwrap();
    assert_eq!(
        before, after,
        "sub_token must be unchanged after CSRF-rejected POST"
    );
}

#[tokio::test]
async fn admin_csrf_get_passes_through_without_origin() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET on /admin/ must pass through CSRF middleware regardless of Origin"
    );
}

#[tokio::test]
async fn admin_csrf_referer_fallback_when_origin_absent() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/tweak/theme")
                .header("host", "test.example")
                .header("referer", "http://test.example/admin/")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("value=foxed"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status() == StatusCode::SEE_OTHER || resp.status() == StatusCode::TEMPORARY_REDIRECT,
        "same-origin Referer (no Origin) must pass CSRF, got {:?}",
        resp.status()
    );
}

#[tokio::test]
async fn admin_csrf_referer_fallback_when_origin_is_literal_null() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/tweak/theme")
                .header("host", "test.example")
                .header("origin", "null")
                .header("referer", "http://test.example/admin/users")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("value=foxed"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status() == StatusCode::SEE_OTHER || resp.status() == StatusCode::TEMPORARY_REDIRECT,
        "`Origin: null` + same-origin Referer must pass CSRF \
         (this exact scenario bricked prod 2026-05-19), got {:?}",
        resp.status()
    );
}

#[tokio::test]
async fn admin_csrf_403_body_shows_host_origin_referer_and_cause() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/tweak/theme")
                .header("host", "real.example")
                .header("origin", "null")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("value=foxed"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();

    assert!(
        text.contains("Host:    real.example"),
        "Host missing from body: {text}"
    );
    assert!(
        text.contains("Origin:  null"),
        "Origin (literal `null`) missing: {text}"
    );
    assert!(
        text.contains("Referer: (absent)"),
        "Referer state missing: {text}"
    );
    assert!(
        text.contains("opaque origin"),
        "must explain the `Origin: null` case in plain English: {text}"
    );
}

#[tokio::test]
async fn admin_referrer_policy_header_is_same_origin_not_no_referrer() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let policy = resp
        .headers()
        .get("referrer-policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        policy, "same-origin",
        "Referrer-Policy must be `same-origin` (NOT `no-referrer` — that bricks the CSRF middleware)"
    );
}

#[tokio::test]
async fn admin_audit_timeline_summary_never_leaks_secret_fields() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .audit(
            "admin",
            "user.add",
            Some("alice"),
            Some(&serde_json::json!({
                "uuid": "aaa-bbb",
                "wg_keypair_provenance": "server-generated",
                "tuic_password": "PW_SECRET_LEAK_CHECK",
                "wireguard_private": "PRIV_SECRET_LEAK_CHECK",
                "sub_token": "TOKEN_SECRET_LEAK_CHECK",
            })),
        )
        .await
        .unwrap();
    let app = router(s);
    let html = fetch_html(app, "/admin/audit").await;
    assert!(html.contains("wg_keypair_provenance=server-generated"));
    for leak in [
        "PW_SECRET_LEAK_CHECK",
        "PRIV_SECRET_LEAK_CHECK",
        "TOKEN_SECRET_LEAK_CHECK",
    ] {
        assert!(
            !html.contains(leak),
            "audit summary leaked {leak} into HTML"
        );
    }
}

#[tokio::test]
async fn admin_pages_contain_no_shell_command_instructions() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    seed(&st.inv, 1, 1, &[(0, 0)]).await;

    let pages = [
        "/admin/",
        "/admin/servers",
        "/admin/servers/s0",
        "/admin/servers/s0/protocols",
        "/admin/users",
        "/admin/users/u0",
        "/admin/monitoring",
        "/admin/activity",
        "/admin/settings/appearance",
        "/admin/settings/notifications",
        "/admin/settings/system",
        "/admin/alerts",
    ];
    let needles = [
        "journalctl",
        "systemctl",
        "ssh root@",
        "ls -la",
        "age -d",
        "vpnctl bootstrap",
        "vpnctl deploy",
        "vpnctl geoip-update",
        "vpnctl grant",
        "vpnctl restore",
        "vpnctl server add",
        "vpnctl user",
        "--gen-wireguard",
        "see vpnctld logs",
    ];
    let app = router(st);
    for path in pages {
        let html = fetch_html(app.clone(), path).await;
        for needle in needles {
            assert!(
                !html.contains(needle),
                "rendered page {path} must not contain shell-command instruction «{needle}» — operator copy is web-only"
            );
        }
    }

    let backups = fetch_html(app, "/admin/settings/backups").await;
    for command in [
        "age -d -i /path/to/vpnctl-backup-key.age",
        "vpnctl restore /path/to/inv.db",
        "systemctl restart vpnctld",
    ] {
        assert_eq!(
            backups.matches(command).count(),
            1,
            "the disaster-recovery runbook must contain exactly one {command:?}"
        );
    }
    let backups_without_recovery_commands = backups
        .replace("age -d -i /path/to/vpnctl-backup-key.age", "")
        .replace("vpnctl restore /path/to/inv.db", "")
        .replace("systemctl restart vpnctld", "");
    for needle in needles {
        assert!(
            !backups_without_recovery_commands.contains(needle),
            "settings/backups contains an unexpected shell instruction {needle:?}"
        );
    }
}
