use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
use vpnctld::router;

use crate::common::*;

#[tokio::test]
async fn admin_backend_error_responses_use_unified_prefix() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let body = body_of(app.clone(), "GET", "/admin/users/no-such", None, None).await;
    assert_eq!(
        body, "vpnctl admin: no such user 'no-such'\n",
        "user-not-found 404 body drifted from the copy contract"
    );

    let body = body_of(
        app.clone(),
        "POST",
        "/admin/tweak/theme",
        Some("application/x-www-form-urlencoded"),
        Some("value=neon"),
    )
    .await;
    assert_eq!(
        body,
        "vpnctl admin: invalid value 'neon' for tweak 'vpnctl_theme' \
         (allowed: default, newsprint, foxed, ink)\n",
        "tweak 400 body drifted"
    );

    let body = body_of(
        app.clone(),
        "POST",
        "/admin/tweak/whatever",
        Some("application/x-www-form-urlencoded"),
        Some("value=foxed"),
    )
    .await;
    assert_eq!(
        body, "vpnctl admin: unknown tweak kind 'whatever' (known: theme, accent, lang)\n",
        "unknown-tweak 404 body drifted"
    );
}

#[tokio::test]
async fn admin_backend_error_text_normalises_newlines_in_detail() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let body = body_of(app.clone(), "GET", "/admin/users/%0A.poison", None, None).await;
    let nl_count = body.matches('\n').count();
    assert_eq!(
        nl_count, 1,
        "error_text MUST normalise embedded \\n — body has {nl_count} newlines: {body:?}",
    );
    assert!(
        body.starts_with("vpnctl admin: no such user '"),
        "prefix survived the normalisation: {body:?}"
    );
    assert!(
        body.ends_with(".poison'\n"),
        "trailing context survived the normalisation: {body:?}"
    );
}

#[tokio::test]
async fn search_percent_is_literal_not_wildcard() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[]).await;
    let html = fetch_html(router(s), "/admin/search?q=%25").await;
    assert!(
        !html.contains("/admin/users/u0"),
        "bare % must not wildcard-match every user"
    );
}

#[tokio::test]
async fn search_masks_user_uuid() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    let html = fetch_html(router(s), "/admin/search?q=u0").await;
    assert!(
        html.contains("uuid=0000\u{2026}0000 (36 chars)")
            || html.contains("uuid=0000…0000 (36 chars)"),
        "search must render the masked uuid preview"
    );
    assert!(
        !html.contains("00000000-0000-0000-0000-000000000000"),
        "search must not leak the full uuid (it is the VLESS credential)"
    );
}

#[tokio::test]
async fn internal_error_body_does_not_leak_anyhow_chain() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/users/no-such-user")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body_str = std::str::from_utf8(&body).unwrap_or("");
    for needle in [
        "sqlx",
        "sqlite::",
        "error returned from database",
        "/var/",
        "/home/",
        "/tmp/",
        "panicked",
        "unwrap_or",
    ] {
        assert!(
            !body_str.contains(needle),
            "4xx/5xx response body must not contain «{needle}» — leak: {body_str:?}"
        );
    }
}

#[tokio::test]
async fn search_empty_q_renders_prompt_no_groups() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/search")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body_bytes).unwrap();
    assert!(
        html.contains(r#"action="/admin/search""#),
        "search form must render"
    );
    assert!(
        !html.contains("hits across") && !html.contains("совпадений"),
        "no group summary when q is empty"
    );
}

#[tokio::test]
async fn search_finds_user_by_id_substring() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_user(&User {
            id: UserId("ninitux".into()),
            uuid: "00000000-0000-0000-0000-000000000111".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/search?q=nini")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body_bytes).unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "search must return 200; body sample: {}",
        if html.len() > 400 { &html[..400] } else { html }
    );
    assert!(
        html.contains(r#"href="/admin/users/ninitux""#),
        "search must link to user detail page"
    );
}

#[tokio::test]
async fn search_finds_server_by_address_substring() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&Server {
            id: ServerId("germany".into()),
            address: "104.194.156.93".into(),
            ssh_port: 2222,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "cloudzy".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/search?q=104.194")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains(r#"href="/admin/servers/germany""#),
        "address substring must surface the server"
    );
    assert!(
        html.contains("104.194.156.93"),
        "rendered row must show the matching address"
    );
}

#[tokio::test]
async fn search_zero_hits_renders_friendly_empty_state() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/search?q=nothing-matches-this")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("No matches") || html.contains("Ничего не найдено"),
        "zero-hit empty state must render"
    );
    assert!(
        html.contains("/admin/audit"),
        "fallback link to audit page must be present"
    );
}
