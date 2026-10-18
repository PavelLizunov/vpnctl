use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctld::router;

use crate::common::*;

#[tokio::test]
async fn admin_user_detail_renders_qr_grants_and_share_links() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 1, &[(0, 0), (0, 1)]).await;

    s.inv
        .set_server_secret(
            &ServerId("s0".into()),
            "vless.private_key",
            "QGZ8K-private-key-base64==",
        )
        .await
        .unwrap();
    s.inv
        .set_server_secret(
            &ServerId("s0".into()),
            "vless.public_key",
            "PUBLIC-KEY-BASE64=",
        )
        .await
        .unwrap();
    s.inv
        .set_server_secret(&ServerId("s0".into()), "vless.short_id", "deadbeef")
        .await
        .unwrap();
    s.inv
        .set_server_secret(&ServerId("s0".into()), "vless.sni", "www.microsoft.com")
        .await
        .unwrap();

    let u0 = s.inv.get_user(&UserId("u0".into())).await.unwrap().unwrap();
    let token = u0.sub_token.expect("token");

    let app = router(s);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/users/u0")
                .header("host", "192.168.0.236:18402")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&bytes).unwrap();

    assert!(html.contains("<svg "), "QR svg missing");
    assert!(
        html.contains("border: 1px solid var(--rule)"),
        "QR card border styling missing"
    );
    let expected_url = format!("http://192.168.0.236:18402/sub/{token}");
    assert!(
        html.contains(&expected_url),
        "sub URL should use the Host header (expected {expected_url})"
    );
    let occurrences = html.matches(token.as_str()).count();
    assert_eq!(
        occurrences, 1,
        "sub_token should appear exactly once (inside the sub URL), got {occurrences}"
    );
    let fetch_tab = |uri: &'static str| {
        let app = app.clone();
        async move {
            let resp = app
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .header("host", "192.168.0.236:18402")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            String::from_utf8(bytes.to_vec()).unwrap()
        }
    };
    let html_access = fetch_tab("/admin/users/u0/access").await;
    for id in ["s0", "s1"] {
        assert!(html_access.contains(id), "granted server {id} missing");
    }
    let html_delivery = fetch_tab("/admin/users/u0/delivery").await;
    assert!(
        html_delivery.contains("vless://") || html_delivery.contains("Per-protocol share links"),
        "expected share-links section, got snippet: {}",
        &html_delivery[..html_delivery.len().min(800)]
    );

    assert!(
        html.contains("vpnctl-qr-frame"),
        "QR frame wrapper class must be present so the inline style can target it"
    );
    assert!(
        html.contains(".vpnctl-qr-frame svg") || html.contains(".vpnctl-qr-frame > svg"),
        "inline CSS targeting the QR's SVG child must be present"
    );
    assert!(
        !html.contains(".vpnctl-qr-frame &gt; svg"),
        "Maud escaped `>` in the QR CSS selector — selector is invalid and \
         the size-normalisation CSS will silently fail. Use a descendant \
         selector (no `>`) or wrap the CSS string in PreEscaped."
    );
}

#[tokio::test]
async fn admin_user_detail_handles_missing_sub_token() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;

    let u0 = s.inv.get_user(&UserId("u0".into())).await.unwrap().unwrap();
    assert!(
        u0.sub_token.is_some(),
        "open() should have backfilled — None branch is currently unreachable via public API"
    );

    let html = fetch_html(router(s), "/admin/users/u0/overview").await;
    assert!(
        html.contains("Subscription"),
        "subscription section heading missing"
    );
    assert!(
        !html.contains("No sub-token assigned"),
        "user has a token — must not render the 'no token' fallback"
    );
}

#[tokio::test]
async fn admin_user_detail_renders_ninitux_url_as_primary_when_device_id_pinned() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    s.inv
        .set_vpn_router_device_id(&UserId("u0".into()), TEST_NINITUX_DEVICE_ID)
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/users/u0/overview").await;

    let expected_ninitux =
        format!("https://ninitux.com/api/v1/app/config/{TEST_NINITUX_DEVICE_ID}");
    assert!(
        html.contains(&expected_ninitux),
        "ninitux production URL must be rendered as the primary subscription URL — \
         expected substring: {expected_ninitux}"
    );
    assert!(
        html.contains(TEST_NINITUX_DEVICE_ID),
        "vpn_router_device_id must be displayed in the Subscription section"
    );
    assert!(
        html.contains("legacy /sub/&lt;token&gt; fallback")
            || html.contains("legacy /sub/<token> fallback"),
        "legacy /sub/<token> URL must be present BUT demoted inside a <details> labelled 'legacy'"
    );
}

#[tokio::test]
async fn admin_user_detail_qr_encodes_ninitux_url_not_lan_url_when_device_id_pinned() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    s.inv
        .set_vpn_router_device_id(&UserId("u0".into()), TEST_NINITUX_DEVICE_ID)
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/users/u0/overview").await;

    let n_pos = html
        .find("https://ninitux.com/api/v1/app/config/")
        .expect("ninitux URL must appear");
    let lan_pos = html
        .find("/sub/")
        .expect("legacy LAN URL must appear (in collapsed fallback)");
    assert!(
        n_pos < lan_pos,
        "ninitux URL ({n_pos}) must appear BEFORE the LAN URL ({lan_pos}) so the \
         QR card encodes ninitux. Otherwise QR encodes the LAN URL = mobile clients break."
    );
}

#[tokio::test]
async fn admin_user_detail_falls_back_to_lan_url_when_no_device_id() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    let u0 = s.inv.get_user(&UserId("u0".into())).await.unwrap().unwrap();
    assert!(u0.vpn_router_device_id.is_none());

    let html = fetch_html(router(s), "/admin/users/u0/overview").await;
    assert!(
        !html.contains("https://ninitux.com/api/v1/app/config/"),
        "no device_id pinned → ninitux URL must NOT render"
    );
    assert!(
        html.contains("scripts/import_from_subscription_server.py"),
        "empty-state must point operator at the import script to pin a device_id"
    );
    assert!(html.contains("Subscription"));
}

#[tokio::test]
async fn admin_user_regen_sub_token_mutates_and_audits() {
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
        .expect("open() backfilled a token");

    let app = router(s.clone());
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/u0/sub-token/regenerate"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "expected 303 (POST-redirect-GET), got {:?}",
        resp.status()
    );
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/admin/users/u0/overview",
        "redirect target must be the user-detail page"
    );

    let after = s
        .inv
        .get_user(&UserId("u0".into()))
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .expect("token still present");
    assert_ne!(
        before, after,
        "sub_token must be different after regenerate"
    );

    let entries = s.inv.recent_audit(10).await.unwrap();
    let regen = entries
        .iter()
        .find(|e| e.action == "user.sub_token.regen")
        .expect("audit row for user.sub_token.regen missing");
    assert_eq!(regen.actor, "admin");
    assert_eq!(regen.target.as_deref(), Some("u0"));
    assert!(
        regen.payload.is_none(),
        "regen audit row should carry no payload (token MUST NOT be logged)"
    );
}

#[tokio::test]
async fn admin_user_regen_sub_token_404_for_unknown_user() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let body = body_of(
        app,
        "POST",
        "/admin/users/no-such/sub-token/regenerate",
        None,
        None,
    )
    .await;
    assert_eq!(
        body, "vpnctl admin: no such user 'no-such'\n",
        "404 body for missing user drifted from the copy contract"
    );
}

#[tokio::test]
async fn admin_user_detail_renders_rotate_button() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    let app = router(s);

    let html = fetch_html(app, "/admin/users/u0/overview").await;
    assert!(
        html.contains(r#"action="/admin/users/u0/sub-token/regenerate""#),
        "rotate-button form must POST to /admin/users/u0/sub-token/regenerate"
    );
    assert!(
        html.contains(">rotate sub-token<"),
        "rotate-button label drifted from 'rotate sub-token'"
    );
}

#[tokio::test]
async fn admin_user_detail_after_regen_shows_new_token() {
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
    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/u0/sub-token/regenerate"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();

    let after = s
        .inv
        .get_user(&UserId("u0".into()))
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .unwrap();

    let html = fetch_html(app, "/admin/users/u0/overview").await;
    assert!(
        html.contains(&after),
        "detail page must render the NEW sub_token after regenerate"
    );
    assert!(
        !html.contains(&before),
        "detail page must NOT render the previous sub_token after regenerate \
         (would be a stale-token leak)"
    );
}

#[tokio::test]
async fn admin_user_detail_flow_a_card_uses_share_link_card_with_copy_textarea() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();

    inv.add_server(&Server {
        id: ServerId("wg1".into()),
        address: "203.0.113.7".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("wg1".into()),
        "wireguard.server_public_key",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("wg1".into()),
        "wireguard.server_private_key",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    )
    .await
    .unwrap();
    inv.add_user(&User {
        id: UserId("flowtest".into()),
        uuid: "11111111-1111-1111-1111-111111111111".into(),
        tuic_password: Some("tp".into()),
        wireguard_pubkey: Some("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=".into()),
        wireguard_private: Some("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=".into()),
        sub_token: Some("subtok-flowtest-abc123".into()),
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    inv.grant(&UserId("flowtest".into()), &ServerId("wg1".into()))
        .await
        .unwrap();

    let app = router(s);
    let html = fetch_html(app, "/admin/users/flowtest/delivery").await;

    assert!(
        html.contains("data-select-on-click"),
        "share_link_card textarea must carry data-select-on-click for the admin.js wiring"
    );
    assert!(
        !html.contains("onclick="),
        "no inline event handlers — the CSP refuses them silently"
    );
    let token_substr = "/sub/subtok-flowtest-abc123";
    let token_at = html
        .rfind(token_substr)
        .unwrap_or_else(|| panic!("sub-token substring missing from page: {token_substr}"));
    let window_start = token_at.saturating_sub(800);
    let before = &html[window_start..token_at];
    assert!(
        before.contains("<textarea readonly"),
        "Flow A sub-token must appear inside a `<textarea readonly>` block — got window before token: {before:?}"
    );
    assert!(
        html.contains("Sing-box / Hiddify pulls the full config"),
        "Flow A footnote regressed"
    );
}

#[tokio::test]
async fn admin_user_detail_flow_b_card_includes_full_wireguard_link_in_textarea() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_server(&Server {
        id: ServerId("wg2".into()),
        address: "203.0.113.8".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("wg2".into()),
        "wireguard.server_public_key",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("wg2".into()),
        "wireguard.server_private_key",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    )
    .await
    .unwrap();
    inv.add_user(&User {
        id: UserId("flowtest2".into()),
        uuid: "22222222-2222-2222-2222-222222222222".into(),
        tuic_password: Some("tp".into()),
        wireguard_pubkey: Some("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=".into()),
        wireguard_private: Some("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=".into()),
        sub_token: Some("subtok-flowtest2".into()),
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    inv.grant(&UserId("flowtest2".into()), &ServerId("wg2".into()))
        .await
        .unwrap();

    let app = router(s);
    let html = fetch_html(app, "/admin/users/flowtest2/delivery").await;

    assert!(
        html.contains("wireguard://"),
        "Flow B must include the wireguard:// link verbatim somewhere on the page"
    );
    assert!(
        html.contains("Click the box above to select-all + copy"),
        "Flow B footnote must teach the click-to-copy interaction"
    );
}

#[tokio::test]
async fn admin_user_detail_flow_c_card_emits_vpn_scheme_link() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_server(&Server {
        id: ServerId("amzwg".into()),
        address: "203.0.113.10".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("amzwg".into()),
        "wireguard.server_public_key",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("amzwg".into()),
        "wireguard.server_private_key",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    )
    .await
    .unwrap();
    inv.add_user(&User {
        id: UserId("amztest".into()),
        uuid: "44444444-4444-4444-4444-444444444444".into(),
        tuic_password: Some("tp".into()),
        wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
        wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
        sub_token: Some("st-amztest".into()),
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    inv.grant(&UserId("amztest".into()), &ServerId("amzwg".into()))
        .await
        .unwrap();

    let app = router(s);
    let html = fetch_html(app, "/admin/users/amztest/delivery").await;

    assert!(
        html.contains("Flow C — AmneziaVPN"),
        "Flow C label missing on user-detail"
    );
    assert!(
        html.contains("vpn://"),
        "Flow C card must include a `vpn://<...>` link for AmneziaVPN"
    );
    let vpn_at = html.find("vpn://").expect("vpn:// substring missing");
    let window_start = vpn_at.saturating_sub(800);
    let before = &html[window_start..vpn_at];
    assert!(
        before.contains("<textarea readonly"),
        "Flow C vpn:// link must appear inside a `<textarea readonly>` block"
    );
}

#[tokio::test]
async fn admin_user_detail_flow_f_card_emits_awg_scheme_link() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_server(&Server {
        id: ServerId("awgnode".into()),
        address: "203.0.113.11".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("amneziawg".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    for (k, v) in [
        (
            "wireguard.server_public_key",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ),
        (
            "wireguard.server_private_key",
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
        ),
        ("amneziawg.jc", "7"),
        ("amneziawg.jmin", "60"),
        ("amneziawg.jmax", "140"),
        ("amneziawg.s1", "30"),
        ("amneziawg.s2", "90"),
        ("amneziawg.h1", "1111111111"),
        ("amneziawg.h2", "2022222222"),
        ("amneziawg.h3", "333333333"),
        ("amneziawg.h4", "444444444"),
    ] {
        inv.set_server_secret(&ServerId("awgnode".into()), k, v)
            .await
            .unwrap();
    }
    inv.add_user(&User {
        id: UserId("awgtest".into()),
        uuid: "55555555-5555-5555-5555-555555555555".into(),
        tuic_password: None,
        wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
        wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
        sub_token: Some("st-awgtest".into()),
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    inv.grant(&UserId("awgtest".into()), &ServerId("awgnode".into()))
        .await
        .unwrap();

    let app = router(s);
    let html = fetch_html(app, "/admin/users/awgtest/delivery").await;
    assert!(
        html.contains("AmneziaWG (awg://)"),
        "Flow F AmneziaWG card label missing"
    );
    assert!(
        html.contains("awg://"),
        "Flow F card must include an awg:// link"
    );
    let at = html.rfind("awg://").expect("awg:// link missing");
    let win = &html[at..(at + 700).min(html.len())];
    assert!(
        win.contains("jc=7") && win.contains("s1=30") && win.contains("h1=1111111111"),
        "obfs params missing in awg:// link: {win}"
    );
    assert!(
        win.contains("s3=0") && win.contains("s4=0"),
        "s3/s4 must be 0 (vpnctl serves AWG 1.x): {win}"
    );
}

#[tokio::test]
async fn admin_user_detail_no_flow_f_without_amneziawg_obfs() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_server(&Server {
        id: ServerId("sbwg".into()),
        address: "203.0.113.12".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("sbwg".into()),
        "wireguard.server_public_key",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    .await
    .unwrap();
    inv.add_user(&User {
        id: UserId("sbwguser".into()),
        uuid: "66666666-6666-6666-6666-666666666666".into(),
        tuic_password: None,
        wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
        wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
        sub_token: Some("st-sbwg".into()),
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    inv.grant(&UserId("sbwguser".into()), &ServerId("sbwg".into()))
        .await
        .unwrap();

    let app = router(s);
    let html = fetch_html(app, "/admin/users/sbwguser/delivery").await;
    assert!(
        !html.contains("AmneziaWG (awg://)"),
        "Flow F must not render without minted AmneziaWG obfs"
    );
}

#[tokio::test]
async fn admin_user_detail_flow_b_links_to_conf_download() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_server(&Server {
        id: ServerId("wgX".into()),
        address: "203.0.113.55".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("wgX".into()),
        "wireguard.server_public_key",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("wgX".into()),
        "wireguard.server_private_key",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    )
    .await
    .unwrap();
    inv.add_user(&User {
        id: UserId("conftest".into()),
        uuid: "77777777-7777-7777-7777-777777777777".into(),
        tuic_password: Some("tp".into()),
        wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
        wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
        sub_token: Some("st-conf".into()),
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    inv.grant(&UserId("conftest".into()), &ServerId("wgX".into()))
        .await
        .unwrap();

    let app = router(s);
    let html = fetch_html(app, "/admin/users/conftest/delivery").await;
    assert!(
        html.contains("/admin/users/conftest/wireguard/conf/wgX"),
        "Flow B server header must link to the .conf download endpoint"
    );
    assert!(
        html.contains("download=\"conftest-wgX.conf\""),
        "anchor must set the download filename to <user>-<server>.conf"
    );
}

#[tokio::test]
async fn v2_user_delivery_renders_subscription_recap() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    let html = fetch_html(router(s), "/admin/users/u0/delivery").await;
    let recap = html
        .split_once(r#"class="ed-inbar""#)
        .unwrap()
        .1
        .split_once("</div>")
        .unwrap()
        .0;
    let link = recap
        .split_once(r#"href="/admin/users/u0">"#)
        .unwrap()
        .1
        .split_once("</a>")
        .unwrap()
        .0;
    assert_eq!(
        link.split_once("<svg ").unwrap().0.trim(),
        "QR on Overview",
        "recap must link the Overview QR with its exact label"
    );
    assert!(
        link.contains(r#"<use href="/admin/assets/icons.svg#arrow-right""#),
        "Overview QR link must carry its own arrow icon"
    );
    assert!(
        html.contains("LAN-only fallback"),
        "legacy /sub fallback note missing"
    );
}

#[tokio::test]
async fn admin_delivery_share_links_empty_when_user_disabled() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;

    s.inv
        .set_server_secret(
            &ServerId("s0".into()),
            "vless.private_key",
            "QGZ8K-private-key-base64==",
        )
        .await
        .unwrap();
    s.inv
        .set_server_secret(
            &ServerId("s0".into()),
            "vless.public_key",
            "PUBLIC-KEY-BASE64=",
        )
        .await
        .unwrap();
    s.inv
        .set_server_secret(&ServerId("s0".into()), "vless.short_id", "deadbeef")
        .await
        .unwrap();
    s.inv
        .set_server_secret(&ServerId("s0".into()), "vless.sni", "www.microsoft.com")
        .await
        .unwrap();

    s.inv
        .set_user_disabled(&UserId("u0".into()), true)
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/users/u0/delivery").await;
    assert!(
        !html.contains("vless://"),
        "disabled user must not have share links in delivery"
    );
    assert!(
        !html.contains("s0 · vless+reality"),
        "disabled user must not have protocol items listed in per-protocol share links"
    );
}

#[tokio::test]
async fn admin_delivery_share_links_skip_auto_suppressed_server() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 1, &[(0, 0), (0, 1)]).await;

    for sid in ["s0", "s1"] {
        s.inv
            .set_server_secret(
                &ServerId(sid.into()),
                "vless.private_key",
                "QGZ8K-private-key-base64==",
            )
            .await
            .unwrap();
        s.inv
            .set_server_secret(
                &ServerId(sid.into()),
                "vless.public_key",
                "PUBLIC-KEY-BASE64=",
            )
            .await
            .unwrap();
        s.inv
            .set_server_secret(&ServerId(sid.into()), "vless.short_id", "deadbeef")
            .await
            .unwrap();
        s.inv
            .set_server_secret(&ServerId(sid.into()), "vless.sni", "www.microsoft.com")
            .await
            .unwrap();
    }

    s.inv
        .set_server_auto_suppress(&ServerId("s0".into()), true)
        .await
        .unwrap();
    s.inv
        .set_server_suppressed(&ServerId("s0".into()), true)
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/users/u0/delivery").await;
    assert!(
        !html.contains("s0 · vless+reality"),
        "auto-suppressed server s0 must be excluded from delivery share links"
    );
    assert!(
        html.contains("s1 · vless+reality"),
        "healthy server s1 must remain in delivery share links"
    );
}

#[tokio::test]
async fn admin_delivery_share_links_skip_hidden_and_user_disabled_protocols() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;

    let sid = ServerId("s0".into());
    let uid = UserId("u0".into());

    s.inv.mint_tuic_password_if_absent(&uid).await.unwrap();

    s.inv
        .add_server_protocol(&sid, &ProtocolId("tuic-v5".into()))
        .await
        .unwrap();

    s.inv
        .set_server_secret(&sid, "vless.private_key", "QGZ8K-private-key-base64==")
        .await
        .unwrap();
    s.inv
        .set_server_secret(&sid, "vless.public_key", "PUBLIC-KEY-BASE64=")
        .await
        .unwrap();
    s.inv
        .set_server_secret(&sid, "vless.short_id", "deadbeef")
        .await
        .unwrap();
    s.inv
        .set_server_secret(&sid, "vless.sni", "www.microsoft.com")
        .await
        .unwrap();

    let html_before = fetch_html(router(s.clone()), "/admin/users/u0/delivery").await;
    assert!(html_before.contains("s0 · vless+reality"));
    assert!(html_before.contains("s0 · tuic-v5"));

    s.inv
        .set_server_protocol_hidden(&sid, &ProtocolId("vless+reality".into()), true)
        .await
        .unwrap();

    let html_hidden = fetch_html(router(s.clone()), "/admin/users/u0/delivery").await;
    assert!(
        !html_hidden.contains("s0 · vless+reality"),
        "hidden protocol must not render in share links"
    );
    assert!(
        html_hidden.contains("s0 · tuic-v5"),
        "unhidden protocol tuic-v5 must render"
    );

    s.inv
        .set_grant_protocol_override(&uid, &sid, &ProtocolId("tuic-v5".into()), true)
        .await
        .unwrap();

    let html_disabled = fetch_html(router(s), "/admin/users/u0/delivery").await;
    assert!(
        !html_disabled.contains("s0 · tuic-v5"),
        "per-user-disabled protocol must not render in share links"
    );
}

#[tokio::test]
async fn admin_delivery_amnezia_and_awg_respect_auto_suppress_hidden_and_user_disabled() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();

    let sid = ServerId("awgnode".into());
    let uid = UserId("awguser".into());

    inv.add_server(&Server {
        id: sid.clone(),
        address: "203.0.113.88".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("amneziawg".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();

    inv.set_server_secret(
        &sid,
        "wireguard.server_public_key",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    .await
    .unwrap();
    inv.set_server_secret(
        &sid,
        "wireguard.server_private_key",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    )
    .await
    .unwrap();
    for (k, v) in [
        ("amneziawg.jc", "7"),
        ("amneziawg.jmin", "50"),
        ("amneziawg.jmax", "1000"),
        ("amneziawg.s1", "30"),
        ("amneziawg.s2", "90"),
        ("amneziawg.h1", "1111111111"),
        ("amneziawg.h2", "2022222222"),
        ("amneziawg.h3", "333333333"),
        ("amneziawg.h4", "444444444"),
    ] {
        inv.set_server_secret(&sid, k, v).await.unwrap();
    }

    inv.add_user(&User {
        id: uid.clone(),
        uuid: "55555555-5555-5555-5555-555555555555".into(),
        tuic_password: None,
        wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
        wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
        sub_token: Some("st-awguser".into()),
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();

    inv.grant(&uid, &sid).await.unwrap();

    let html_init = fetch_html(router(s.clone()), "/admin/users/awguser/delivery").await;
    assert!(html_init.contains("vpn://"));
    assert!(html_init.contains("awg://"));

    inv.set_server_protocol_hidden(&sid, &ProtocolId("wireguard".into()), true)
        .await
        .unwrap();
    let html_hidden = fetch_html(router(s.clone()), "/admin/users/awguser/delivery").await;
    assert!(
        !html_hidden.contains("vpn://"),
        "hidden wireguard must not emit AmneziaVPN vpn:// link"
    );
    assert!(
        !html_hidden.contains("awg://"),
        "hidden wireguard must not emit AmneziaWG awg:// link"
    );

    inv.set_server_protocol_hidden(&sid, &ProtocolId("wireguard".into()), false)
        .await
        .unwrap();
    inv.set_grant_protocol_override(&uid, &sid, &ProtocolId("wireguard".into()), true)
        .await
        .unwrap();
    let html_user_disabled = fetch_html(router(s.clone()), "/admin/users/awguser/delivery").await;
    assert!(
        !html_user_disabled.contains("vpn://"),
        "user-disabled wireguard must not emit AmneziaVPN vpn:// link"
    );
    assert!(
        !html_user_disabled.contains("awg://"),
        "user-disabled wireguard must not emit AmneziaWG awg:// link"
    );

    inv.set_grant_protocol_override(&uid, &sid, &ProtocolId("wireguard".into()), false)
        .await
        .unwrap();
    inv.set_server_auto_suppress(&sid, true).await.unwrap();
    inv.set_server_suppressed(&sid, true).await.unwrap();
    let html_suppressed = fetch_html(router(s), "/admin/users/awguser/delivery").await;
    assert!(
        !html_suppressed.contains("vpn://"),
        "auto-suppressed server must not emit AmneziaVPN vpn:// link"
    );
    assert!(
        !html_suppressed.contains("awg://"),
        "auto-suppressed server must not emit AmneziaWG awg:// link"
    );
}
