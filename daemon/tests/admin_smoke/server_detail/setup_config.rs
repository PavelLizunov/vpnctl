use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctld::router;

use crate::common::*;

#[tokio::test]
async fn admin_server_detail_naive_section_renders_when_enabled() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv.add_server(&naive_server("nv")).await.unwrap();
    let html = fetch_html(router(s), "/admin/servers/nv/protocols").await;
    assert!(
        html.contains(r#"action="/admin/servers/nv/naive-config""#),
        "naive config form must POST to the right route"
    );
    assert!(
        html.contains("NAIVE (CADDY) CONFIG"),
        "section eyebrow copy contract"
    );
    assert!(
        html.contains("DNS A-record"),
        "prerequisite reminder must be present"
    );
    assert!(
        html.contains(r#"name="domain""#) && html.contains(r#"name="acme_email""#),
        "both inputs present"
    );
}

#[tokio::test]
async fn admin_server_detail_naive_section_absent_when_not_enabled() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await; // seeded server is vless+reality only
    let html = fetch_html(router(s), "/admin/servers/s0/protocols").await;
    assert!(
        !html.contains("/naive-config"),
        "naive section must not render on a non-naive server"
    );
}

#[tokio::test]
async fn admin_server_set_naive_config_mutates_and_audits() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv.add_server(&naive_server("nv")).await.unwrap();
    let resp = router(s.clone())
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/nv/naive-config")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from(
                "domain=cdn.example.com&acme_email=admin%40example.com",
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let sid = vpnctl_core::ServerId("nv".into());
    assert_eq!(
        s.inv
            .get_server_secret(&sid, "naive.domain")
            .await
            .unwrap()
            .as_deref(),
        Some("cdn.example.com")
    );
    assert_eq!(
        s.inv
            .get_server_secret(&sid, "naive.acme_email")
            .await
            .unwrap()
            .as_deref(),
        Some("admin@example.com")
    );
    let audit = s.inv.recent_audit(10).await.unwrap();
    assert!(
        audit
            .iter()
            .any(|e| e.action == "server.naive.set" && e.target.as_deref() == Some("nv")),
        "audit row server.naive.set must land"
    );
}

#[tokio::test]
async fn admin_server_set_udp_pair_toggles_and_audits() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&vpnctl_core::Server {
            id: vpnctl_core::ServerId("lv".into()),
            address: "1.2.3.4".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![vpnctl_core::KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let sid = vpnctl_core::ServerId("lv".into());
    assert!(
        !s.inv.is_server_udp_pair_enabled(&sid).await.unwrap(),
        "default off"
    );

    // Enable via the handler.
    let resp = router(s.clone())
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/lv/udp-pair")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("enabled=true"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(
        s.inv.is_server_udp_pair_enabled(&sid).await.unwrap(),
        "enable must persist"
    );
    assert!(
        s.inv
            .recent_audit(10)
            .await
            .unwrap()
            .iter()
            .any(|e| e.action == "server.udp_pair.set" && e.target.as_deref() == Some("lv")),
        "audit row server.udp_pair.set must land"
    );

    // Disable via the handler.
    let resp = router(s.clone())
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/lv/udp-pair")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("enabled=false"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(
        !s.inv.is_server_udp_pair_enabled(&sid).await.unwrap(),
        "disable must persist"
    );
}

#[tokio::test]
async fn admin_server_set_naive_config_rejects_empty_domain() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv.add_server(&naive_server("nv")).await.unwrap();
    let resp = router(s)
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/nv/naive-config")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("domain=&acme_email=admin%40example.com"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_server_set_naive_config_rejects_injection_in_domain() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv.add_server(&naive_server("nv")).await.unwrap();
    // `evil{block}` — a `{` would break out of the forward_proxy block
    // in the rendered Caddyfile. Must be rejected at save-time (400),
    // and nothing may persist.
    let resp = router(s.clone())
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/nv/naive-config")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("domain=evil%7Bblock%7D&acme_email="))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        s.inv
            .get_server_secret(&vpnctl_core::ServerId("nv".into()), "naive.domain")
            .await
            .unwrap()
            .is_none(),
        "rejected domain must not persist"
    );
}

#[tokio::test]
async fn admin_server_set_naive_config_404_on_missing_server() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let resp = router(s)
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/nope/naive-config")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("domain=cdn.example.com&acme_email="))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn server_detail_renders_push_deploy_key_section() {
    // Phase G chunk 3.5 follow-up — every server-detail page must
    // expose a «push deploy key» form so the operator can append
    // the daemon's pubkey without dropping to a terminal.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&vpnctl_core::Server {
            id: vpnctl_core::ServerId("vps-de1".into()),
            address: "203.0.113.7".into(),
            ssh_port: 2222,
            ssh_user: "root".into(),
            kernels: vec![vpnctl_core::KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/vps-de1/setup")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("Deploy SSH key — push to this server"),
        "section eyebrow must render"
    );
    assert!(
        html.contains(r#"action="/admin/servers/vps-de1/push-deploy-key""#),
        "form must POST to the push-key route"
    );
    assert!(
        html.contains(r#"name="ssh_user""#) && html.contains(r#"value="root""#),
        "form must include the current SSH user"
    );
    assert!(
        html.contains(r#"name="root_password""#),
        "form must include the password input"
    );
    assert!(
        html.contains("root@203.0.113.7:2222"),
        "button hint must show concrete ssh_user@host:port"
    );
    assert!(
        html.contains("never stored"),
        "placeholder must reassure operator that password isn't persisted"
    );
}

#[tokio::test]
async fn server_push_deploy_key_404s_for_unknown_server() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let mut req = Request::builder()
        .method("POST")
        .uri("/admin/servers/no-such/push-deploy-key")
        .header("content-type", "application/x-www-form-urlencoded");
    req = add_same_origin(req);
    let resp = app
        .oneshot(req.body(Body::from("root_password=hunter2")).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains("no such server 'no-such'"),
        "must surface the unknown-server message"
    );
}

#[tokio::test]
async fn server_push_deploy_key_rejects_invalid_ssh_user_before_connecting() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&vpnctl_core::Server {
            id: vpnctl_core::ServerId("stg-user".into()),
            address: "1.2.3.4".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![vpnctl_core::KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/stg-user/push-deploy-key")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("ssh_user=debian%3Bsudo&root_password=hunter2"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn server_push_deploy_key_rejects_empty_password_without_reference_key() {
    // Defensive: empty password reaches the handler if the
    // browser bypasses the `required` attr (curl, custom client).
    // Must 400 with a clear message — NEVER attempt the SSH call
    // with no password (sshpass would silently retry without
    // password and the failure mode would look like generic
    // network error).
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&vpnctl_core::Server {
            id: vpnctl_core::ServerId("stg".into()),
            address: "1.2.3.4".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![vpnctl_core::KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(st);
    let mut req = Request::builder()
        .method("POST")
        .uri("/admin/servers/stg/push-deploy-key")
        .header("content-type", "application/x-www-form-urlencoded");
    req = add_same_origin(req);
    let resp = app
        .oneshot(req.body(Body::from("root_password=")).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_server_detail_shows_deploy_button() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("sb".into()),
            address: "203.0.113.7".into(),
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
    let app = router(s);
    let html = fetch_html(app, "/admin/servers/sb").await;
    assert!(
        html.contains(r#"action="/admin/servers/sb/deploy""#),
        "deploy form must POST to /admin/servers/<id>/deploy (noscript fallback)"
    );
    assert!(html.contains(">deploy →<"), "submit button label drifted");
    // Item-1 SSE deploy: JS-driven button streams progress to a log pane.
    assert!(
        html.contains(r#"data-sse-url="/admin/servers/sb/deploy/sse""#),
        "deploy button must carry the SSE trigger URL"
    );
    assert!(
        html.contains(r#"id="deploy-log""#),
        "live deploy log pane must be present"
    );
    assert!(
        html.contains(r#"src="/admin/assets/admin.js""#),
        "external admin.js (CSP-safe SSE wiring) must be loaded"
    );
    // The POST fallback must be inside <noscript> (JS path is primary).
    assert!(
        html.contains("<noscript>"),
        "synchronous POST deploy must be the <noscript> fallback"
    );
}

#[tokio::test]
async fn admin_server_deploy_bootstraps_keys_but_keeps_pending_on_failure() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_server(&Server {
            id: ServerId("wg-node".into()),
            address: "198.51.100.5".into(),
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
    s.inv
        .add_user(&User {
            id: UserId("wg-user".into()),
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
    s.inv
        .grant(&UserId("wg-user".into()), &ServerId("wg-node".into()))
        .await
        .unwrap();
    s.inv
        .audit(
            "admin",
            "user.grant",
            Some("wg-user"),
            Some(&serde_json::json!({ "server": "wg-node" })),
        )
        .await
        .unwrap();
    let app = router(s);
    // Pre-deploy: no WG keys.
    let before = inv
        .list_server_secrets(&ServerId("wg-node".into()))
        .await
        .unwrap();
    assert!(!before.contains_key("wireguard.server_public_key"));
    assert!(!before.contains_key("wireguard.server_private_key"));

    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/wg-node/deploy"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

    // Post-deploy: WG server keypair minted.
    let after = inv
        .list_server_secrets(&ServerId("wg-node".into()))
        .await
        .unwrap();
    let pub_ = after.get("wireguard.server_public_key").expect("pubkey");
    let priv_ = after.get("wireguard.server_private_key").expect("private");
    assert_eq!(pub_.len(), 44, "WG pubkey is 44 b64 chars");
    assert_eq!(priv_.len(), 44);
    assert!(pub_.ends_with('='));
    assert!(priv_.ends_with('='));
    assert_ne!(pub_, priv_, "pub != priv");

    // The attempt is recorded, but not as the canonical success baseline.
    let audit = inv.recent_audit(5).await.unwrap();
    let row = audit
        .iter()
        .find(|a| {
            matches!(
                a.action.as_str(),
                "server.deploy.skipped" | "server.deploy.failed"
            )
        })
        .expect("failed/skipped deploy audit row");
    assert!(
        audit.iter().all(|a| a.action != "server.deploy"),
        "a skipped SSH push must not clear pending-deploy state"
    );
    assert!(
        inv.server_pending_deploy(&ServerId("wg-node".into()))
            .await
            .unwrap(),
        "failed/skipped deploy must leave the granted server pending"
    );
    let payload = row
        .payload
        .as_ref()
        .map(|v| v.to_string())
        .unwrap_or_default();
    // Post-refactor (2026-05-30 server_secret_specs): the `bootstrapped`
    // audit field records the minted secret KEY NAMES (not human labels),
    // so the WG keypair shows as its primary key. Asserting the key name
    // is strictly more precise than the old "wireguard server keypair".
    assert!(
        payload.contains("wireguard.server_private_key"),
        "deploy audit payload should record the minted WG key; got {payload}"
    );
}

#[tokio::test]
async fn admin_server_deploy_idempotent_re_click_no_dup_keys() {
    // UNIQUE server-id per deploy-POST test: the per-server deploy gate
    // (`wizard_bootstrap::DeployGuard`) is a process-wide static, so two
    // parallel tests deploying the SAME id would race — the loser gets a
    // 409 "deploy already running" and mints no secrets. Each deploy test
    // must therefore own its server-id (here `wg-idem`, distinct from the
    // sibling `wg-node` mint test).
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_server(&Server {
            id: ServerId("wg-idem".into()),
            address: "198.51.100.5".into(),
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
    let app = router(s);

    // First click.
    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/wg-idem/deploy"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let first_pub = inv
        .list_server_secrets(&ServerId("wg-idem".into()))
        .await
        .unwrap()
        .get("wireguard.server_public_key")
        .unwrap()
        .clone();

    // Second click — keys must NOT change (idempotent).
    app.oneshot(
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/wg-idem/deploy"),
        )
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
    let second_pub = inv
        .list_server_secrets(&ServerId("wg-idem".into()))
        .await
        .unwrap()
        .get("wireguard.server_public_key")
        .unwrap()
        .clone();
    assert_eq!(
        first_pub, second_pub,
        "deploy must be idempotent — re-clicking when keys exist must NOT rotate them"
    );
}

#[tokio::test]
async fn admin_server_detail_deploy_caption_describes_ssh_push() {
    // 2026-05-17 — Pavel: подпись «Mints missing keys… Subscription
    // URLs go live immediately» неполная: реальный deploy включает
    // ensure_installed + apply_config + restart. Pin the new copy.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_server(&Server {
        id: ServerId("deploysrv".into()),
        address: "203.0.113.9".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    let app = router(s);
    let html = fetch_html(app, "/admin/servers/deploysrv").await;

    // New caption mentions the real SSH-side work, not just secret mint.
    assert!(
        html.contains("ensure_installed"),
        "deploy caption must mention ensure_installed (apt-get install side)"
    );
    assert!(
        html.contains("apply_config"),
        "deploy caption must mention apply_config (systemctl restart side)"
    );
    // Old half-truth wording is gone.
    assert!(
        !html.contains("Mints missing keys for every enabled protocol."),
        "deploy caption regressed to the old keys-only wording"
    );
    // Tooltip on the button mentions the full cycle too.
    assert!(
        html.contains("Full deploy:") || html.contains("Full deploy "),
        "deploy button title attribute must lead with 'Full deploy:'"
    );
}

/// The server-detail page must surface a "danger zone" link to the
/// delete-confirm page. Without it the operator has no UI path to remove
/// a decommissioned server (the bug this feature fixes).
#[tokio::test]
async fn admin_server_detail_has_delete_link() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let html = fetch_html(router(s), "/admin/servers/s0/setup").await;
    assert!(
        html.contains(r#"href="/admin/servers/s0/delete-confirm""#),
        "server-detail must link to the delete-confirm page"
    );
}

#[tokio::test]
async fn admin_server_set_reality_config_saves_valid_port_and_audits() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&reality_naive_server("cdn"))
        .await
        .unwrap();

    // UI section renders on the protocols tab for a reality-enabled node.
    let html = fetch_html(router(s.clone()), "/admin/servers/cdn/protocols").await;
    assert!(
        html.contains(r#"action="/admin/servers/cdn/reality-config""#),
        "reality config form must POST to the right route"
    );

    // 8443 frees tcp/443 for naive → guard passes → 303 + persisted.
    let resp = router(s.clone())
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/cdn/reality-config")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("listen_port=8443"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let sid = vpnctl_core::ServerId("cdn".into());
    assert_eq!(
        s.inv
            .get_server_secret(&sid, "vless.listen_port")
            .await
            .unwrap()
            .as_deref(),
        Some("8443")
    );
    assert!(
        s.inv
            .recent_audit(10)
            .await
            .unwrap()
            .iter()
            .any(|e| e.action == "server.reality.set" && e.target.as_deref() == Some("cdn")),
        "audit row server.reality.set must land"
    );
}

#[tokio::test]
async fn admin_server_set_reality_config_rejects_zero_with_single_prefix() {
    // listen_port=0 → 400, and the body carries EXACTLY ONE
    // `vpnctl admin: ` prefix — `error_text` is the single source of
    // truth (PR #139 round-2 finding 1).
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&reality_naive_server("cdn"))
        .await
        .unwrap();
    let resp = router(s.clone())
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/cdn/reality-config")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("listen_port=0"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(
        body.starts_with("vpnctl admin: invalid REALITY listen port"),
        "copy contract (single prefix): {body:?}"
    );
    assert!(
        !body.starts_with("vpnctl admin: vpnctl admin:"),
        "doubled prefix regressed: {body:?}"
    );
    // Nothing persisted on rejection.
    assert_eq!(
        s.inv
            .get_server_secret(&vpnctl_core::ServerId("cdn".into()), "vless.listen_port")
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn admin_server_set_reality_config_rejects_naive_collision_at_save_time() {
    // naive owns tcp/443 on this node; blank listen_port means reality
    // falls back to its default 443 → the save-time guard must reject
    // with the port-conflict copy BEFORE anything persists (deploy
    // stays the authoritative gate, but the operator gets the answer
    // at save time — symmetry with the vless-ws form).
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&reality_naive_server("cdn"))
        .await
        .unwrap();
    let resp = router(s.clone())
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/cdn/reality-config")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("listen_port="))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(
        body.starts_with("vpnctl admin: "),
        "copy contract (single prefix): {body:?}"
    );
    assert!(
        body.contains("port conflict on tcp/443"),
        "port-conflict copy expected: {body:?}"
    );
    assert!(
        s.inv
            .get_server_secret(&vpnctl_core::ServerId("cdn".into()), "vless.listen_port")
            .await
            .unwrap()
            .is_none(),
        "nothing may persist on rejection"
    );
}
