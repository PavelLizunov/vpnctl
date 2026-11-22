use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctld::router;

use crate::common::*;

fn fixture_server(id: &str, jump_via: Option<&str>) -> Server {
    Server {
        id: ServerId(id.into()),
        address: "203.0.113.40".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: jump_via.map(|id| ServerId(id.into())),
        usage_coefficient: 1.0,
    }
}

async fn add_fixture_server(st: &vpnctld::AppState, id: &str, jump_via: Option<&str>) {
    st.inv
        .add_server(&fixture_server(id, jump_via))
        .await
        .unwrap();
}

async fn seed_vless_secrets(st: &vpnctld::AppState, sid: &ServerId) {
    for (key, value) in [
        ("vless.private_key", "QGZ8K-private-key-base64=="),
        ("vless.public_key", "PUBLIC-KEY-BASE64="),
        ("vless.short_id", "deadbeef"),
        ("vless.sni", "www.microsoft.com"),
    ] {
        st.inv.set_server_secret(sid, key, value).await.unwrap();
    }
}

async fn add_fixture_user(st: &vpnctld::AppState, id: &str) {
    st.inv
        .add_user(&User {
            id: UserId(id.into()),
            uuid: format!("00000000-0000-0000-0000-{:012}", id.len()),
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

async fn grant_for_delivery(st: &vpnctld::AppState, sid: &str) {
    assert!(
        st.inv
            .grant_audited(&UserId("u0".into()), &ServerId(sid.into()), "admin", "test")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn servers_page_primary_action_is_the_wizard_and_register_is_demoted() {
    let dir = TempDir::new().unwrap();
    let html = fetch_html(router(state(&dir).await), "/admin/servers").await;

    let wizard = html
        .find(r#"href="/admin/servers/new""#)
        .expect("wizard CTA must exist");
    let advanced = html
        .find("Already have a node?")
        .expect("register-only disclosure must exist");
    let quick_add = html
        .find(r#"action="/admin/servers/quick-add""#)
        .expect("register-only form must stay available");
    assert!(
        wizard < advanced && advanced < quick_add,
        "the wizard CTA must precede the accordion that contains register-only"
    );
    assert!(
        html.contains("start wizard"),
        "primary wizard label missing"
    );
    assert!(
        html.contains("add server"),
        "servers page must keep the 'add server' wording"
    );
    assert!(
        html.contains("installs the deploy key, hardens the node and deploys its config"),
        "primary path must promise the end-to-end bootstrap"
    );
    let register = &html[quick_add..];
    assert!(
        register.contains("ed-abtn--secondary"),
        "register-only submit must be visually demoted to secondary"
    );
    assert!(
        register.contains("does NOT install the deploy key"),
        "register-only must warn that it is not the full bootstrap path"
    );
}

#[tokio::test]
async fn add_user_shows_ready_and_skipped_servers_before_creating() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    add_fixture_server(&st, "ready", None).await;
    add_fixture_server(&st, "unverified", None).await;
    mark_ssh_available(&st.inv, &ServerId("ready".into())).await;

    let html = fetch_html(router(st), "/admin/users").await;
    assert!(
        html.contains("1 ready"),
        "ready target count missing: {html:.400}"
    );
    assert!(html.contains("1 not ready"), "skipped target count missing");
    assert!(
        html.contains("ready targets: 1"),
        "eligible targets must be named, not only counted"
    );
    assert!(
        html.contains("why some servers are skipped"),
        "operator needs a disclosure explaining skipped targets"
    );
    assert!(html.contains("unverified"), "skipped server must be named");
    assert!(
        html.contains("/admin/servers/unverified/status#ssh-access"),
        "skipped server must link to the SSH check"
    );
    assert!(
        html.contains("grant all ready servers"),
        "grant-all checkbox must describe the ready-only scope"
    );
}

#[tokio::test]
async fn user_create_grant_all_skips_servers_without_a_verified_ssh_path() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    add_fixture_server(&st, "ready", None).await;
    add_fixture_server(&st, "unverified", None).await;
    mark_ssh_available(&st.inv, &ServerId("ready".into())).await;

    let resp = router(st.clone())
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("id=newbie&grant_all=1"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let granted = st
        .inv
        .servers_for_user(&UserId("newbie".into()))
        .await
        .unwrap();
    let ids: Vec<&str> = granted.iter().map(|server| server.id.0.as_str()).collect();
    assert_eq!(
        ids,
        vec!["ready"],
        "grant-all must skip a server whose SSH deploy-key path is unverified"
    );
}

#[tokio::test]
async fn web_grant_paths_reject_unverified_servers_but_keep_noop_regrants_idempotent() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    add_fixture_server(&st, "s-unverified", None).await;
    add_fixture_user(&st, "alice").await;
    let inv = st.inv.clone();
    let app = router(st);

    for uri in [
        "/admin/users/alice/grants/s-unverified",
        "/admin/servers/s-unverified/grants/alice",
    ] {
        let resp = app
            .clone()
            .oneshot(
                add_same_origin(Request::builder().method("POST").uri(uri))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{uri}");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.contains("no verified SSH deploy-key path"),
            "{uri} must explain the readiness gate: {text}"
        );
        assert!(
            text.contains("/admin/servers/s-unverified/status#ssh-access"),
            "{uri} must point at the web SSH check"
        );
    }
    assert!(
        inv.servers_for_user(&UserId("alice".into()))
            .await
            .unwrap()
            .is_empty(),
        "rejected web grants must not be saved"
    );

    inv.grant(&UserId("alice".into()), &ServerId("s-unverified".into()))
        .await
        .unwrap();
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/alice/grants/s-unverified"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "re-granting an existing pair is a no-op and must stay idempotent"
    );
    assert_eq!(
        inv.servers_for_user(&UserId("alice".into()))
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn web_grant_remediation_is_deferred_and_web_only() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    add_fixture_server(&st, "s-deferred", None).await;
    add_fixture_user(&st, "deferred").await;
    let inv = st.inv.clone();
    let app = router(st.clone());

    let resp = app
        .clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/deferred/grants/s-deferred"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    inv.grant(&UserId("deferred".into()), &ServerId("s-deferred".into()))
        .await
        .unwrap();
    assert_eq!(
        inv.servers_for_user(&UserId("deferred".into()))
            .await
            .unwrap()
            .len(),
        1,
        "the gate is web-mutation only; inventory/CLI grants stay available"
    );
    inv.revoke(&UserId("deferred".into()), &ServerId("s-deferred".into()))
        .await
        .unwrap();

    mark_ssh_available(&st.inv, &ServerId("s-deferred".into())).await;
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/deferred/grants/s-deferred"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "after the operator fixes SSH, the deferred web grant must work without a controller change"
    );
}

#[tokio::test]
async fn jump_routes_require_the_jump_check_even_when_direct_is_verified() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    add_fixture_server(&st, "gateway", None).await;
    add_fixture_server(&st, "jump-target", Some("gateway")).await;
    add_fixture_user(&st, "alice").await;
    mark_ssh_available(&st.inv, &ServerId("jump-target".into())).await;

    let resp = router(st)
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/alice/grants/jump-target"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "deploy uses the configured jump route, so a direct-only check is insufficient"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains("SSH via jump"),
        "the rejection must name the jump route: {text}"
    );
}

#[tokio::test]
async fn bulk_grant_all_rejects_unverified_servers_but_reports_a_noop() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    add_fixture_server(&st, "s-bulk", None).await;
    add_fixture_user(&st, "bob").await;
    let inv = st.inv.clone();
    let app = router(st);

    let resp = app
        .clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s-bulk/grants/_grant-all"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("no verified SSH deploy-key path")
    );

    inv.grant(&UserId("bob".into()), &ServerId("s-bulk".into()))
        .await
        .unwrap();
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s-bulk/grants/_grant-all"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains("Granted: 0; already granted: 1; disabled users skipped: 0; failed: 0."),
        "a no-op bulk grant must still report its counts: {text}"
    );
}

#[tokio::test]
async fn access_tab_hides_the_grant_button_and_names_the_ssh_check_when_unverified() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    add_fixture_server(&st, "s-unverified", None).await;
    add_fixture_server(&st, "s-ready", None).await;
    add_fixture_user(&st, "alice").await;
    mark_ssh_available(&st.inv, &ServerId("s-ready".into())).await;

    let html = fetch_html(router(st), "/admin/users/alice/access").await;
    assert!(
        !html.contains(r#"action="/admin/users/alice/grants/s-unverified""#),
        "an unverified server must not expose a dead grant form"
    );
    assert!(
        html.contains("SSH unverified"),
        "the row must say why the grant is unavailable"
    );
    assert!(
        html.contains("/admin/servers/s-unverified/status#ssh-access"),
        "the row must link to the SSH check action"
    );
    assert!(
        html.contains(r#"action="/admin/users/alice/grants/s-ready""#),
        "a verified server must still expose the grant form"
    );
}

async fn ready_delivery_state(dir: &TempDir) -> (vpnctld::AppState, String) {
    let st = state(dir).await;
    seed(&st.inv, 1, 1, &[]).await;
    // Real users are created with a WireGuard keypair; the Flow A/B/C blocks
    // below the recommendation only render when that pair exists.
    let (wg_private, wg_public) = vpnctl_crypto::gen_wireguard_keypair();
    st.inv
        .set_user_wireguard_keypair(&UserId("u0".into()), &wg_public, &wg_private)
        .await
        .unwrap();
    seed_vless_secrets(&st, &ServerId("s0".into())).await;
    grant_for_delivery(&st, "s0").await;
    st.inv
        .audit("admin", "server.deploy", Some("s0"), None)
        .await
        .unwrap();
    st.inv
        .set_public_base_url(Some("https://vpn.example.com"))
        .await
        .unwrap();
    let token = st
        .inv
        .get_user(&UserId("u0".into()))
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .expect("seed user has a sub-token");
    (st, token)
}

#[tokio::test]
async fn delivery_recommends_one_artifact_with_explicit_copy_confirmation() {
    let dir = TempDir::new().unwrap();
    let (st, token) = ready_delivery_state(&dir).await;

    let html = fetch_html(router(st), "/admin/users/u0/delivery").await;
    assert!(
        html.contains("Recommended share"),
        "primary heading missing"
    );
    assert!(
        html.contains(r#"data-copy-recommended="recommended-share-url""#),
        "recommended artefact must have an explicit copy action"
    );
    assert!(
        html.contains(r#"id="recommended-share-status""#) && html.contains(r#"aria-live="polite""#),
        "copy action must expose an explicit confirmation status"
    );
    let expected = format!("https://vpn.example.com/sub/{token}");
    assert!(
        html.contains(&expected),
        "recommended subscription URL must use the configured public base"
    );
    assert!(
        html.contains("One URL for the subscription flow"),
        "recommended card must explain the single-artifact promise"
    );
    assert!(
        html.contains("review the per-server links below for anything missing"),
        "recommended card must not promise that every grant is present"
    );
    assert!(
        html.contains("Sing-box / Hiddify pulls the full config"),
        "other delivery flows must stay reachable below the recommendation"
    );
}

#[tokio::test]
async fn delivery_explains_disabled_user_instead_of_a_dead_link() {
    let dir = TempDir::new().unwrap();
    let (st, _) = ready_delivery_state(&dir).await;
    st.inv
        .set_user_disabled(&UserId("u0".into()), true)
        .await
        .unwrap();

    let html = fetch_html(router(st), "/admin/users/u0/delivery").await;
    assert!(html.contains("This user is disabled."));
    assert!(html.contains(r#"action="/admin/users/u0/enable""#));
    assert!(
        !html.contains(r#"data-copy-recommended="recommended-share-url""#),
        "a disabled user must not get a recommended live link"
    );
}

#[tokio::test]
async fn delivery_explains_zero_grants_instead_of_a_dead_link() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    seed(&st.inv, 1, 1, &[]).await;

    let html = fetch_html(router(st), "/admin/users/u0/delivery").await;
    assert!(html.contains("No deliverable server grants yet."));
    assert!(html.contains(r#"href="/admin/users/u0/access#server-access""#));
    assert!(!html.contains(r#"data-copy-recommended="recommended-share-url""#));
}

#[tokio::test]
async fn delivery_explains_pending_deploy_instead_of_a_dead_link() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    seed(&st.inv, 1, 1, &[]).await;
    grant_for_delivery(&st, "s0").await;
    st.inv
        .set_public_base_url(Some("https://vpn.example.com"))
        .await
        .unwrap();

    let html = fetch_html(router(st), "/admin/users/u0/delivery").await;
    assert!(
        html.contains("server is not applied yet."),
        "pending deploy explanation missing"
    );
    assert!(html.contains("deploy-pending action above"));
    assert!(
        !html.contains("Deployment is not confirmed."),
        "a known pending deploy must not be reported as missing deploy evidence"
    );
    assert!(!html.contains(r#"data-copy-recommended="recommended-share-url""#));
}

#[tokio::test]
async fn delivery_explains_loopback_recipient_url_and_links_to_public_address() {
    let dir = TempDir::new().unwrap();
    let (st, _) = ready_delivery_state(&dir).await;
    st.inv
        .set_public_base_url(Some("http://127.0.0.1:18402"))
        .await
        .unwrap();

    let html = fetch_html(router(st), "/admin/users/u0/delivery").await;
    assert!(html.contains("The share link points at loopback"));
    assert!(
        html.contains("The public address in Settings → System is obviously local to this host.")
    );
    assert!(html.contains(r#"href="/admin/settings/system#public-address""#));
    assert!(!html.contains(r#"data-copy-recommended="recommended-share-url""#));
}

#[tokio::test]
async fn delivery_keeps_copy_for_private_lan_or_tailscale_origin_with_scope_hint() {
    let dir = TempDir::new().unwrap();
    let (st, _) = ready_delivery_state(&dir).await;
    st.inv
        .set_public_base_url(Some("http://192.168.0.10:18402"))
        .await
        .unwrap();

    let html = fetch_html(router(st), "/admin/users/u0/delivery").await;
    assert!(
        html.contains(r#"data-copy-recommended="recommended-share-url""#),
        "an intentionally configured LAN/Tailscale origin must keep one-click copy"
    );
    assert!(
        html.contains("The configured address is private, LAN, CGNAT or Tailscale-style."),
        "private origins need a network-scope hint"
    );
    assert!(
        html.contains("No public reachability is assumed."),
        "the hint must not claim verified reachability"
    );
    assert!(
        !html.contains("obviously local to this host"),
        "private origins must not be treated as loopback failures"
    );
}

#[tokio::test]
async fn delivery_does_not_recommend_an_empty_artefact_when_every_protocol_is_hidden() {
    let dir = TempDir::new().unwrap();
    let (st, _) = ready_delivery_state(&dir).await;
    st.inv
        .set_grant_protocol_override(
            &UserId("u0".into()),
            &ServerId("s0".into()),
            &ProtocolId("vless+reality".into()),
            true,
        )
        .await
        .unwrap();

    let html = fetch_html(router(st), "/admin/users/u0/delivery").await;
    assert!(
        html.contains("No renderable protocol is delivered on an applied node yet."),
        "hidden protocols must suppress the primary artefact"
    );
    assert!(
        !html.contains(r#"data-copy-recommended="recommended-share-url""#),
        "an empty subscription must not offer a copy action"
    );
    assert!(html.contains("/admin/users/u0/access#server-access"));
}

#[tokio::test]
async fn delivery_keeps_the_primary_artefact_in_an_applied_mixed_fleet_with_explicit_pending_details()
 {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    seed(&st.inv, 2, 1, &[]).await;
    grant_for_delivery(&st, "s0").await;
    grant_for_delivery(&st, "s1").await;
    seed_vless_secrets(&st, &ServerId("s0".into())).await;
    st.inv
        .audit("admin", "server.deploy", Some("s0"), None)
        .await
        .unwrap();
    st.inv
        .set_public_base_url(Some("https://vpn.example.com"))
        .await
        .unwrap();

    let html = fetch_html(router(st), "/admin/users/u0/delivery").await;
    assert!(
        html.contains(r#"data-copy-recommended="recommended-share-url""#),
        "one applied node must keep one primary artefact"
    );
    assert!(
        html.contains("1 server is still pending."),
        "pending detail must be explicit"
    );
    assert!(
        html.contains("Access for this user is still pending on these servers:"),
        "mixed fleet must explain what the artefact covers"
    );
    assert!(html.contains("s1"), "pending server must be named");
}

#[tokio::test]
async fn delivery_refuses_a_primary_link_without_deploy_or_grant_evidence() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    // Legacy import: the grant row exists, but there is no user mutation audit
    // and no successful deploy. Inventory rightly reports "not pending"; the
    // delivery page must still refuse to call the node applied.
    seed(&st.inv, 1, 1, &[(0, 0)]).await;
    seed_vless_secrets(&st, &ServerId("s0".into())).await;
    st.inv
        .set_public_base_url(Some("https://vpn.example.com"))
        .await
        .unwrap();

    let pending = st
        .inv
        .servers_pending_deploy_for_user(&UserId("u0".into()), &[ServerId("s0".into())])
        .await
        .unwrap();
    assert!(
        pending.is_empty(),
        "inventory contract: a missing user mutation audit must stay 'not pending'"
    );

    let html = fetch_html(router(st), "/admin/users/u0/delivery").await;
    assert!(
        !html.contains(r#"data-copy-recommended="recommended-share-url""#),
        "an unconfirmed grant must not expose a recommended live link"
    );
    assert!(
        html.contains("Deployment is not confirmed."),
        "missing deploy evidence must be named, not presented as applied"
    );
    assert!(
        html.contains(r#"href="/admin/servers/s0#deploy-button""#),
        "the remediation must be the web deploy action, not SSH guidance"
    );
    assert!(
        !html.contains("No renderable protocol is delivered on an applied node yet."),
        "an unconfirmed node must not be described as an applied node with hidden protocols"
    );
}

#[tokio::test]
async fn delivery_keeps_the_primary_link_for_an_applied_node_beside_an_unconfirmed_legacy_grant() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    seed(&st.inv, 2, 1, &[(0, 1)]).await;
    seed_vless_secrets(&st, &ServerId("s0".into())).await;
    grant_for_delivery(&st, "s0").await;
    st.inv
        .audit("admin", "server.deploy", Some("s0"), None)
        .await
        .unwrap();
    st.inv
        .set_public_base_url(Some("https://vpn.example.com"))
        .await
        .unwrap();

    let html = fetch_html(router(st), "/admin/users/u0/delivery").await;
    assert!(
        html.contains(r#"data-copy-recommended="recommended-share-url""#),
        "one confirmed applied renderable node must keep the primary artefact"
    );
    assert!(
        html.contains("Deployment is not confirmed on:"),
        "the unconfirmed grant must be named instead of silently trusted"
    );
    assert!(
        html.contains(r#"href="/admin/servers/s1#deploy-button""#),
        "the unconfirmed server must link to its web deploy action"
    );
}

#[tokio::test]
async fn delivery_offers_a_read_only_retry_when_deploy_evidence_cannot_be_read() {
    let dir = TempDir::new().unwrap();
    let (st, _) = ready_delivery_state(&dir).await;
    // Break just the evidence lookup in this disposable fixture. Other user
    // and audit reads still work, so the page can explain how to retry.
    let db = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new().filename(dir.path().join("inv.db")),
    )
    .await
    .unwrap();
    sqlx::query("ALTER TABLE grants RENAME COLUMN created_at TO unavailable_created_at")
        .execute(&db)
        .await
        .unwrap();

    let html = fetch_html(router(st), "/admin/users/u0/delivery").await;
    assert!(html.contains("The deployment history could not be read."));
    assert!(html.contains("Check again"));
    assert!(!html.contains("Deployment is not confirmed on:"));
    assert!(!html.contains(r#"data-copy-recommended="recommended-share-url""#));
}
