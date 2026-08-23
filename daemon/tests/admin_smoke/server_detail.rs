use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Registry, Server, ServerId, User, UserId};
use vpnctl_inventory::{SqliteInventory, VpnStatsDelta};
use vpnctl_kernels::SingBox;
use vpnctl_protocols::{TuicV5, VlessReality};
use vpnctld::{AppState, router};

use super::common::*;

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

/// W5 pin: protocol enable no-op re-POST writes NO second audit row
/// (NM-10) — the 4 toggle handlers audited unconditionally before.
#[tokio::test]
async fn protocol_enable_noop_repost_writes_no_audit_row() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    seed(&inv, 1, 0, &[]).await;
    let app = router(s);
    let post = || {
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/s0/protocols/tuic-v5/enable"),
        )
        .body(Body::empty())
        .unwrap()
    };
    let r1 = app.clone().oneshot(post()).await.unwrap();
    assert_eq!(
        r1.status(),
        StatusCode::SEE_OTHER,
        "first enable must succeed"
    );
    let r2 = app.oneshot(post()).await.unwrap();
    assert_eq!(
        r2.status(),
        StatusCode::SEE_OTHER,
        "no-op re-enable must still redirect"
    );
    let rows = inv
        .recent_audit(20)
        .await
        .unwrap()
        .iter()
        .filter(|e| e.action == "server.protocol.enable")
        .count();
    assert_eq!(rows, 1, "no-op re-enable must not write a second row");
}

/// Server-side pending-deploy banner (audit 2026-06-10 follow-up):
/// the ONE surface that can warn about a revoked-but-still-deployed
/// UUID is the server's own detail page — after a revoke the server
/// leaves the user's granted list, so no user-detail banner mentions
/// it. Pin: banner appears after a real revoke, clears after a
/// server.deploy row lands.
#[tokio::test]
async fn server_detail_shows_pending_banner_after_revoke_until_deploy() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    seed(&inv, 1, 1, &[(0, 0)]).await; // u0 granted s0
    inv.audit("admin", "server.deploy", Some("s0"), None)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let app = router(s);

    // Deployed + no membership change since → no banner.
    let html = fetch_html(app.clone(), "/admin/servers/s0").await;
    assert!(
        !html.contains("pending-deploy-banner"),
        "freshly-deployed server must not show the pending banner"
    );

    // Revoke u0 through the real handler → banner appears.
    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s0/grants/u0/revoke"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let html = fetch_html(app.clone(), "/admin/servers/s0").await;
    assert!(
        html.contains("pending-deploy-banner"),
        "revoke must raise the server-side pending-deploy banner"
    );

    // A deploy AFTER the revoke clears it.
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    inv.audit("admin", "server.deploy", Some("s0"), None)
        .await
        .unwrap();
    let html = fetch_html(app, "/admin/servers/s0").await;
    assert!(
        !html.contains("pending-deploy-banner"),
        "deploy must clear the pending banner"
    );
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

// ── wgturn info section on /admin/servers/{id} ──────────────────────
//
// Pre-2026-05-19 this was a vk_link operator-input FORM. Pavel
// 2026-05-19: «пользователь сам вставляет свою ссылку, так как у
// каждого звонка ограниченное кол-во потоков» — VK link is end-
// user-supplied at connect time per upstream `pkg/wgshare/doc.go`.
// The section is now info-only, explaining the operator-facing
// contract for the operator + sketching the user-facing CLI step
// the user runs on their device.

/// Pavel 2026-05-19: «не очень понимаю логику взаимодействия с
/// server, если я включаю trojan, мне нужно жать deploy или он
/// сразу при клики включается, по поводу kernel тот же вопрос».
/// Both the Kernels and the Enabled-protocols sections MUST carry
/// a loud (accent-bordered) banner explaining that toggles touch
/// inventory only and a subsequent click of «deploy →» is needed
/// to push the change to the live node. Anchor href to the deploy
/// button so it works as a scroll-to-top link.
#[tokio::test]
async fn server_detail_kernels_and_protocols_banners_explain_deploy_step() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&vpnctl_core::Server {
            id: vpnctl_core::ServerId("dx".into()),
            address: "203.0.113.30".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![vpnctl_core::KernelId("sing-box".into())],
            enabled_protocols: vec![vpnctl_core::ProtocolId("vless+reality".into())],
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
                .uri("/admin/servers/dx/protocols")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();

    // Deploy button has an anchor id so the banner-links can target it.
    assert!(
        html.contains("id=\"deploy-button\""),
        "Deploy button container must have id=\"deploy-button\""
    );
    // The banner phrase appears TWICE — once in Kernels, once in
    // Enabled protocols (deliberately duplicated; operators jump
    // straight to whichever section they're touching).
    let banner_marker = "toggle here = inventory only";
    let occurrences = html.matches(banner_marker).count();
    assert_eq!(
        occurrences, 2,
        "expected the «toggle = inventory only» banner in BOTH Kernels and Protocols sections; \
         got {occurrences}"
    );
    // Each banner links back to the deploy button (#deploy-button
    // anchor) so a one-click scroll takes the operator to the
    // button without keyboard navigation.
    assert!(
        html.matches("href=\"#deploy-button\"").count() >= 2,
        "each banner must include a link to #deploy-button so click → scroll-to-top works"
    );
}

#[tokio::test]
async fn server_detail_omits_wgturn_section_for_non_wgturn_kernels() {
    // Server with only sing-box kernel — the wgturn section must NOT
    // render. Keeps the page short for the common case.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&vpnctl_core::Server {
            id: vpnctl_core::ServerId("plain".into()),
            address: "203.0.113.10".into(),
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
            Request::builder()
                .uri("/admin/servers/plain")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        !html.contains("wgturn — emergency channel"),
        "section must NOT render for non-wgturn servers"
    );
    assert!(
        !html.contains("wgturn-cli connect-url"),
        "info block must NOT render for non-wgturn servers"
    );
}

#[tokio::test]
async fn server_detail_renders_wgturn_info_when_kernel_enabled() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&vpnctl_core::Server {
            id: vpnctl_core::ServerId("wt-1".into()),
            address: "203.0.113.20".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![vpnctl_core::KernelId("wgturn".into())],
            enabled_protocols: vec![vpnctl_core::ProtocolId("wgturn".into())],
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
                .uri("/admin/servers/wt-1/protocols")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("wgturn — emergency channel"),
        "info eyebrow must render"
    );
    // Operator copy must explicitly state the end-user-supplies rule.
    assert!(
        html.contains("VK link is supplied by the END USER"),
        "must explain that VK link is end-user-supplied: {html}"
    );
    // The CLI example must surface the `--vk-link` flag so the
    // operator knows what to tell the user to type.
    assert!(
        html.contains("--vk-link"),
        "must show the user-side CLI invocation with `--vk-link`: {html}"
    );
    // The OLD operator-facing form MUST NOT be present anywhere.
    assert!(
        !html.contains(r#"name="vk_link""#),
        "pre-2026-05-19 vk_link form must be gone: {html}"
    );
    assert!(
        !html.contains("/wgturn/vk-link"),
        "pre-2026-05-19 vk_link POST action must be gone: {html}"
    );
}

#[tokio::test]
async fn server_detail_wgturn_info_does_not_leak_stale_vk_link_secret() {
    // Migration safety: if a daemon was upgraded from pre-2026-05-19,
    // the inventory's `server_secrets` table may still carry a
    // `wgturn:vk_link` row. The info section MUST NOT read or echo it
    // — the value is dead data; rendering it would be a secret leak.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&vpnctl_core::Server {
            id: vpnctl_core::ServerId("wt-2".into()),
            address: "203.0.113.21".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![vpnctl_core::KernelId("wgturn".into())],
            enabled_protocols: vec![vpnctl_core::ProtocolId("wgturn".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let stale = "https://vk.com/call/join/stale-from-pre-may19";
    st.inv
        .set_server_secret(
            &vpnctl_core::ServerId("wt-2".into()),
            "wgturn:vk_link",
            stale,
        )
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/wt-2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        !html.contains("stale-from-pre-may19"),
        "stale vk_link MUST NOT leak into HTML — got: {html}"
    );
}

#[tokio::test]
async fn admin_servers_id_wgturn_vk_link_route_returns_404() {
    // Pre-2026-05-19 this was a POST endpoint. Post-removal it
    // should 404 (no route registered). Pin the contract so we
    // don't accidentally restore the endpoint without re-discussing
    // the design.
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let mut req = Request::builder()
        .method("POST")
        .uri("/admin/servers/anything/wgturn/vk-link")
        .header("content-type", "application/x-www-form-urlencoded");
    req = add_same_origin(req);
    let resp = app
        .oneshot(req.body(Body::from("vk_link=irrelevant")).unwrap())
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "removed route must 404 (got {:?})",
        resp.status()
    );
}

// ────────────────────────────────────────────────────────────────────────
// Phase H chunk 3 — server detail page (/admin/servers/{id})
//
// Covers:
//   * Unknown server → 404 with canonical body
//   * Known server, no probes → empty-state mentions "chunk 4"
//   * Known server WITH a probe row → KPI tiles render with real numbers
//   * Drift highlight when declared protocols disagree with observed
//     listening ports
//   * Servers-list page links to the detail page (clickable headline)

#[tokio::test]
async fn admin_server_detail_unknown_id_returns_404() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/no-such")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(text.starts_with("vpnctl admin: no such server"));
}

#[tokio::test]
async fn admin_server_detail_no_probe_shows_chunk4_empty_state() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await; // server s0 only
    let html = fetch_html(router(s), "/admin/servers/s0").await;
    assert!(html.contains("Live status"));
    assert!(
        html.contains("No probes yet"),
        "empty-state copy must mention 'No probes yet'"
    );
    // Copy refreshed 2026-06-10: poller is LIVE at a 10-min cadence;
    // blank = not probed yet / not a sing-box node.
    assert!(
        html.contains("every 10 min"),
        "must state the live poller cadence"
    );
}

#[tokio::test]
async fn admin_server_detail_with_probe_renders_kpis() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    // Insert a probe row matching what node_probe would produce
    s.inv
        .record_node_health(
            &ServerId("s0".into()),
            Some(true),
            Some(true),
            Some(9876),
            Some(20480),
            Some(231),
            Some(960),
            Some(4),
            Some(r#"["tcp/443","tcp/8388","udp/8388","udp/8443"]"#),
            Some(308_432),
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/servers/s0").await;
    // Dense six-tile hero strip visible.
    assert!(html.contains("ed-status-strip"));
    assert!(html.contains("active"), "sing-box active visible");
    assert!(html.contains("48%"), "disk pct visible (9876/20480)");
    assert!(html.contains("76%"), "mem pct visible (1 - 231/960 = 76)");
    assert!(
        html.contains(r#"class="ed-status-tile warn""#),
        "memory above 70% must render the warm heat tile"
    );
    // No empty-state once we have data
    assert!(!html.contains("No probes yet"));
}

#[tokio::test]
async fn admin_server_detail_highlights_drift_between_declared_and_observed() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // Server declares vless+reality + tuic-v5 in inventory
    s.inv
        .add_server(&vpnctl_core::Server {
            id: ServerId("driftnode".into()),
            address: "10.0.0.99".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![
                ProtocolId("vless+reality".into()),
                ProtocolId("tuic-v5".into()),
            ],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    // But the probe sees vless (tcp/443) AND an EXTRA hysteria2 (udp/8444),
    // and NO tuic (no udp/8443). Two drifts: missing tuic, extra hy2.
    s.inv
        .record_node_health(
            &ServerId("driftnode".into()),
            Some(true),
            Some(true),
            Some(1000),
            Some(10000),
            Some(500),
            Some(1000),
            Some(10),
            Some(r#"["tcp/22","tcp/443","udp/8444"]"#),
            Some(1000),
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/servers/driftnode/protocols").await;
    // v2 3c grid: the silent tuic port renders the warm flag + the
    // declared-but-NOT-listening line names it.
    assert!(
        html.contains("✗ silent") || html.contains("✗ молчит"),
        "silent declared port must carry the ✗ flag; got: {}",
        &html[..html.len().min(400)]
    );
    assert!(
        html.contains("declared but NOT listening"),
        "missing-port warning line must render"
    );
    assert!(
        html.contains("udp/8443"),
        "missing tuic udp/8443 must be listed"
    );
    // The extra hysteria2 socket lands in the grouped undeclared table
    // (unclassified group names raw ports).
    assert!(
        html.contains("Listening but undeclared"),
        "undeclared group table must render"
    );
    assert!(
        html.contains("udp/8444"),
        "extra hysteria2 udp/8444 must be listed in a group"
    );
    // SSH port 22 must NOT be flagged as "extra" (always-listening).
    let undeclared = html.split("Listening but undeclared").nth(1).unwrap_or("");
    assert!(
        !undeclared.contains("tcp/22"),
        "ssh port must be excluded from the undeclared groups"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Pavel iter A1: server-detail protocols section — checkbox list of every
// registered protocol with enable/disable form. Closes the "main-brat WG
// keys are useless because vps-is-01 doesn't run wireguard" gap by
// letting the operator add protocols to an existing server without CLI.

#[tokio::test]
async fn admin_server_detail_protocols_section_shows_every_registered_protocol() {
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("nowg".into()),
            address: "203.0.113.7".into(),
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
    let html = fetch_html(app, "/admin/servers/nowg/protocols").await;
    assert!(html.contains("Enabled protocols"), "section heading");
    // Every registered protocol appears as a row (sing-box ships 6,
    // amneziawg ships 1 — total 7 unique ids in the registry).
    for pid in [
        "vless+reality",
        "tuic-v5",
        "hysteria2",
        "shadowsocks-2022",
        "anytls",
        "trojan",
        "wireguard",
    ] {
        assert!(
            html.contains(pid),
            "protocol row '{pid}' missing from server-detail"
        );
    }
    // The currently-enabled one has a disable button + ✓ on marker.
    // `+` in vless+reality gets URL-encoded to %2B in the form action.
    assert!(
        html.contains(r#"/admin/servers/nowg/protocols/vless%2Breality/disable"#),
        "enabled protocol must have a disable form (vless+reality URL-encoded)"
    );
    assert!(html.contains("✓ on"), "enabled marker missing");
    // A compatible-but-not-yet-enabled one has an enable button.
    assert!(
        html.contains(r#"/admin/servers/nowg/protocols/hysteria2/enable"#),
        "compatible-disabled protocol must have an enable form"
    );
    // Incompatible (wireguard under sing-box kernel) is greyed out
    // with no toggle button — only the explainer copy.
    assert!(
        html.contains("not supported by kernel sing-box"),
        "incompatible explainer must appear next to wireguard"
    );
    assert!(
        !html.contains(r#"/admin/servers/nowg/protocols/wireguard/enable"#),
        "incompatible protocol MUST NOT have an enable form"
    );
}

#[tokio::test]
async fn admin_server_enable_protocol_persists_and_audits() {
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_server(&Server {
            id: ServerId("amz".into()),
            address: "198.51.100.5".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("amneziawg".into())],
            enabled_protocols: vec![], // start empty
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/amz/protocols/wireguard/enable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let server = inv
        .get_server(&ServerId("amz".into()))
        .await
        .unwrap()
        .unwrap();
    assert!(
        server
            .enabled_protocols
            .contains(&ProtocolId("wireguard".into())),
        "wireguard must be persisted into enabled_protocols"
    );
    // Audit row exists with the protocol name + newly_added flag.
    let audit = inv.recent_audit(5).await.unwrap();
    let row = audit
        .iter()
        .find(|a| a.action == "server.protocol.enable")
        .expect("audit row");
    let payload = row
        .payload
        .as_ref()
        .map(|v| v.to_string())
        .unwrap_or_default();
    assert!(payload.contains("wireguard"));
    assert!(payload.contains("newly_added"));
}

#[tokio::test]
async fn admin_server_enable_protocol_rejects_unregistered_protocol_id() {
    use vpnctl_core::{KernelId, Server, ServerId};
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
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/sb/protocols/totally-fake/enable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(text.contains("unknown protocol"));
    assert!(text.contains("totally-fake"));
}

#[tokio::test]
async fn admin_server_disable_protocol_removes_row_and_audits() {
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_server(&Server {
            id: ServerId("sb".into()),
            address: "203.0.113.7".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![
                ProtocolId("vless+reality".into()),
                ProtocolId("tuic-v5".into()),
            ],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/sb/protocols/tuic-v5/disable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let server = inv
        .get_server(&ServerId("sb".into()))
        .await
        .unwrap()
        .unwrap();
    assert!(
        !server
            .enabled_protocols
            .contains(&ProtocolId("tuic-v5".into())),
        "tuic-v5 must be gone after disable"
    );
    assert!(
        server
            .enabled_protocols
            .contains(&ProtocolId("vless+reality".into())),
        "other protocols must stay untouched"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Multi-kernel server (Pavel: «а что на 1 сервере не может быть 2 ядра?»).
// Server.kernels is now Vec<KernelId>; server detail gains a Kernels
// section with enable/disable mirroring the Protocols section.

#[tokio::test]
async fn admin_server_detail_kernels_section_shows_every_registered_kernel() {
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("sb-only".into()),
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
    let html = fetch_html(app, "/admin/servers/sb-only/protocols").await;
    assert!(html.contains("Kernels"), "Kernels heading missing");
    // sing-box is registered AND enabled → disable form
    assert!(
        html.contains("/admin/servers/sb-only/kernels/sing-box/disable"),
        "enabled kernel must have disable form"
    );
    // amneziawg is registered but NOT enabled → enable form
    assert!(
        html.contains("/admin/servers/sb-only/kernels/amneziawg/enable"),
        "disabled kernel must have enable form"
    );
}

#[tokio::test]
async fn admin_server_enable_kernel_persists_and_audits() {
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_server(&Server {
            id: ServerId("hybrid".into()),
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
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/hybrid/kernels/amneziawg/enable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let server = inv
        .get_server(&ServerId("hybrid".into()))
        .await
        .unwrap()
        .unwrap();
    let kids: Vec<&str> = server.kernels.iter().map(|k| k.0.as_str()).collect();
    assert!(
        kids.contains(&"sing-box") && kids.contains(&"amneziawg"),
        "hybrid server must run both kernels post-enable, got: {kids:?}"
    );
    let audit = inv.recent_audit(5).await.unwrap();
    assert!(
        audit.iter().any(|a| a.action == "server.kernel.enable"),
        "audit row for kernel enable missing"
    );
}

#[tokio::test]
async fn admin_server_enable_kernel_rejects_unregistered_id() {
    use vpnctl_core::{KernelId, Server, ServerId};
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
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/sb/kernels/totally-fake/enable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(text.contains("unknown kernel"));
}

#[tokio::test]
async fn admin_multi_kernel_server_enables_wireguard_protocol() {
    // The end-to-end scenario Pavel raised: add amneziawg kernel
    // to a sing-box node → wireguard protocol becomes enable-able
    // (not "incompatible") on the same server.
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_server(&Server {
            id: ServerId("dual".into()),
            address: "203.0.113.7".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into()), KernelId("amneziawg".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(s);
    let html = fetch_html(app.clone(), "/admin/servers/dual/protocols").await;
    // wireguard MUST now show an enable form (previously was
    // "incompatible" under the sing-box-only kernel).
    assert!(
        html.contains("/admin/servers/dual/protocols/wireguard/enable"),
        "wireguard must be enable-able once amneziawg kernel is on the server"
    );
    // Validate end-to-end: actually enable wireguard, then assert
    // it lands in the row.
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/dual/protocols/wireguard/enable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let server = inv
        .get_server(&ServerId("dual".into()))
        .await
        .unwrap()
        .unwrap();
    assert!(
        server.enabled_protocols.iter().any(|p| p.0 == "wireguard"),
        "wireguard should be in enabled_protocols after enable"
    );
}

// Pavel iter B — server-side grant/revoke (centralised view on
// server detail). Same mutation as user-side, but redirect lands
// back on the server page so the operator stays where they started.

#[tokio::test]
async fn admin_server_detail_lists_all_users_with_grant_buttons() {
    use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
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
    for uid in ["alice", "bob"] {
        s.inv
            .add_user(&User {
                id: UserId(uid.into()),
                uuid: format!("uuid-{uid}"),
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
    // Grant alice but not bob.
    s.inv
        .grant(&UserId("alice".into()), &ServerId("sb".into()))
        .await
        .unwrap();
    let app = router(s);
    let html = fetch_html(app, "/admin/servers/sb/grants").await;
    // Alice = granted → revoke form
    assert!(
        html.contains("/admin/servers/sb/grants/alice/revoke"),
        "granted user must have revoke form on server detail"
    );
    // Bob = ungranted → grant form
    assert!(
        html.contains("/admin/servers/sb/grants/bob"),
        "ungranted user must have grant form on server detail"
    );
    // Counter pin (1 of 2)
    assert!(html.contains("1 of 2"), "X of N counter missing");
}

// ─── Operator-facing Deploy button (CLAUDE.md "Web is the ONLY
//     operator surface" — Pavel must never open a terminal).

#[tokio::test]
async fn admin_server_detail_shows_deploy_button() {
    use vpnctl_core::{KernelId, Server, ServerId};
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

/// "Update kernels" button (update-kernels PR2): the server-detail page
/// shows the SSE-driven kernel-binary upgrade trigger with its OWN log
/// pane (`update-kernels-log`, distinct from `deploy-log`). Copy-contract.
#[tokio::test]
async fn admin_server_detail_shows_update_kernels_button() {
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("ukb".into()),
            address: "203.0.113.8".into(),
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
    let html = fetch_html(app, "/admin/servers/ukb").await;
    assert!(
        html.contains(r#"data-sse-url="/admin/servers/ukb/update-kernels/sse""#),
        "update-kernels button must carry the per-server SSE trigger URL"
    );
    // Its OWN log pane — distinct from the deploy button's `deploy-log`.
    assert!(
        html.contains(r#"id="update-kernels-log""#),
        "update-kernels needs its own live log pane (not deploy-log)"
    );
    assert!(
        html.contains(r#"data-log="update-kernels-log""#),
        "update-kernels button must point admin.js at its own log pane"
    );
    assert!(
        html.contains("update kernels") || html.contains("обновить ядра"),
        "update-kernels button label drifted"
    );
}

/// Operator-action-policy contract (CLAUDE.md HARD rule): the
/// update-kernels button's title / caption must NOT carry a bare
/// `ssh root@…` operator instruction. It describes what the DAEMON does
/// (apt upgrade + service restart), matching Deploy's allowed descriptive
/// register — it must not read as a shell-on-node instruction-to-operator.
#[tokio::test]
async fn admin_server_detail_update_kernels_copy_has_no_ssh_operator_instruction() {
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("ukpolicy".into()),
            address: "203.0.113.11".into(),
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
    let html = fetch_html(app, "/admin/servers/ukpolicy").await;
    // No bare operator-facing `ssh root@…` instruction anywhere on the
    // page (the page carries no ssh-instruction copy today; the new
    // update-kernels block must not introduce one).
    assert!(
        !html.contains("ssh root@"),
        "update-kernels copy must not instruct the operator to `ssh root@…` the node"
    );
}

/// Handler smoke: a cross-site `Sec-Fetch-Site` on the per-server
/// update-kernels SSE route is refused with 403 (CSRF guard), mirroring
/// the deploy SSE guard. A full stream needs a live node — the guard +
/// not-found below are the daemon-side analog.
#[tokio::test]
async fn server_update_kernels_sse_cross_site_is_403() {
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("uksse".into()),
            address: "203.0.113.12".into(),
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
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/uksse/update-kernels/sse")
                .header("sec-fetch-site", "cross-site")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "cross-site update-kernels SSE trigger must be refused"
    );
}

/// Handler smoke: the per-server update-kernels SSE route 404s for an
/// unknown server id (server lookup runs after the same-origin guard).
#[tokio::test]
async fn server_update_kernels_sse_unknown_server_is_404() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/no-such/update-kernels/sse")
                .header("sec-fetch-site", "same-origin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains("no such server"),
        "404 body should name the missing server, got: {text}"
    );
}

#[tokio::test]
async fn admin_server_deploy_bootstraps_keys_but_keeps_pending_on_failure() {
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
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
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
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
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
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

// ────────────────────────────────────────────────────────────────────────
//  Phase 4a — user-detail 30d aggregates + VPN-egress hide toggle.
// ────────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────────
//  Phase 4b — server-detail Live activity tile + dashboard VPN-activity.
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn phase4b_server_detail_renders_live_activity_section_when_no_samples() {
    // Pavel: even before the poller has sampled, the section must
    // render (with empty-state «active now: 0», «last poll: never»)
    // so the page structure is predictable. NM-11 caveat copy
    // present.
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("emptynode".into()),
            address: "192.0.2.99".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: Vec::new(),
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/servers/emptynode/activity").await;
    assert!(
        html.contains("Live activity · last 24h"),
        "server-detail must surface the Phase 4b live-activity section eyebrow"
    );
    assert!(
        html.contains("NM-11"),
        "section must mention NM-11 upstream caveat so the operator knows why per-user is zero"
    );
    assert!(
        html.contains("active now") && html.contains("upload 24h") && html.contains("download 24h"),
        "all 4 tile labels must render"
    );
    assert!(
        html.contains("last poll: ") && html.contains("never"),
        "empty-state must read «last poll: never»"
    );
}

// ────────────────────────────────────────────────────────────────────────
//  Phase 4c — server-detail Live connections drill-down section
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn phase4c_server_detail_renders_empty_state_when_no_snapshot() {
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("emptynode".into()),
            address: "192.0.2.99".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: Vec::new(),
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/emptynode/activity").await;
    assert!(
        html.contains("Live connections"),
        "server-detail must surface the Phase 4c section eyebrow even without data"
    );
    assert!(
        html.contains("No clash-api snapshot for this server yet"),
        "empty-state copy must explain the 5-minute poller cadence"
    );
}

#[tokio::test]
async fn phase4c_server_detail_renders_top_destinations_and_sources_from_snapshot() {
    // Manually inject a snapshot into the cache so we don't need a
    // real clash-api running. Pin: top destinations + top sources +
    // network breakdown tiles + correlation column header.
    use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("active".into()),
            address: "203.0.113.10".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: Vec::new(),
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .add_user(&User {
            id: UserId("brat".into()),
            uuid: "br0".into(),
            sub_token: Some("brtok".into()),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    // brat fetched subscription from 9.9.9.9 → correlation
    // should surface that user_id when 9.9.9.9 appears as
    // sourceIP in the live snapshot.
    s.inv
        .log_sub_access(&UserId("brat".into()), "9.9.9.9", None, 200, 100)
        .await
        .unwrap();

    use vpnctld::clash_api::{Connection, ConnectionMeta, Snapshot};
    let snap = Snapshot {
        upload_total: 5000,
        download_total: 10000,
        connections: vec![
            Connection {
                id: "c1".into(),
                upload: 1000,
                download: 5000,
                start: "2026-05-21T18:00:00Z".into(),
                metadata: ConnectionMeta {
                    network: "tcp".into(),
                    destination_ip: "172.217.16.142".into(),
                    destination_port: "443".into(),
                    source_ip: "9.9.9.9".into(),
                    source_port: "55555".into(),
                    host: "youtube.com".into(),
                    user: None,
                },
            },
            Connection {
                id: "c2".into(),
                upload: 100,
                download: 200,
                start: "2026-05-21T18:00:01Z".into(),
                metadata: ConnectionMeta {
                    network: "udp".into(),
                    destination_ip: "1.1.1.1".into(),
                    destination_port: "53".into(),
                    source_ip: "9.9.9.9".into(),
                    source_port: "55556".into(),
                    host: String::new(),
                    user: None,
                },
            },
        ],
    };
    s.snapshot_cache.store(ServerId("active".into()), snap);

    let html = fetch_html(router(s), "/admin/servers/active/activity").await;
    assert!(html.contains("Live connections"));
    // Top destinations must include youtube.com (preferred over IP).
    assert!(
        html.contains("youtube.com:443"),
        "top destinations must render host:port preferring DNS name"
    );
    // Top sources must include the real client IP.
    assert!(
        html.contains("9.9.9.9"),
        "top sources must render the real source IP"
    );
    // Correlation should resolve `9.9.9.9` → `brat`.
    assert!(
        html.contains("href=\"/admin/users/brat\""),
        "source-IP-to-user correlation must surface brat as the likely owner of 9.9.9.9"
    );
    // Network breakdown tiles (TCP 1 / UDP 1).
    assert!(html.contains(">tcp<") || html.contains("tcp"));
    assert!(html.contains("udp"));
    // NM-11 caveat copy
    assert!(
        html.contains("NM-11"),
        "section must surface NM-11 explainer"
    );
}

// ────────────────────────────────────────────────────────────────────────
//  Phase 4d — sing-box log scrape exact attribution wins over sub_access
//  correlation in the «top sources» column.
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn phase4d_server_detail_log_attribution_wins_over_sub_access_correlation() {
    // Setup: clash snapshot has source IP 31.135.234.102 with no
    // sub_access row (so Phase 4c correlation returns nothing).
    // Phase 4d attribution map says 31.135.234.102 → main-brat.
    // The «top sources» row must surface main-brat (exact match,
    // tagged «log») not «—».
    use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
    use vpnctld::clash_api::{Connection, ConnectionMeta, Snapshot};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("phase4d-srv".into()),
            address: "203.0.113.50".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: Vec::new(),
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .add_user(&User {
            id: UserId("main-brat".into()),
            uuid: "mb0".into(),
            sub_token: None,
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    // NO sub_access_log row — so Phase 4c fallback would NOT
    // find a match. Only Phase 4d log attribution can.

    let snap = Snapshot {
        upload_total: 1000,
        download_total: 5000,
        connections: vec![Connection {
            id: "c1".into(),
            upload: 1000,
            download: 5000,
            start: "2026-05-21T19:00:00Z".into(),
            metadata: ConnectionMeta {
                network: "tcp".into(),
                destination_ip: "1.2.3.4".into(),
                destination_port: "443".into(),
                source_ip: "31.135.234.102".into(),
                source_port: "2810".into(),
                host: String::new(),
                user: Some("main-brat".into()),
            },
        }],
    };
    s.snapshot_cache.store(ServerId("phase4d-srv".into()), snap);

    let html = fetch_html(router(s), "/admin/servers/phase4d-srv/activity").await;
    // Exact match link to main-brat — now sourced from metadata.user
    // (the patched sing-box clash-api), not the removed log-scrape map.
    assert!(
        html.contains("href=\"/admin/users/main-brat\""),
        "metadata.user attribution must link the source IP to main-brat"
    );
}

#[tokio::test]
async fn phase4d_server_detail_falls_back_to_sub_access_when_no_log_attribution() {
    // Symmetric case — log attribution empty, sub_access has a
    // match → falls back, tagged «sub».
    use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
    use vpnctld::clash_api::{Connection, ConnectionMeta, Snapshot};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("phase4d-fb".into()),
            address: "203.0.113.51".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: Vec::new(),
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .add_user(&User {
            id: UserId("falluser".into()),
            uuid: "fb0".into(),
            sub_token: Some("fbtok".into()),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    // sub_access_log entry — Phase 4c sub_access correlation
    // hit for 5.5.5.5.
    s.inv
        .log_sub_access(&UserId("falluser".into()), "5.5.5.5", None, 200, 100)
        .await
        .unwrap();

    let snap = Snapshot {
        upload_total: 100,
        download_total: 200,
        connections: vec![Connection {
            id: "c1".into(),
            upload: 100,
            download: 200,
            start: "2026-05-21T19:00:00Z".into(),
            metadata: ConnectionMeta {
                network: "tcp".into(),
                destination_ip: "1.2.3.4".into(),
                destination_port: "443".into(),
                source_ip: "5.5.5.5".into(),
                source_port: "55555".into(),
                host: String::new(),
                user: None,
            },
        }],
    };
    // EMPTY attribution map — Phase 4d had nothing for this IP.
    s.snapshot_cache.store(ServerId("phase4d-fb".into()), snap);

    let html = fetch_html(router(s), "/admin/servers/phase4d-fb/activity").await;
    // Must link to falluser via sub_access fallback.
    assert!(
        html.contains("href=\"/admin/users/falluser\""),
        "sub_access fallback must link the source IP to falluser when log attribution is empty"
    );
    // Tagged «sub» (not «log»).
    assert!(
        html.contains(">sub<"),
        "tag «sub» must indicate fallback-via-sub_access"
    );
    assert!(
        !html.contains(">log<"),
        "no «log» tag when log attribution map is empty"
    );
}

#[tokio::test]
async fn phase4d_server_detail_renders_dash_when_neither_log_nor_sub_has_attribution() {
    // Pin the «both layers empty» path: no log attribution, no
    // sub_access correlation hits → the «likely user» cell must
    // render «—» with NO `<a href="/admin/users/...">` link.
    use vpnctl_core::{KernelId, Server, ServerId};
    use vpnctld::clash_api::{Connection, ConnectionMeta, Snapshot};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("phase4d-none".into()),
            address: "203.0.113.52".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: Vec::new(),
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    // NO users added → users_for_source_ips returns no matches
    // for any IP, and we pass an empty attribution map.

    let snap = Snapshot {
        upload_total: 100,
        download_total: 100,
        connections: vec![Connection {
            id: "c1".into(),
            upload: 100,
            download: 100,
            start: "2026-05-21T19:00:00Z".into(),
            metadata: ConnectionMeta {
                network: "tcp".into(),
                destination_ip: "1.2.3.4".into(),
                destination_port: "443".into(),
                source_ip: "203.0.113.99".into(),
                source_port: "55555".into(),
                host: String::new(),
                user: None,
            },
        }],
    };
    s.snapshot_cache
        .store(ServerId("phase4d-none".into()), snap);

    let html = fetch_html(router(s), "/admin/servers/phase4d-none/activity").await;
    // Source IP must render in the top-sources row.
    assert!(
        html.contains("203.0.113.99"),
        "the unattributed source IP must still render in the table"
    );
    // NO link to any user-detail for this orphan IP. We use a
    // targeted check: extract the slice around the source IP cell
    // and assert it doesn't carry a user-detail link.
    let pos = html.find("203.0.113.99").expect("source IP must render");
    // The cell + the next ~400 chars cover the «likely user» cell.
    let window = &html[pos..pos.saturating_add(800)];
    assert!(
        !window.contains("href=\"/admin/users/"),
        "orphan source IP must NOT link to any user-detail; window: …{window}…"
    );
    // The «—» glyph appears as the cell content.
    assert!(
        window.contains("—"),
        "«likely user» cell must render «—» for orphan IP, got window: …{window}…"
    );
}

// ── Phase H+ — per-server uptime SLO section ─────────────────────────
//
// Two tests pin the section's render contract:
//   1. Empty (no node_health rows) — section MUST NOT render. The
//      hero already owns the «no probes yet» empty-state; stacking
//      another would be noise. This is the «empty branch returns
//      `html! {}`» guard.
//   2. With probe rows — section renders with eyebrow + 3 chips
//      labelled 24h/7d/30d + percent text «100%» (all-up).

#[tokio::test]
async fn server_detail_uptime_section_omitted_when_no_probes() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&Server {
            id: ServerId("nuevo".into()),
            address: "203.0.113.99".into(),
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
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/nuevo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    // The section's anchor id + eyebrow text are the canonical
    // markers; both must be absent when there are no probes.
    assert!(
        !html.contains("id=\"uptime-section\""),
        "uptime section must NOT render for a server with zero node_health rows"
    );
    assert!(
        !html.contains("Uptime · sing-box service"),
        "uptime section eyebrow must NOT render when section is suppressed"
    );
}

#[tokio::test]
async fn server_detail_renders_traffic_gap_section() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let sid = ServerId("gaptest".into());
    st.inv
        .add_server(&Server {
            id: sid.clone(),
            address: "203.0.113.9".into(),
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
    // Two NIC readings → rx Δ5 GB, tx 0 → nic_total ≈ 5 GB.
    for rx in [1_000_000_000u64, 6_000_000_000u64] {
        st.inv
            .record_node_health(
                &sid,
                Some(true),
                Some(true),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some("ens18"),
                Some(rx),
                Some(0),
                None,
            )
            .await
            .unwrap();
    }
    // Clash attributes ~1 GB → the gap is ~4 GB of unseen traffic.
    st.inv
        .record_vpn_stats(
            &sid,
            &[vpnctl_inventory::VpnStatsDelta {
                user_id: None,
                upload_bytes: 1_000_000_000,
                download_bytes: 0,
                active_connections: 0,
            }],
        )
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/gaptest/activity")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    // Section + the three tiles render (NIC ground-truth vs attributed vs gap).
    assert!(html.contains("Traffic accounting"), "gap section eyebrow");
    assert!(html.contains("NIC total"), "NIC total tile");
    assert!(html.contains("GAP (unattributed)"), "gap tile");
    assert!(html.contains("ens18"), "interface name shown");
    // With 2 samples it must NOT show the empty-state.
    assert!(
        !html.contains("No NIC ground-truth yet"),
        "should render real numbers, not the empty-state"
    );
}

#[tokio::test]
async fn server_detail_uptime_section_renders_with_probe_data() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let sid = ServerId("with-data".into());
    st.inv
        .add_server(&Server {
            id: sid.clone(),
            address: "203.0.113.50".into(),
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
    // Seed 5 all-up probes. record_node_health uses ts=now so all
    // will fall inside the 24h/7d/30d windows.
    for _ in 0..5 {
        st.inv
            .record_node_health(
                &sid,
                Some(true),  // sing_box_active
                Some(true),  // fail2ban_active
                Some(1024),  // disk_used_mib
                Some(10240), // disk_total_mib
                Some(500),   // mem_available_mib
                Some(1024),  // mem_total_mib
                Some(50),    // load_1min_x100
                Some("[\"tcp/443\",\"udp/8443\"]"),
                Some(1024 * 1024),
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
    }
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/with-data")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    // Section anchor + eyebrow must both appear.
    assert!(
        html.contains("id=\"uptime-section\""),
        "uptime section must render when probes exist"
    );
    assert!(
        html.contains("Uptime · sing-box service"),
        "eyebrow copy must render (EN default)"
    );
    // All three window labels must be present.
    for chip in &["last 24h", "last 7d", "last 30d"] {
        assert!(
            html.contains(chip),
            "chip label «{chip}» must render in uptime section"
        );
    }
    // With 5 up probes + 0 down, all three chips MUST read 100%.
    // We assert on the stable `data-uptime-pct="100"` attribute
    // (review-agent NM-uptime catch) rather than scanning for the
    // literal «100%» text — the admin page has 11+ unrelated
    // `100%` substrings (CSS `width: 100%`, full-disk tile, etc.)
    // and a regression where all three chips fell through to
    // `None` could falsely pass an inline-text count.
    let pct_attr_count = html.matches("data-uptime-pct=\"100\"").count();
    assert_eq!(
        pct_attr_count,
        3,
        "all three uptime chips must carry data-uptime-pct=\"100\" \
         (found {pct_attr_count}); html len = {} bytes",
        html.len()
    );
    // Probe count chip footer must mention «probes».
    assert!(
        html.contains("probes"),
        "chip footer must show «N probes» count"
    );
}

// ── A3 — per-server 24h resource-trend sparklines ───────────────────
//
// Renders ONLY when at least one node_health row exists for the
// server in the last 24h. Fresh server (no probes yet) gets
// nothing — the hero section already covers the empty-state.

#[tokio::test]
async fn server_detail_resource_trend_omitted_when_no_probe_data() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&Server {
            id: ServerId("freshly".into()),
            address: "203.0.113.10".into(),
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
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/freshly")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        !html.contains("id=\"resource-trend\""),
        "no probe data → resource-trend section must be omitted"
    );
}

// ── server delete (retype-to-confirm + cascade + audit) ──────────────────

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

// ════════════════════════════════════════════════════════════════════
//  PR-Server — informativeness cards on the server-detail page.
//  DOM + empty-state per card; the ?drift=live gating + policy-safe
//  SSH-failure path; NM-11 empty-state; copy-contract EN + RU.
// ════════════════════════════════════════════════════════════════════

/// server#1 — DEFAULT page load (no ?drift=live) renders the
/// «check live drift →» link and does NOT attempt any SSH. We can't
/// directly assert «no SSH» from the integration boundary, but the
/// node address is bogus (10.0.0.0) and the page MUST still return 200
/// fast — a default load that tried SSH would block on ConnectTimeout.
#[tokio::test]
async fn server_detail_drift_detail_default_shows_check_link_no_ssh() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await; // server s0
    let html = fetch_html(router(s), "/admin/servers/s0/protocols").await;
    assert!(
        html.contains("Drift detail · on-node UUIDs"),
        "drift-detail eyebrow missing on default load"
    );
    assert!(
        html.contains("check live drift →"),
        "default load must offer the [check live drift] link"
    );
    assert!(
        html.contains("?drift=live#drift-detail"),
        "the link must arm the ?drift=live opt-in"
    );
    // No live-read result copy on the default path.
    assert!(
        !html.contains("orphan uuids on node"),
        "default load must NOT render live-read results"
    );
}

/// server#1 — ?drift=live against an unreachable node (bogus address)
/// renders the POLICY-SAFE empty-state and NEVER 500s. The empty-state
/// copy must NOT instruct the operator to «ssh» the box.
#[tokio::test]
async fn server_detail_drift_live_failure_renders_policy_safe_empty_state() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // Address 192.0.2.1 is TEST-NET-1 (RFC 5737) — guaranteed
    // unroutable, so the live read fails fast under the ≤6s timeout.
    s.inv
        .add_server(&Server {
            id: ServerId("blackhole".into()),
            address: "192.0.2.1".into(),
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
    let html = fetch_html(router(s), "/admin/servers/blackhole/protocols?drift=live").await;
    // 200 (fetch_html asserts) + the policy-safe empty-state.
    assert!(
        html.contains("Couldn't read the live config"),
        "armed live-read failure must render the policy-safe empty-state"
    );
    assert!(
        html.contains("node unreachable or deploy key"),
        "empty-state must name the real cause (unreachable / deploy key)"
    );
    // Operator-action-policy: the DRIFT-DETAIL card's empty-state must
    // NEVER tell the operator to ssh the box. Scope the check to that
    // section (the page-wide Deploy button legitimately mentions an
    // automated «SSH into the node» it performs for the operator — a
    // different, allowed string).
    let drift_section = html
        .split("Drift detail · on-node UUIDs")
        .nth(1)
        .unwrap_or("")
        .split("Server traffic · ")
        .next()
        .unwrap_or("");
    let lower = drift_section.to_lowercase();
    assert!(
        !lower.contains("ssh to the box")
            && !lower.contains("ssh into")
            && !lower.contains("run ssh"),
        "policy violation: drift-detail empty-state must not instruct an SSH session"
    );
}

/// server#3 — top-users card carries the NM-11 empty-state when no
/// per-user traffic is attributed (the prod reality).
#[tokio::test]
async fn server_detail_top_users_renders_nm11_empty_state() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let html = fetch_html(router(s), "/admin/servers/s0/activity").await;
    assert!(
        html.contains("Top users · last 24h"),
        "top-users eyebrow missing"
    );
    assert!(
        html.contains("NM-11"),
        "empty top-users card must carry the NM-11 explainer"
    );
}

/// server#3 — when per-user rows DO exist they render with a drill-in
/// link to the user-detail page (and the NM-11 empty-state is gone).
#[tokio::test]
async fn server_detail_top_users_lists_users_with_links_when_present() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await; // s0, u0 granted
    s.inv
        .record_vpn_stats(
            &ServerId("s0".into()),
            &[VpnStatsDelta {
                user_id: Some(UserId("u0".into())),
                upload_bytes: 3_000_000,
                download_bytes: 7_000_000,
                active_connections: 2,
            }],
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/s0/activity").await;
    assert!(
        html.contains(r#"href="/admin/users/u0""#),
        "top-users row must link to the user-detail page"
    );
    // Section present; the NM-11 empty-state must NOT show with data.
    let top_section = html.split("Top users · last 24h").nth(1).unwrap_or("");
    let next_section = top_section.split("TCP / UDP split").next().unwrap_or("");
    assert!(
        !next_section.contains("NM-11"),
        "NM-11 empty-state must not render once per-user rows exist"
    );
}

/// server#4 — per-server traffic sparkline renders with the window
/// picker scoped to /admin/servers/{id} and the ↑↓ totals tiles.
#[tokio::test]
async fn server_detail_traffic_section_renders_sparkline_and_window_picker() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    s.inv
        .record_vpn_stats(
            &ServerId("s0".into()),
            &[VpnStatsDelta {
                user_id: None, // server-wide row
                upload_bytes: 10_000_000,
                download_bytes: 40_000_000,
                active_connections: 12,
            }],
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/s0/activity").await;
    assert!(
        html.contains("Server traffic · "),
        "server-traffic eyebrow missing"
    );
    assert!(
        html.contains("↑ upload") && html.contains("↓ download"),
        "server-traffic ↑↓ totals tiles missing"
    );
    // Window picker links scoped to THIS server.
    assert!(
        html.contains("/admin/servers/s0/activity?vpn_window=7d"),
        "window picker must be scoped to /admin/servers/s0"
    );
    // An <svg> sparkline rendered for the populated window.
    let traffic = html.split("Server traffic · ").nth(1).unwrap_or("");
    assert!(
        traffic.contains("<svg"),
        "populated window must render the sparkline svg"
    );
}

/// server#4 — empty window renders the no-traffic empty-state, not a
/// broken/blank chart.
#[tokio::test]
async fn server_detail_traffic_section_empty_state_when_no_stats() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await; // no vpn stats recorded
    let html = fetch_html(router(s), "/admin/servers/s0/activity").await;
    assert!(
        html.contains("No traffic recorded in this window yet"),
        "empty traffic window must render the empty-state copy"
    );
}

/// server#5 — TCP/UDP split renders from the live snapshot with the
/// «no per-protocol tag» caption + tiles.
#[tokio::test]
async fn server_detail_network_split_renders_from_snapshot() {
    use vpnctld::clash_api::{Connection, ConnectionMeta, Snapshot};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let snap = Snapshot {
        upload_total: 300,
        download_total: 600,
        connections: vec![
            Connection {
                id: "c1".into(),
                upload: 100,
                download: 200,
                start: "2026-05-21T18:00:00Z".into(),
                metadata: ConnectionMeta {
                    network: "tcp".into(),
                    destination_ip: "1.1.1.1".into(),
                    destination_port: "443".into(),
                    source_ip: "9.9.9.9".into(),
                    source_port: "5000".into(),
                    host: String::new(),
                    user: None,
                },
            },
            Connection {
                id: "c2".into(),
                upload: 50,
                download: 100,
                start: "2026-05-21T18:00:01Z".into(),
                metadata: ConnectionMeta {
                    network: "udp".into(),
                    destination_ip: "1.1.1.1".into(),
                    destination_port: "53".into(),
                    source_ip: "9.9.9.9".into(),
                    source_port: "5001".into(),
                    host: String::new(),
                    user: None,
                },
            },
        ],
    };
    s.snapshot_cache.store(ServerId("s0".into()), snap);
    let html = fetch_html(router(s), "/admin/servers/s0/activity").await;
    assert!(
        html.contains("TCP / UDP split"),
        "network-split eyebrow missing"
    );
    assert!(
        html.contains("clash-api carries no per-protocol tag"),
        "network-split must carry the per-protocol caveat caption"
    );
}

/// server#5 — empty-state when no snapshot exists for the server.
#[tokio::test]
async fn server_detail_network_split_empty_state_when_no_snapshot() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await; // no snapshot cached
    let html = fetch_html(router(s), "/admin/servers/s0/activity").await;
    assert!(
        html.contains("TCP / UDP split"),
        "network-split eyebrow must render even with no snapshot"
    );
    assert!(
        html.contains("No clash-api snapshot for this server yet"),
        "network-split must render an empty-state when no snapshot"
    );
}

/// server#7 — server-scoped audit timeline renders rows that reference
/// this server (deploy/grant/etc), reusing the .ed-time component.
#[tokio::test]
async fn server_detail_audit_timeline_renders_server_scoped_rows() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    // An audit row targeting this server.
    s.inv
        .audit("admin", "server.deploy", Some("s0"), None)
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/s0/activity").await;
    assert!(
        html.contains("Audit timeline · this server"),
        "server-audit eyebrow missing"
    );
    assert!(
        html.contains("server.deploy"),
        "server-scoped audit row must list the deploy action"
    );
    assert!(
        html.contains("ed-time-row"),
        "audit timeline must reuse the .ed-time editorial component"
    );
}

/// server#7 — empty-state when no audit row references the server.
#[tokio::test]
async fn server_detail_audit_timeline_empty_state() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await; // seed writes no audit rows
    let html = fetch_html(router(s), "/admin/servers/s0/activity").await;
    assert!(
        html.contains("No audit rows reference this server yet"),
        "server-audit must render an empty-state with no rows"
    );
}

/// server#2 — per-server kernel rollup renders the sing-box floor +
/// on-target verdict from this node's kernel_versions_json.
#[tokio::test]
async fn server_detail_kernel_rollup_renders_version_for_this_node() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    s.inv
        .record_node_health(
            &ServerId("s0".into()),
            Some(true),
            Some(true),
            Some(1000),
            Some(10000),
            Some(500),
            Some(1000),
            Some(100),
            Some(r#"["tcp/443","udp/8443"]"#),
            Some(1000),
            Some(r#"{"sing-box":"1.13.12"}"#),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/s0/protocols").await;
    assert!(
        html.contains("Kernel rollup · sing-box"),
        "per-server kernel-rollup eyebrow missing"
    );
    assert!(
        html.contains("1.13.12"),
        "kernel-rollup must show this node's sing-box version"
    );
    assert!(
        html.contains("on target"),
        "single node at its own floor reads on-target"
    );
}

/// Copy-contract (EN) — pin every new PR-Server headline so a future
/// copy edit has to update this test in lockstep.
#[tokio::test]
async fn server_detail_info_cards_headlines_match_voice() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    // ui-audit §4 — these cards now live across tabs: server#1/#2 on
    // protocols, server#3/#4/#5 on activity, server#7 (audit) on the
    // default status tab. Fetch each tab and pin its subset.
    let app = router(s);
    let proto = fetch_html(app.clone(), "/admin/servers/s0/protocols").await;
    let act = fetch_html(app.clone(), "/admin/servers/s0/activity").await;
    let status = fetch_html(app, "/admin/servers/s0").await;
    for (html, needle) in [
        (&proto, "Drift detail · on-node UUIDs"), // server#1
        (&proto, "Kernel rollup · sing-box"),     // server#2
        (&act, "Top users · last 24h"),           // server#3
        (&act, "Server traffic · "),              // server#4
        (&act, "TCP / UDP split"),                // server#5
        (&status, "drift-summary"),               // status keeps the drift verdict
        (&act, "Audit timeline · this server"),   // server#7 (v2 3b: activity)
    ] {
        assert!(
            html.contains(needle),
            "PR-Server headline drifted — missing: {needle:?}"
        );
    }
}

/// Copy-contract (RU) — pin the Russian arm of each new PR-Server card
/// so a half-translation can't ship. Extends the i18n RU walker.
#[tokio::test]
async fn server_detail_info_cards_headlines_ru() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let app = router(s);
    let proto =
        fetch_html_with_cookie(app.clone(), "/admin/servers/s0/protocols", "vpnctl_lang=ru").await;
    let act =
        fetch_html_with_cookie(app.clone(), "/admin/servers/s0/activity", "vpnctl_lang=ru").await;
    let status = fetch_html_with_cookie(app, "/admin/servers/s0", "vpnctl_lang=ru").await;
    for (html, needle) in [
        (&proto, "Детальный дрейф · UUID на ноде"), // server#1
        (&proto, "Версии ядер · sing-box"),         // server#2
        (&act, "Топ пользователей · за 24ч"),       // server#3
        (&act, "Трафик сервера · "),                // server#4
        (&act, "Разбивка TCP / UDP"),               // server#5
        (&status, "drift-summary"),                 // status keeps the drift verdict
        (&act, "Лента аудита · этот сервер"),       // server#7 (v2 3b: activity)
    ] {
        assert!(
            html.contains(needle),
            "PR-Server RU headline drifted — missing: {needle:?}"
        );
    }
}

// ════════════════════════════════════════════════════════════════════
//  ui-audit Phase 1 — server_detail split into 5 sub-route tabs
//  (status / activity / protocols / grants / setup). Each tab renders
//  ONLY its own sections; the deploy chrome is on every tab; the active
//  tab carries `.ed-tab--on`; bare `/admin/servers/{id}` == status.
// ════════════════════════════════════════════════════════════════════

/// Each tab route → 200, renders the `.ed-tabs` bar, marks the right tab
/// active, shows a section unique to that tab, and does NOT leak a
/// foreign tab's section (proves the gating actually gates).
#[tokio::test]
async fn server_detail_tabs_render_gate_and_mark_active() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let app = router(s);
    // (path, active-slug, present-on-this-tab, absent-on-this-tab)
    let cases = [
        (
            "/admin/servers/s0/status",
            "status",
            "drift-summary",
            "Enabled protocols",
        ),
        (
            "/admin/servers/s0/activity",
            "activity",
            "Live activity · last 24h",
            "Enabled protocols",
        ),
        (
            "/admin/servers/s0/protocols",
            "protocols",
            "Enabled protocols",
            "Live activity · last 24h",
        ),
        (
            "/admin/servers/s0/grants",
            "grants",
            "users granted",
            "Enabled protocols",
        ),
        (
            "/admin/servers/s0/setup",
            "setup",
            "delete this server",
            "Enabled protocols",
        ),
    ];
    for (path, slug, present, absent) in cases {
        let html = fetch_html(app.clone(), path).await;
        assert!(
            html.contains(r#"class="ed-tabs""#),
            "{path}: tab bar (.ed-tabs) missing"
        );
        let active = format!(r#"ed-tab--on" href="/admin/servers/s0/{slug}""#);
        assert!(
            html.contains(&active),
            "{path}: {slug} tab not marked active"
        );
        assert!(
            html.contains(present),
            "{path}: missing its own section marker {present:?}"
        );
        assert!(
            !html.contains(absent),
            "{path}: leaked a foreign tab's section {absent:?}"
        );
    }
}

/// Bare `/admin/servers/{id}` renders the status tab directly — no
/// redirect — so old bookmarks + internal links keep working.
#[tokio::test]
async fn server_detail_bare_url_renders_status_tab() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let html = fetch_html(router(s), "/admin/servers/s0").await;
    assert!(
        html.contains(r#"ed-tab--on" href="/admin/servers/s0/status""#),
        "bare URL must mark the status tab active"
    );
    assert!(
        html.contains(r#"id="drift-summary""#),
        "bare URL must render the status tab's sections"
    );
    assert!(
        !html.contains("Enabled protocols"),
        "bare URL (status) must not render the protocols tab"
    );
}

/// §9 discoverability — the daily deploy action must never hide behind a
/// tab. The deploy SSE button lives in the chrome above the tab bar, so
/// it renders on every tab (bare + all 5).
#[tokio::test]
async fn server_detail_deploy_chrome_present_on_every_tab() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let app = router(s);
    let deploy = r#"data-sse-url="/admin/servers/s0/deploy/sse""#;
    for path in [
        "/admin/servers/s0",
        "/admin/servers/s0/status",
        "/admin/servers/s0/activity",
        "/admin/servers/s0/protocols",
        "/admin/servers/s0/grants",
        "/admin/servers/s0/setup",
    ] {
        let html = fetch_html(app.clone(), path).await;
        assert!(
            html.contains(deploy),
            "{path}: deploy button missing from chrome (regressed §9)"
        );
    }
}

/// Copy-contract — pin the 5 tab labels in both locales so a future
/// edit (or a half-translation) has to update this test in lockstep.
#[tokio::test]
async fn server_detail_tab_labels_copy_contract() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let app = router(s);
    let en = fetch_html(app.clone(), "/admin/servers/s0").await;
    for label in [
        ">Status</a>",
        ">Activity</a>",
        ">Protocols</a>",
        ">Grants · 0</a>",
        ">Setup</a>",
    ] {
        assert!(en.contains(label), "EN tab label drifted: {label:?}");
    }
    let ru = fetch_html_with_cookie(app, "/admin/servers/s0", "vpnctl_lang=ru").await;
    for label in [
        ">Статус</a>",
        ">Активность</a>",
        ">Протоколы</a>",
        ">Гранты · 0</a>",
        ">Настройка</a>",
    ] {
        assert!(ru.contains(label), "RU tab label drifted: {label:?}");
    }
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
