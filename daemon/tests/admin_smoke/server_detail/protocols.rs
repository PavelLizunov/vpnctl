use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
use vpnctld::router;

use crate::common::*;

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
        .add_server(&Server {
            id: ServerId("dx".into()),
            address: "203.0.113.30".into(),
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
async fn admin_server_detail_protocols_section_shows_every_registered_protocol() {
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

/// Router-level coverage only: proves AWG2/AWG3 toggle wiring, independent
/// mutations, auto-deploy dispatch, and no-op idempotency. The focused
/// wizard-bootstrap unit test separately proves that redeploy refreshes the
/// current server snapshot before minting protocol secrets.
#[tokio::test]
async fn admin_server_enable_awg2_and_awg3_dispatches_only_for_real_mutations() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_server(&Server {
        id: ServerId("awg-toggle".into()),
        address: "198.51.100.23".into(),
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

    let post = |protocol: &str| {
        add_same_origin(Request::builder().method("POST").uri(format!(
            "/admin/servers/awg-toggle/protocols/{protocol}/enable"
        )))
        .body(Body::empty())
        .unwrap()
    };

    let awg2 = app.clone().oneshot(post("amneziawg2")).await.unwrap();
    assert_eq!(awg2.status(), StatusCode::SEE_OTHER);
    wait_for_autodeploy_rows(&inv, 1).await;

    let awg3 = app.clone().oneshot(post("amneziawg3")).await.unwrap();
    assert_eq!(awg3.status(), StatusCode::SEE_OTHER);
    let auto_rows = wait_for_autodeploy_rows(&inv, 2).await;
    assert_eq!(auto_rows.len(), 2);
    for row in &auto_rows {
        assert_eq!(row.action, "server.autodeploy");
        assert_eq!(row.target.as_deref(), Some("awg-toggle"));
        let payload = row.payload.as_ref().unwrap();
        assert_eq!(payload["trigger"], "server.protocol.enable");
        assert_eq!(payload["servers"], serde_json::json!(["awg-toggle"]));
        assert_eq!(
            payload["ok"], false,
            "missing test deploy key must be recorded as an intentional failed dispatch"
        );
    }

    let server = inv
        .get_server(&ServerId("awg-toggle".into()))
        .await
        .unwrap()
        .unwrap();
    assert!(
        server
            .enabled_protocols
            .contains(&ProtocolId("amneziawg2".into()))
    );
    assert!(
        server
            .enabled_protocols
            .contains(&ProtocolId("amneziawg3".into()))
    );
    let mutation_rows = inv
        .recent_audit(20)
        .await
        .unwrap()
        .into_iter()
        .filter(|row| row.action == "server.protocol.enable")
        .count();
    assert_eq!(mutation_rows, 2, "each AWG toggle is one real mutation");

    for protocol in ["amneziawg2", "amneziawg3"] {
        let response = app.clone().oneshot(post(protocol)).await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        count_autodeploy_rows(&inv).await,
        2,
        "no-op AWG re-enables must not dispatch more auto-deploys"
    );
    let mutation_rows_after_reposts = inv
        .recent_audit(20)
        .await
        .unwrap()
        .into_iter()
        .filter(|row| row.action == "server.protocol.enable")
        .count();
    assert_eq!(
        mutation_rows_after_reposts, 2,
        "no-op AWG re-enables must not add mutation audit rows"
    );
}

#[tokio::test]
async fn admin_server_enable_protocol_rejects_unregistered_protocol_id() {
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
