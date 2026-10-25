use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
use vpnctld::router;

use crate::common::*;

#[tokio::test]
async fn protocol_enable_rejects_conflicting_caddy_front_without_mutation_or_audit() {
    for (enabled, requested) in [("naive", "vless-ws"), ("vless-ws", "naive")] {
        let dir = TempDir::new().unwrap();
        let s = state(&dir).await;
        let server = Server {
            id: ServerId("caddy-conflict".into()),
            address: "203.0.113.7".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("caddy".into()), KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId(enabled.into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        };
        s.inv.add_server(&server).await.unwrap();
        let before = s.inv.recent_audit(100).await.unwrap().len();
        let response = router(s.clone())
            .oneshot(
                add_same_origin(Request::builder().method("POST").uri(format!(
                    "/admin/servers/caddy-conflict/protocols/{requested}/enable"
                )))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let message = std::str::from_utf8(&body).unwrap();
        assert!(message.contains("naive") && message.contains("vless-ws"));
        assert_eq!(
            s.inv
                .get_server(&server.id)
                .await
                .unwrap()
                .unwrap()
                .enabled_protocols,
            server.enabled_protocols
        );
        assert_eq!(s.inv.recent_audit(100).await.unwrap().len(), before);
    }
}

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

#[tokio::test]
async fn server_detail_kernels_and_protocols_hints_explain_automatic_apply_in_both_languages() {
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
    for (cookie, banner, tooltip, stale_banner, stale_tooltip) in [
        (
            "vpnctl_lang=en",
            "Changes are saved and applied automatically to the node.",
            "Applied automatically to the node.",
            "inventory only",
            "Takes effect on next deploy.",
        ),
        (
            "vpnctl_lang=ru",
            "Изменения сохраняются и автоматически применяются на ноде.",
            "Применяется автоматически на ноде.",
            "только инвентарь",
            "Применится при следующем деплое.",
        ),
    ] {
        let html = fetch_html_with_cookie(app.clone(), "/admin/servers/dx/protocols", cookie).await;
        assert!(html.contains("id=\"deploy-button\""));
        assert_eq!(
            html.matches(banner).count(),
            2,
            "both kernel and protocol banners must explain automatic apply: {cookie}"
        );
        for action in [
            "kernels/sing-box/disable",
            "kernels/amneziawg/enable",
            "protocols/vless%2Breality/disable",
            "protocols/tuic-v5/enable",
        ] {
            let form = html
                .split_once(&format!("action=\"/admin/servers/dx/{action}\""))
                .unwrap()
                .1
                .split_once("</form>")
                .unwrap()
                .0;
            assert!(
                form.contains(tooltip),
                "missing automatic apply hint: {action}"
            );
        }
        assert!(!html.contains(stale_banner));
        assert!(!html.contains(stale_tooltip));
    }
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
    assert!(
        html.contains(r#"/admin/servers/nowg/protocols/vless%2Breality/disable"#),
        "enabled protocol must have a disable form (vless+reality URL-encoded)"
    );
    let enabled_row = html
        .split("<li ")
        .find(|row| {
            row.split("</li>")
                .next()
                .unwrap()
                .contains("/admin/servers/nowg/protocols/vless%2Breality/disable")
        })
        .unwrap()
        .split("</li>")
        .next()
        .unwrap();
    assert!(
        enabled_row.contains(r#"icons.svg#check"></use></svg>on</span>"#),
        "enabled protocol must have the check icon and exact on label"
    );
    assert!(
        html.contains(r#"/admin/servers/nowg/protocols/hysteria2/enable"#),
        "compatible-disabled protocol must have an enable form"
    );
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
