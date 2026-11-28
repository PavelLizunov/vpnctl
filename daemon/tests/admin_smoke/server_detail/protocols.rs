use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;
use url::form_urlencoded;

use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
use vpnctld::{AppState, router};

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
    let picker = html
        .split_once(r#"id="enabled-protocols""#)
        .unwrap()
        .1
        .split_once("</section>")
        .unwrap()
        .0;
    let (shown, groups) = picker.split_once("<details").unwrap();
    assert!(shown.contains("Enabled protocols · 1"));
    assert!(shown.contains("vless%2Breality/disable"));
    assert!(!shown.contains("hysteria2/enable"));
    let (available, incompatible) = groups.split_once("<details").unwrap();
    assert!(!available.split_once('>').unwrap().0.contains("open"));
    assert!(available.contains("Available to enable") && available.contains("hysteria2/enable"));
    assert!(!incompatible.split_once('>').unwrap().0.contains("open"));
    assert!(
        incompatible.contains("Require a different kernel") && incompatible.contains("wireguard")
    );
    assert!(!incompatible.contains("<form"));
    for pid in ["shadowsocks-2022", "anytls", "trojan", "amneziawg2"] {
        assert!(!html.contains(&format!("protocols/{pid}/enable")));
    }
    for pid in [
        "vless+reality",
        "tuic-v5",
        "hysteria2",
        "amneziawg3",
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
        enabled_row.contains(r#"icons.svg#check"></use></svg>Enabled</span>"#),
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
async fn configured_protocol_stays_enabled_when_no_selected_kernel_supports_it() {
    let dir = TempDir::new().unwrap();
    let state = state(&dir).await;
    seed(&state.inv, 1, 0, &[]).await;
    let server = ServerId("s0".into());
    let wireguard = ProtocolId("wireguard".into());
    state
        .inv
        .add_server_protocol(&server, &wireguard)
        .await
        .unwrap();
    let html = fetch_html_with_cookie(
        router(state),
        "/admin/servers/s0/protocols",
        "vpnctl_lang=ru",
    )
    .await;
    let enabled = html
        .split_once(r#"id="enabled-protocols""#)
        .unwrap()
        .1
        .split_once("<details")
        .unwrap()
        .0;
    let row = enabled
        .split("<li ")
        .find(|row| row.contains("/wireguard/disable"))
        .unwrap();
    assert!(row.contains("Включён"));
    assert!(row.contains("Выбранные ядра не поддерживают протокол"));
    assert!(!row.contains("/wireguard/hide") && !row.contains("/wireguard/enable"));
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
async fn admin_server_rejects_retired_protocols_and_enables_awg3() {
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

    for protocol in ["shadowsocks-2022", "anytls", "trojan", "amneziawg2"] {
        let response = app.clone().oneshot(post(protocol)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    assert_eq!(count_autodeploy_rows(&inv).await, 0);

    let awg3 = app.clone().oneshot(post("amneziawg3")).await.unwrap();
    assert_eq!(awg3.status(), StatusCode::SEE_OTHER);
    let auto_rows = wait_for_autodeploy_rows(&inv, 1).await;
    assert_eq!(auto_rows.len(), 1);
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
    assert_eq!(
        server.enabled_protocols,
        vec![ProtocolId("amneziawg3".into())]
    );
    let mutation_rows = inv
        .recent_audit(20)
        .await
        .unwrap()
        .into_iter()
        .filter(|row| row.action == "server.protocol.enable")
        .count();
    assert_eq!(mutation_rows, 1);

    let response = app.oneshot(post("amneziawg3")).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        count_autodeploy_rows(&inv).await,
        1,
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
        mutation_rows_after_reposts, 1,
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

#[tokio::test]
async fn enabled_retired_protocol_remains_visible_and_can_be_disabled() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let sid = ServerId("legacy-toggle".into());
    inv.add_server(&Server {
        id: sid.clone(),
        address: "198.51.100.42".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![
            ProtocolId("vless+reality".into()),
            ProtocolId("amneziawg2".into()),
        ],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    let app = router(s);
    let page = "/admin/servers/legacy-toggle/protocols";
    let action = format!("{page}/amneziawg2/disable");
    let html = fetch_html(app.clone(), page).await;
    let row = html
        .split("</li>")
        .find_map(|item| {
            item.rsplit("<li ")
                .next()
                .filter(|row| row.contains(&action))
        })
        .expect("retired AWG2 row must offer Disable");
    assert!(row.contains("(retired)"));
    assert!(row.contains("/amneziawg2/hide"));
    let response = app
        .oneshot(
            add_same_origin(Request::builder().method("POST").uri(action))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        inv.get_server(&sid)
            .await
            .unwrap()
            .unwrap()
            .enabled_protocols,
        vec![ProtocolId("vless+reality".into())]
    );
    assert_eq!(
        inv.recent_audit(10)
            .await
            .unwrap()
            .iter()
            .filter(|row| row.action == "server.protocol.disable")
            .count(),
        1
    );
}

const VMESS_PROTOCOLS_PATH: &str = "/admin/servers/s0/protocols";
const VMESS_CONFIG_PATH: &str = "/admin/servers/s0/vmess-config";
const VMESS_DOMAIN: &str = "fixture.example.com";

#[path = "../../fixtures/tls.rs"]
mod tls;
use tls::{
    TLS_CERTIFICATE_DER as VMESS_CERTIFICATE_DER, TLS_KEY_DER as VMESS_KEY_DER, pem as vmess_pem,
};

const VMESS_UNRELATED_KEY_DER: &str = concat!(
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsETm5/4wW5smP8pe\n",
    "S5fZBNRL5WXNTaR4t5k0HQzTjEOhRANCAASFYo1H4NmxZdsv+PfL7SacfJ2OEL7x\n",
    "mza/c5HrAw0z0OpEFIp5CRsYQUGDWAWIxRZC4+yAbkN9rNTABLBfXyMs\n",
);

async fn vmess_state(dir: &TempDir) -> AppState {
    let mut state = state(dir).await;
    state.registry = Arc::new(vpnctl_kernels::build_registry().unwrap());
    seed(&state.inv, 2, 0, &[]).await;
    state
}

fn protocol_settings_post(path: &str, fields: &[(&str, &str)]) -> Request<Body> {
    let body = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields.iter().copied())
        .finish();
    add_same_origin(
        Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded"),
    )
    .body(Body::from(body))
    .unwrap()
}

fn vmess_config_post(port: &str, certificate: &str, key: &str) -> Request<Body> {
    protocol_settings_post(
        VMESS_CONFIG_PATH,
        &[
            ("domain", VMESS_DOMAIN),
            ("listen_port", port),
            ("detour_via", "s1"),
            ("certificate", certificate),
            ("key", key),
        ],
    )
}

fn assert_vmess_tls_redacted(rendered: &str) {
    for encoded in [VMESS_CERTIFICATE_DER, VMESS_KEY_DER] {
        assert!(
            encoded.lines().all(|line| !rendered.contains(line)),
            "VMess TLS material leaked"
        );
    }
}

#[tokio::test]
async fn vmess_config_persists_settings_and_keeps_tls_material_out_of_ui_and_audit() {
    let dir = TempDir::new().unwrap();
    let state = vmess_state(&dir).await;
    let sid = ServerId("s0".into());
    let app = router(state.clone());
    let certificate = vmess_pem("CERTIFICATE", VMESS_CERTIFICATE_DER);
    let key = vmess_pem("PRIVATE KEY", VMESS_KEY_DER);
    let baseline = state.inv.recent_audit(100).await.unwrap().len();

    let response = app
        .clone()
        .oneshot(vmess_config_post("8443", &certificate, &key))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()[header::LOCATION].to_str().unwrap();
    assert_eq!(location.split('#').next(), Some(VMESS_PROTOCOLS_PATH));

    let settings = state.inv.list_server_secrets(&sid).await.unwrap();
    for (field, expected) in [
        ("vmess.domain", VMESS_DOMAIN),
        ("vmess.listen_port", "8443"),
        ("vmess.preferred_entry", "s1"),
        ("vmess.certificate", certificate.as_str()),
        ("vmess.key", key.as_str()),
    ] {
        assert!(
            settings.get(field).is_some_and(|value| value == expected),
            "{field}"
        );
    }

    let html = fetch_html(app.clone(), VMESS_PROTOCOLS_PATH).await;
    assert!(html.contains(VMESS_CONFIG_PATH));
    assert!(html.contains(VMESS_DOMAIN));
    assert_vmess_tls_redacted(&html);
    let after_save = state.inv.recent_audit(100).await.unwrap().len();
    assert!(after_save > baseline);

    let response = app
        .oneshot(vmess_config_post("9443", "", ""))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let updated = state.inv.list_server_secrets(&sid).await.unwrap();
    assert_eq!(updated["vmess.listen_port"], "9443");
    for field in ["vmess.certificate", "vmess.key"] {
        assert!(
            updated[field] == settings[field],
            "blank input overwrote {field}"
        );
    }

    let audit = state.inv.recent_audit(100).await.unwrap();
    assert!(audit.len() > after_save);
    let new_rows = &audit[..audit.len() - baseline];
    let (update_rows, save_rows) = new_rows.split_at(audit.len() - after_save);
    for rows in [save_rows, update_rows] {
        assert!(rows.iter().any(|row| row.target.as_deref() == Some("s0")));
    }
    for row in new_rows {
        if let Some(payload) = &row.payload {
            assert_vmess_tls_redacted(&payload.to_string());
        }
    }
}

#[tokio::test]
async fn vmess_config_rejects_partial_and_mismatched_tls_pairs_atomically() {
    let dir = TempDir::new().unwrap();
    let state = vmess_state(&dir).await;
    let sid = ServerId("s0".into());
    let app = router(state.clone());
    let certificate = vmess_pem("CERTIFICATE", VMESS_CERTIFICATE_DER);
    let key = vmess_pem("PRIVATE KEY", VMESS_KEY_DER);
    let unrelated_key = vmess_pem("PRIVATE KEY", VMESS_UNRELATED_KEY_DER);
    let response = app
        .clone()
        .oneshot(vmess_config_post("8443", &certificate, &key))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let settings = state.inv.list_server_secrets(&sid).await.unwrap();
    let baseline = state.inv.recent_audit(100).await.unwrap().len();

    for (certificate, key) in [
        (certificate.as_str(), ""),
        ("", key.as_str()),
        (certificate.as_str(), unrelated_key.as_str()),
    ] {
        let response = app
            .clone()
            .oneshot(vmess_config_post("9443", certificate, key))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(state.inv.list_server_secrets(&sid).await.unwrap() == settings);
        assert_eq!(state.inv.recent_audit(100).await.unwrap().len(), baseline);
    }
}

#[tokio::test]
async fn vmess_enable_rejects_a_reserved_port_and_missing_config_without_mutation() {
    let dir = TempDir::new().unwrap();
    let state = vmess_state(&dir).await;
    let app = router(state.clone());
    let certificate = vmess_pem("CERTIFICATE", VMESS_CERTIFICATE_DER);
    let key = vmess_pem("PRIVATE KEY", VMESS_KEY_DER);

    let response = app
        .clone()
        .oneshot(protocol_settings_post(
            "/admin/servers/s0/reserved-ports",
            &[("ports", "8443")],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let response = app
        .clone()
        .oneshot(vmess_config_post("8443", &certificate, &key))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    // Leave the default VMess port free on the node with no VMess settings.
    state
        .inv
        .set_server_secret(&ServerId("s1".into()), "vless.listen_port", "9443")
        .await
        .unwrap();
    let baseline = state.inv.recent_audit(100).await.unwrap().len();
    for id in ["s0", "s1"] {
        let sid = ServerId(id.into());
        let enabled = state
            .inv
            .get_server(&sid)
            .await
            .unwrap()
            .unwrap()
            .enabled_protocols;
        let settings = state.inv.list_server_secrets(&sid).await.unwrap();
        let response = app
            .clone()
            .oneshot(protocol_settings_post(
                &format!("/admin/servers/{id}/protocols/vmess/enable"),
                &[],
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "server {id}");
        if id == "s0" {
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert!(std::str::from_utf8(&body).unwrap().contains("8443"));
        }
        assert_eq!(
            state
                .inv
                .get_server(&sid)
                .await
                .unwrap()
                .unwrap()
                .enabled_protocols,
            enabled
        );
        assert!(state.inv.list_server_secrets(&sid).await.unwrap() == settings);
        assert_eq!(state.inv.recent_audit(100).await.unwrap().len(), baseline);
    }
}

#[tokio::test]
async fn native_sing_box_protocols_enable_with_defaults_and_can_be_disabled() {
    let dir = TempDir::new().unwrap();
    let state = vmess_state(&dir).await;
    let sid = ServerId("s0".into());
    for protocol in ["trusttunnel", "mieru"] {
        let pid = ProtocolId(protocol.into());
        for (action, enabled) in [("enable", true), ("disable", false)] {
            let response = router(state.clone())
                .oneshot(protocol_settings_post(
                    &format!("/admin/servers/s0/protocols/{protocol}/{action}"),
                    &[],
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            assert_eq!(
                state
                    .inv
                    .list_server_protocols(&sid)
                    .await
                    .unwrap()
                    .contains(&pid),
                enabled
            );
        }
    }
    let response = router(state)
        .oneshot(
            Request::builder()
                .uri(VMESS_PROTOCOLS_PATH)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let html = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    for id in ["trusttunnel", "mieru"] {
        assert!(html.contains(&format!("/admin/servers/s0/{id}-config")));
        assert!(html.contains(&format!("/admin/servers/s0/protocols/{id}/enable")));
    }
}

#[tokio::test]
async fn native_sing_box_settings_validate_and_keep_previous_values_on_conflicts() {
    let dir = TempDir::new().unwrap();
    let state = vmess_state(&dir).await;
    let sid = ServerId("s0".into());
    state
        .inv
        .set_reserved_ports(&sid, &[8444, 8445])
        .await
        .unwrap();
    for protocol in ["trusttunnel", "mieru"] {
        let result = router(state.clone())
            .oneshot(protocol_settings_post(
                &format!("/admin/servers/s0/protocols/{protocol}/enable"),
                &[],
            ))
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
    }
    let trust = "/admin/servers/s0/trusttunnel-config";
    let mieru = "/admin/servers/s0/mieru-config";
    for (path, fields) in [
        (trust, &[("listen_port", "8444")][..]),
        (trust, &[("quic", "false"), ("client_quic", "true")]),
        (trust, &[("domain", "incomplete.example.com")]),
        (mieru, &[("listen_port", "65536")]),
        (mieru, &[("transport", "sctp")]),
        (mieru, &[("handshake_mode", "invalid")]),
    ] {
        let response = router(state.clone())
            .oneshot(protocol_settings_post(path, fields))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{path} {fields:?}"
        );
    }
    for (path, fields) in [
        (
            trust,
            &[
                ("listen_port", "9444"),
                ("quic", "false"),
                ("udp", "false"),
                ("sni", "node.example.com"),
            ][..],
        ),
        (
            mieru,
            &[
                ("listen_port", "9444"),
                ("transport", "udp"),
                ("multiplexing", "high"),
                ("handshake_mode", "no_wait"),
            ],
        ),
    ] {
        let response = router(state.clone())
            .oneshot(protocol_settings_post(path, fields))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }
    for protocol in ["trusttunnel", "mieru"] {
        let response = router(state.clone())
            .oneshot(protocol_settings_post(
                &format!("/admin/servers/s0/protocols/{protocol}/enable"),
                &[],
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }
    let saved = state.inv.list_server_secrets(&sid).await.unwrap();
    for (key, value) in [
        ("trusttunnel.listen_port", "9444"),
        ("trusttunnel.quic", "false"),
        ("trusttunnel.udp", "false"),
        ("trusttunnel.sni", "node.example.com"),
        ("mieru.listen_port", "9444"),
        ("mieru.transport", "udp"),
        ("mieru.multiplexing", "high"),
        ("mieru.handshake_mode", "no_wait"),
    ] {
        assert_eq!(saved[key], value);
    }
    // Turning on TrustTunnel H3 would collide with Mieru on UDP/9444.
    let response = router(state.clone())
        .oneshot(protocol_settings_post(
            trust,
            &[("listen_port", "9444"), ("quic", "true")],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(state.inv.list_server_secrets(&sid).await.unwrap(), saved);
}

#[tokio::test]
async fn trusttunnel_custom_tls_can_be_saved_rotated_and_cleared_without_displaying_pem() {
    let dir = TempDir::new().unwrap();
    let state = vmess_state(&dir).await;
    let sid = ServerId("s0".into());
    let path = "/admin/servers/s0/trusttunnel-config";
    let certificate = vmess_pem("CERTIFICATE", VMESS_CERTIFICATE_DER);
    let key = vmess_pem("PRIVATE KEY", VMESS_KEY_DER);
    let bad_key = vmess_pem("PRIVATE KEY", VMESS_UNRELATED_KEY_DER);
    for (field, status) in [
        (&bad_key, StatusCode::BAD_REQUEST),
        (&key, StatusCode::SEE_OTHER),
    ] {
        let response = router(state.clone())
            .oneshot(protocol_settings_post(
                path,
                &[
                    ("domain", VMESS_DOMAIN),
                    ("certificate", &certificate),
                    ("key", field),
                ],
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), status);
    }
    let response = router(state.clone())
        .oneshot(protocol_settings_post(
            path,
            &[("domain", VMESS_DOMAIN), ("listen_port", "9444")],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let saved = state.inv.list_server_secrets(&sid).await.unwrap();
    assert_eq!(saved["trusttunnel.key"], key);
    assert_eq!(saved["trusttunnel.certificate"], certificate);

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .uri(VMESS_PROTOCOLS_PATH)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let html = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert_vmess_tls_redacted(&html);
    let response = router(state.clone())
        .oneshot(protocol_settings_post(path, &[("domain", "")]))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cleared = state.inv.list_server_secrets(&sid).await.unwrap();
    for key in [
        "trusttunnel.domain",
        "trusttunnel.certificate",
        "trusttunnel.key",
    ] {
        assert!(!cleared.contains_key(key));
    }
}
