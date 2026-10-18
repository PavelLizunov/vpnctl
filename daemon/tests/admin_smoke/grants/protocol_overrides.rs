use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctld::router;

use crate::common::{add_same_origin, fetch_html, state};

#[tokio::test]
async fn nm10_server_detail_visible_protocol_shows_hide_button() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("hidesrv".into()),
            address: "203.0.113.10".into(),
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
    let html = fetch_html(router(s), "/admin/servers/hidesrv/protocols").await;
    let row = html
        .split("<li ")
        .find(|row| {
            row.split("</li>")
                .next()
                .unwrap()
                .contains("/admin/servers/hidesrv/protocols/vless%2Breality/hide")
        })
        .unwrap()
        .split("</li>")
        .next()
        .unwrap();
    assert!(
        row.contains(r#"icons.svg#check"></use></svg>on</span>"#) && !row.contains("on · hidden"),
        "visible enabled protocol should show the check icon and plain on label"
    );
    assert!(
        html.contains(r#"/admin/servers/hidesrv/protocols/vless%2Breality/hide"#),
        "visible protocol must offer a hide button (POST /hide)"
    );
    assert!(
        !html.contains(r#"/admin/servers/hidesrv/protocols/vless%2Breality/unhide"#),
        "visible protocol must NOT offer an unhide button"
    );
}

#[tokio::test]
async fn nm10_server_detail_hidden_protocol_shows_unhide_button() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("hidesrv".into()),
            address: "203.0.113.10".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("tuic-v5".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .set_server_protocol_hidden(
            &ServerId("hidesrv".into()),
            &ProtocolId("tuic-v5".into()),
            true,
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/hidesrv/protocols").await;
    let row = html
        .split("<li ")
        .find(|row| {
            row.split("</li>")
                .next()
                .unwrap()
                .contains("/admin/servers/hidesrv/protocols/tuic-v5/unhide")
        })
        .unwrap()
        .split("</li>")
        .next()
        .unwrap();
    assert!(
        row.contains(r#"icons.svg#check"></use></svg>on · hidden</span>"#),
        "hidden protocol must surface the check icon and exact on · hidden label"
    );
    assert!(
        html.contains(r#"/admin/servers/hidesrv/protocols/tuic-v5/unhide"#),
        "hidden protocol must offer an unhide button (POST /unhide)"
    );
    assert!(
        !html.contains(r#"/admin/servers/hidesrv/protocols/tuic-v5/hide""#),
        "hidden protocol must NOT offer a redundant hide button"
    );
}

#[tokio::test]
async fn nm10_server_detail_post_hide_persists_and_redirects() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_server(&Server {
            id: ServerId("hsrv".into()),
            address: "203.0.113.11".into(),
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
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/hsrv/protocols/vless%2Breality/hide"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        location, "/admin/servers/hsrv/protocols#enabled-protocols",
        "303 must redirect back to /admin/servers/{{id}}#enabled-protocols so the browser scrolls the operator back to the section they just clicked in (Pavel 2026-05-20: «каждый раз когда я жму disable меня выкидывает в верх страницы»)"
    );
    assert!(
        inv.is_server_protocol_hidden(
            &ServerId("hsrv".into()),
            &ProtocolId("vless+reality".into())
        )
        .await
        .unwrap(),
        "hidden flag must persist after POST /hide"
    );
    let audit = inv.recent_audit(5).await.unwrap();
    assert!(
        audit
            .iter()
            .any(|a| a.action == "server.protocol.set_hidden"),
        "POST /hide must write an audit row"
    );
}

#[tokio::test]
async fn nm10_user_detail_per_protocol_grid_renders_for_granted_server() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("alice".into()),
            uuid: "00000000-0000-0000-0000-000000000001".to_string(),
            sub_token: Some("t1".into()),
            wireguard_pubkey: None,
            wireguard_private: None,
            tuic_password: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("gridsrv".into()),
            address: "203.0.113.12".into(),
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
    s.inv
        .grant(&UserId("alice".into()), &ServerId("gridsrv".into()))
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/alice/access").await;
    assert!(
        html.contains("Per-protocol delivery"),
        "grid heading must appear under the granted server's row"
    );
    for protocol in ["vless%2Breality", "tuic-v5"] {
        let action = format!("/admin/users/alice/grants/gridsrv/protocols/{protocol}/disable");
        let row = html
            .rsplit("<li ")
            .find(|row| row.split("</li>").next().unwrap().contains(&action))
            .unwrap()
            .split("</li>")
            .next()
            .unwrap();
        assert!(
            row.contains(r#"icons.svg#check"></use></svg>delivered</span>"#),
            "{protocol}: default delivery state must have the check icon and delivered label"
        );
    }
    assert!(
        html.contains(r#"/admin/users/alice/grants/gridsrv/protocols/vless%2Breality/disable"#),
        "vless+reality must have a disable (block) form"
    );
    assert!(
        html.contains(r#"/admin/users/alice/grants/gridsrv/protocols/tuic-v5/disable"#),
        "tuic-v5 must have a disable (block) form"
    );
}

#[tokio::test]
async fn nm10_user_detail_grid_hides_when_server_not_granted() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("bob".into()),
            uuid: "00000000-0000-0000-0000-000000000002".to_string(),
            sub_token: Some("t2".into()),
            wireguard_pubkey: None,
            wireguard_private: None,
            tuic_password: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("notgranted".into()),
            address: "203.0.113.13".into(),
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
    let html = fetch_html(router(s), "/admin/users/bob/access").await;
    assert!(
        !html.contains(r#"/admin/users/bob/grants/notgranted/protocols/vless%2Breality/disable"#),
        "ungranted server must NOT expose the per-protocol disable form"
    );
}

#[tokio::test]
async fn nm10_user_detail_grid_marks_server_hidden_readonly() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("carol".into()),
            uuid: "00000000-0000-0000-0000-000000000003".to_string(),
            sub_token: Some("t3".into()),
            wireguard_pubkey: None,
            wireguard_private: None,
            tuic_password: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("hidsrv".into()),
            address: "203.0.113.14".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("tuic-v5".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .grant(&UserId("carol".into()), &ServerId("hidsrv".into()))
        .await
        .unwrap();
    s.inv
        .set_server_protocol_hidden(
            &ServerId("hidsrv".into()),
            &ProtocolId("tuic-v5".into()),
            true,
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/carol/access").await;
    assert!(
        html.contains("server-hidden (read-only here)"),
        "server-hidden protocol must surface read-only marker in the grid"
    );
    assert!(
        !html.contains(r#"/admin/users/carol/grants/hidsrv/protocols/tuic-v5/disable"#),
        "server-hidden + no override should suppress the block button (would be a redundant override)"
    );
}

#[tokio::test]
async fn nm10_user_detail_grid_shows_user_blocked_marker_and_unblock_form() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("dave".into()),
            uuid: "00000000-0000-0000-0000-000000000004".to_string(),
            sub_token: Some("t4".into()),
            wireguard_pubkey: None,
            wireguard_private: None,
            tuic_password: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("dsrv".into()),
            address: "203.0.113.15".into(),
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
    s.inv
        .grant(&UserId("dave".into()), &ServerId("dsrv".into()))
        .await
        .unwrap();
    s.inv
        .set_grant_protocol_override(
            &UserId("dave".into()),
            &ServerId("dsrv".into()),
            &ProtocolId("vless+reality".into()),
            true,
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/dave/access").await;
    let row = html
        .rsplit("<li ")
        .find(|row| {
            row.split("</li>")
                .next()
                .unwrap()
                .contains("/admin/users/dave/grants/dsrv/protocols/vless%2Breality/enable")
        })
        .unwrap()
        .split("</li>")
        .next()
        .unwrap();
    assert!(
        row.contains(r#"icons.svg#x"></use></svg>user-blocked</span>"#),
        "user-blocked override must surface the x icon and exact user-blocked label"
    );
    assert!(
        html.contains(r#"/admin/users/dave/grants/dsrv/protocols/vless%2Breality/enable"#),
        "user-blocked protocol must offer an unblock (enable) button"
    );
    assert!(
        !html.contains(r#"/admin/users/dave/grants/dsrv/protocols/vless%2Breality/disable"#),
        "user-blocked protocol must NOT redundantly offer a block button"
    );
}

#[tokio::test]
async fn nm10_user_detail_post_block_persists_and_redirects() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_user(&User {
            id: UserId("erin".into()),
            uuid: "00000000-0000-0000-0000-000000000005".to_string(),
            sub_token: Some("t5".into()),
            wireguard_pubkey: None,
            wireguard_private: None,
            tuic_password: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("esrv".into()),
            address: "203.0.113.16".into(),
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
    s.inv
        .grant(&UserId("erin".into()), &ServerId("esrv".into()))
        .await
        .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/erin/grants/esrv/protocols/vless%2Breality/disable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        location, "/admin/users/erin/access#server-access",
        "303 must redirect back to /admin/users/{{uid}}#server-access so the browser scrolls the operator back to the per-protocol grid they just clicked in"
    );
    let overrides = inv
        .list_protocol_overrides_for_user(&UserId("erin".into()))
        .await
        .unwrap();
    assert!(
        overrides
            .get(&(ServerId("esrv".into()), ProtocolId("vless+reality".into())))
            .copied()
            .unwrap_or(false),
        "POST /disable must insert a disabled override"
    );
    let audit = inv.recent_audit(5).await.unwrap();
    assert!(
        audit
            .iter()
            .any(|a| a.action == "grant.protocol.set_override"),
        "POST /disable must write a grant.protocol.set_override audit row, got: {:?}",
        audit.iter().map(|a| &a.action).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn nm10_user_detail_grid_renders_both_axes_branch() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("frank".into()),
            uuid: "00000000-0000-0000-0000-000000000006".to_string(),
            sub_token: Some("t6".into()),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("fsrv".into()),
            address: "203.0.113.17".into(),
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
    s.inv
        .grant(&UserId("frank".into()), &ServerId("fsrv".into()))
        .await
        .unwrap();
    s.inv
        .set_server_protocol_hidden(
            &ServerId("fsrv".into()),
            &ProtocolId("vless+reality".into()),
            true,
        )
        .await
        .unwrap();
    s.inv
        .set_grant_protocol_override(
            &UserId("frank".into()),
            &ServerId("fsrv".into()),
            &ProtocolId("vless+reality".into()),
            true,
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/frank/access").await;
    assert!(
        html.contains("server-hidden + user-blocked"),
        "both-axes-deny branch must render the compound label"
    );
    assert!(
        html.contains(r#"/admin/users/frank/grants/fsrv/protocols/vless%2Breality/enable"#),
        "both-axes branch must STILL offer the unblock-user form (operator clears the user-axis here; server-axis on server detail)"
    );
}

#[tokio::test]
async fn nm10_user_detail_grid_iterates_table_not_in_memory_enabled_protocols() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("gina".into()),
            uuid: "00000000-0000-0000-0000-000000000007".to_string(),
            sub_token: Some("t7".into()),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("gsrv".into()),
            address: "203.0.113.18".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![
                ProtocolId("tuic-v5".into()),
                ProtocolId("vless+reality".into()),
            ],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .grant(&UserId("gina".into()), &ServerId("gsrv".into()))
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/gina/access").await;
    let tuic_pos = html.find("tuic-v5").expect("tuic row present");
    let vless_pos = html.find("vless+reality").expect("vless row present");
    assert!(
        tuic_pos < vless_pos,
        "grid rows must be alphabetically sorted by protocol_id to match visible_protocols_for_subscription ORDER BY"
    );
}

#[tokio::test]
async fn nm12_server_detail_renders_dpi_strong_chip_for_vless_reality() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("strongsrv".into()),
            address: "203.0.113.20".into(),
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
    let html = fetch_html(router(s), "/admin/servers/strongsrv/protocols").await;
    assert!(
        html.contains("DPI: strong"),
        "vless+reality row must surface its Strong DPI-risk chip"
    );
    assert!(
        html.contains("Active-probe-resistant"),
        "Strong tier tooltip must explain the active-probe defence"
    );
}

#[tokio::test]
async fn nm12_server_detail_renders_dpi_weak_chip_and_smaller_font_for_wireguard() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("weaksrv".into()),
            address: "203.0.113.21".into(),
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
    let html = fetch_html(router(s), "/admin/servers/weaksrv/protocols").await;
    assert!(
        html.contains("DPI: weak"),
        "wireguard row must surface its Weak DPI-risk chip"
    );
    assert!(
        html.contains("font-size: 11px"),
        "Weak protocol row must shrink the name to 11px (Pavel: «шрифт меньше у них»)"
    );
    assert!(
        html.contains("0x01 handshake tag") || html.contains("WireGuard"),
        "Weak tier tooltip must explain the trivial fingerprint (raw-WG 0x01 tag)"
    );
}

#[tokio::test]
async fn nm12_server_detail_renders_dpi_chip_for_every_known_protocol() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("allsrv".into()),
            address: "203.0.113.22".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("amneziawg".into()), KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/allsrv/protocols").await;
    let strong_count = html.matches("DPI: strong").count();
    let moderate_count = html.matches("DPI: moderate").count();
    let weak_count = html.matches("DPI: weak").count();
    assert_eq!(
        strong_count, 4,
        "expected 4 Strong chips (vless+reality, naive, vless-ws, vless+xhttp), got {strong_count}"
    );
    assert_eq!(
        moderate_count, 4,
        "expected 4 Moderate chips (tuic-v5, anytls, amneziawg2, amneziawg3), got {moderate_count}"
    );
    assert_eq!(
        weak_count, 4,
        "expected 4 Weak chips (shadowsocks-2022, wireguard, trojan, hysteria2), got {weak_count}"
    );
}

#[tokio::test]
async fn nm12_server_detail_renders_dpi_moderate_chip_for_tuic_v5() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("modsrv".into()),
            address: "203.0.113.24".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("tuic-v5".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/modsrv/protocols").await;
    assert!(
        html.contains("DPI: moderate"),
        "tuic-v5 row must surface its Moderate DPI-risk chip"
    );
    assert!(
        html.contains("Recognisable on careful active probing"),
        "Moderate tier tooltip must explain the careful-probe boundary"
    );
}

#[tokio::test]
async fn nm12_server_detail_hidden_weak_protocol_still_shows_chip() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("hwsrv".into()),
            address: "203.0.113.25".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("shadowsocks-2022".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .set_server_protocol_hidden(
            &ServerId("hwsrv".into()),
            &ProtocolId("shadowsocks-2022".into()),
            true,
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/hwsrv/protocols").await;
    assert!(
        html.contains("DPI: weak"),
        "hidden Weak protocol must STILL show the chip — chip is about the wire format, not visibility"
    );
    let row = html
        .split("<li ")
        .find(|row| {
            row.split("</li>")
                .next()
                .unwrap()
                .contains("/admin/servers/hwsrv/protocols/shadowsocks-2022/unhide")
        })
        .unwrap()
        .split("</li>")
        .next()
        .unwrap();
    assert!(
        row.contains("DPI: weak"),
        "weak DPI chip must belong to the hidden protocol row"
    );
    assert!(
        row.contains(r#"icons.svg#check"></use></svg>on · hidden</span>"#),
        "hidden status check icon and exact label must appear alongside the chip"
    );
}

#[tokio::test]
async fn nm12_unknown_protocol_in_server_renders_no_chip_defensively() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("unksrv".into()),
            address: "203.0.113.26".into(),
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
    let html = fetch_html(router(s), "/admin/servers/unksrv/protocols").await;
    let total_chips = html.matches("DPI: strong").count()
        + html.matches("DPI: moderate").count()
        + html.matches("DPI: weak").count();
    assert_eq!(
        total_chips, 12,
        "12 registered protocols must each carry exactly one chip on a server with all kernels — got {total_chips}"
    );
}

#[tokio::test]
async fn nm12_user_detail_grid_renders_dpi_chip_and_weak_shrinks_to_10px() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("hank".into()),
            uuid: "00000000-0000-0000-0000-000000000008".to_string(),
            sub_token: Some("t8".into()),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("hsrv".into()),
            address: "203.0.113.23".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("amneziawg".into()), KernelId("sing-box".into())],
            enabled_protocols: vec![
                ProtocolId("vless+reality".into()),
                ProtocolId("wireguard".into()),
                ProtocolId("shadowsocks-2022".into()),
            ],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .grant(&UserId("hank".into()), &ServerId("hsrv".into()))
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/hank/access").await;
    assert!(
        html.contains("DPI: strong") && html.contains("DPI: weak"),
        "grid must render risk chips matching the protocol tiers"
    );
    assert!(
        html.contains("font-size: 10px"),
        "Weak protocol row in user-detail grid must shrink to 10px"
    );
}

#[tokio::test]
async fn nm12_followup_server_detail_section_carries_enabled_protocols_anchor() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("anchsrv".into()),
            address: "203.0.113.27".into(),
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
    let html = fetch_html(router(s), "/admin/servers/anchsrv/protocols").await;
    assert!(
        html.contains(r#"id="enabled-protocols""#),
        "server-detail must carry an id=\"enabled-protocols\" anchor for the visibility-toggle handlers to scroll back into"
    );
}

#[tokio::test]
async fn nm12_followup_user_detail_section_carries_server_access_anchor() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("ivy".into()),
            uuid: "00000000-0000-0000-0000-000000000009".to_string(),
            sub_token: Some("t9".into()),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/ivy/access").await;
    assert!(
        html.contains(r#"id="server-access""#),
        "user-detail must carry an id=\"server-access\" anchor for the grant-toggle handlers to scroll back into"
    );
}

#[tokio::test]
async fn nm12_followup_server_protocol_unhide_redirects_with_fragment() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_server(&Server {
            id: ServerId("uhsrv".into()),
            address: "203.0.113.28".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("tuic-v5".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    inv.set_server_protocol_hidden(
        &ServerId("uhsrv".into()),
        &ProtocolId("tuic-v5".into()),
        true,
    )
    .await
    .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/uhsrv/protocols/tuic-v5/unhide"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(loc, "/admin/servers/uhsrv/protocols#enabled-protocols");
}

#[tokio::test]
async fn nm12_followup_grant_protocol_enable_redirects_with_fragment() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_user(&User {
            id: UserId("ji".into()),
            uuid: "00000000-0000-0000-0000-000000000010".to_string(),
            sub_token: Some("t10".into()),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("jsrv".into()),
            address: "203.0.113.29".into(),
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
    inv.grant(&UserId("ji".into()), &ServerId("jsrv".into()))
        .await
        .unwrap();
    inv.set_grant_protocol_override(
        &UserId("ji".into()),
        &ServerId("jsrv".into()),
        &ProtocolId("vless+reality".into()),
        true,
    )
    .await
    .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/ji/grants/jsrv/protocols/vless%2Breality/enable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(loc, "/admin/users/ji/access#server-access");
}

#[tokio::test]
async fn nm12_followup_legacy_server_disable_protocol_also_carries_fragment() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("lsrv".into()),
            address: "203.0.113.30".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("tuic-v5".into())],
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
                    .uri("/admin/servers/lsrv/protocols/tuic-v5/disable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(loc, "/admin/servers/lsrv/protocols#enabled-protocols");
}

#[tokio::test]
async fn nm12_followup_servers_list_reflects_hidden_state() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("lpsrv".into()),
            address: "203.0.113.40".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![
                ProtocolId("vless+reality".into()),
                ProtocolId("tuic-v5".into()),
                ProtocolId("anytls".into()),
            ],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .set_server_protocol_hidden(
            &ServerId("lpsrv".into()),
            &ProtocolId("tuic-v5".into()),
            true,
        )
        .await
        .unwrap();
    s.inv
        .set_server_protocol_hidden(
            &ServerId("lpsrv".into()),
            &ProtocolId("anytls".into()),
            true,
        )
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/servers").await;

    let visible_seg = html
        .split(r#"<span class="ed-grid__flag""#)
        .next()
        .expect("page renders");
    assert!(
        visible_seg.contains("vless+reality"),
        "visible protocol list must show vless+reality"
    );
    assert!(
        !visible_seg.contains("tuic-v5") && !visible_seg.contains("anytls"),
        "hidden protocols must NOT appear in the visible list (only in the flag title)"
    );
    assert!(
        html.contains(r#"class="ed-grid__flag""#),
        "a +N hidden flag must render for the server with hidden protocols"
    );
    assert!(
        html.contains("tuic-v5") && html.contains("anytls"),
        "hidden protocols must be surfaced (in the flag title)"
    );
    assert!(html.contains("+2"), "flag must show the hidden count (+2)");
}

#[tokio::test]
async fn nm12_followup_servers_list_no_hidden_row_when_all_visible() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("vsrv".into()),
            address: "203.0.113.41".into(),
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
    let html = fetch_html(router(s), "/admin/servers").await;
    assert!(
        !html.contains(r#"<dt style="color: var(--acc);">hidden</dt>"#),
        "no protocols are hidden — the hidden dt row must NOT render"
    );
}

#[tokio::test]
async fn nm12_followup_legacy_server_enable_protocol_also_carries_fragment() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("esrv2".into()),
            address: "203.0.113.31".into(),
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
                    .uri("/admin/servers/esrv2/protocols/anytls/enable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(loc, "/admin/servers/esrv2/protocols#enabled-protocols");
}
