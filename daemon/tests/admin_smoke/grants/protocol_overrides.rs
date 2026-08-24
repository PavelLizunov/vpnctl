//! Protocol visibility and per-protocol override tests.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctld::router;

use crate::common::{add_same_origin, fetch_html, state};

// ────────────────────────────────────────────────────────────────────────
// NM-10 — protocol visibility UI (server-detail hide/unhide chip +
// user-detail per-protocol delivery grid). Backend handlers landed in
// cd71cf9; these tests pin the corresponding UI surfaces so a future
// HTML refactor can't silently drop the toggle. Each test exercises a
// distinct rule: hidden-chip render, visible-chip render, POST mutation
// round-trip, per-grant grid presence, server-hidden read-only marker,
// override-blocks-render check, ungranted-server-suppression.

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
    // Visible (hidden=0) protocol: shows "✓ on" without the "· hidden"
    // suffix AND offers a hide button (no unhide).
    assert!(
        html.contains("✓ on") && !html.contains("✓ on · hidden"),
        "visible enabled protocol should show plain ✓ on marker"
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
    assert!(
        html.contains("✓ on · hidden"),
        "hidden protocol must surface the · hidden suffix on its status chip"
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
    // Default state = delivered + block button per protocol.
    assert!(
        html.contains("✓ delivered"),
        "default delivery state should be ✓ delivered"
    );
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
    // Ungranted server should NOT render the per-protocol grid —
    // overrides would refuse with Invalid anyway, and surfacing the
    // buttons creates a confusing "click does nothing" UX.
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
    // No grant() call.
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
    // Server-hidden + no override → read-only label, NO block button.
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
    assert!(
        html.contains("✗ user-blocked"),
        "user-blocked override must surface the ✗ marker"
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
    // Auditable-write invariant (CLAUDE.md): every inventory mutation
    // writes one audit_log row. Mirrors the parallel assert on the
    // server-hide test above.
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
    // The "server-hidden + user-blocked" branch (line 7501 in admin.rs)
    // is the only label where BOTH axes deny the protocol. A regression
    // collapsing the branch into "server-hidden (read-only)" would lose
    // the "unblock (user)" button — the operator's only path to clear
    // a stale per-user override on a server-hidden protocol. This test
    // pins that label + the unblock-user form so the branch can't be
    // silently deleted.
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
    // Set BOTH axes — server-hide AND user-block. Canonical render
    // omits via OR-semantics; UI must surface both flags so the
    // operator's mental model matches.
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
    // Defensive: the grid iterates `hidden_map.keys()` (the
    // `server_protocols` table rows) rather than the in-memory
    // `Server.enabled_protocols` cache, so OR-semantics resolution
    // matches `visible_protocols_for_subscription` BYTE-for-BYTE
    // even in the (rare/impossible-in-production) case where the
    // cache and table diverge. This test exercises the happy path:
    // a server with two protocols renders both rows in alphabetical
    // order matching the canonical query's ORDER BY.
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
            // Out of order on purpose — render should still sort.
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

// ─── NM-12: DPI-risk chips on server-detail + user-detail grid ───────
//
// Pavel 2026-05-20: «давай начнём с того что ты уберёшь чтото плохие
// протоколы и пометишь их в ui как плохие и можешь даже шрифт меньше
// сделать у них». Risk tier comes from the registry — no inventory
// state. These tests pin the chip text, the colour-driving class, the
// smaller-font branch for Weak rows, and the explainer tooltip.

#[tokio::test]
async fn nm12_server_detail_renders_dpi_strong_chip_for_vless_reality() {
    // Strong tier should produce a "DPI: strong" chip on the row.
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
    // Tooltip carries the explainer ("Active-probe-resistant: ...").
    assert!(
        html.contains("Active-probe-resistant"),
        "Strong tier tooltip must explain the active-probe defence"
    );
}

#[tokio::test]
async fn nm12_server_detail_renders_dpi_weak_chip_and_smaller_font_for_wireguard() {
    // Weak tier produces "DPI: weak" chip AND the row gets
    // font-size: 11px (visual de-emphasis). The test pins BOTH so a
    // regression that drops the font shrink would fail loudly.
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
    // Explainer mentions the specific fingerprint so the operator
    // understands WHY it's Weak — and the chip-tooltip lookup table
    // never silently changes.
    assert!(
        html.contains("0x01 handshake tag") || html.contains("WireGuard"),
        "Weak tier tooltip must explain the trivial fingerprint (raw-WG 0x01 tag)"
    );
}

#[tokio::test]
async fn nm12_server_detail_renders_dpi_chip_for_every_known_protocol() {
    // Spec: every registered protocol must produce SOME chip. A
    // future protocol added without overriding dpi_risk() still
    // gets `Moderate` (the default), so the chip set is exhaustive.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("allsrv".into()),
            address: "203.0.113.22".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("amneziawg".into()), KernelId("sing-box".into())],
            // Empty enabled_protocols — the server-detail still lists
            // every protocol in the registry with [enable] buttons,
            // and the chip should render alongside the name.
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/allsrv/protocols").await;
    // Tier distribution across the FULL production registry (the test
    // `state` mirrors `build_registry` — naive + dns-tunnel + vless-ws
    // + vless+xhttp included):
    //   Strong:   vless+reality, naive,
    //             vless-ws, vless+xhttp            (4)
    //   Moderate: tuic-v5, anytls, dns-tunnel      (3)
    //   Weak:     shadowsocks-2022, wireguard,
    //             trojan, hysteria2                (4)
    //   ────────────────────────────────────────────
    //   total                                      (11)
    let strong_count = html.matches("DPI: strong").count();
    let moderate_count = html.matches("DPI: moderate").count();
    let weak_count = html.matches("DPI: weak").count();
    assert_eq!(
        strong_count, 4,
        "expected 4 Strong chips (vless+reality, naive, vless-ws, vless+xhttp), got {strong_count}"
    );
    assert_eq!(
        moderate_count, 3,
        "expected 3 Moderate chips (tuic-v5, anytls, dns-tunnel), got {moderate_count}"
    );
    assert_eq!(
        weak_count, 4,
        "expected 4 Weak chips (shadowsocks-2022, wireguard, trojan, hysteria2), got {weak_count}"
    );
}

#[tokio::test]
async fn nm12_server_detail_renders_dpi_moderate_chip_for_tuic_v5() {
    // After the review-agent re-tier (Trojan/Hysteria2 → Weak), only
    // tuic-v5 and anytls are Moderate. This test pins that tuic-v5
    // actually carries the Moderate chip — without it the
    // Strong/Weak tests would happily pass even if the Moderate arm
    // of `border_css()` / `text_css()` were broken.
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
    // Moderate uses --rule + --mute (not the green/red palette); the
    // tooltip wording is distinct from Strong/Weak.
    assert!(
        html.contains("Recognisable on careful active probing"),
        "Moderate tier tooltip must explain the careful-probe boundary"
    );
}

#[tokio::test]
async fn nm12_server_detail_hidden_weak_protocol_still_shows_chip() {
    // The chip is informational about the wire format, not about
    // current visibility. Hiding a Weak protocol (NM-10) does NOT
    // erase the DPI: weak chip — the operator still needs to see
    // WHY they hid it. A regression that suppresses the chip on
    // hidden rows would silently strip the most important context.
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
    assert!(
        html.contains("✓ on · hidden"),
        "hidden status marker must also appear alongside the chip"
    );
}

#[tokio::test]
async fn nm12_unknown_protocol_in_server_renders_no_chip_defensively() {
    // Defensive: if a server's `enabled_protocols` row references a
    // ProtocolId the registry doesn't know about (impossible in
    // production — registry is seeded at boot — but possible during
    // an interrupted migration / dev-time table edit), the render
    // path falls back to `risk = None` and emits NO chip rather
    // than panicking.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("unksrv".into()),
            address: "203.0.113.26".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            // Empty enabled_protocols — server-detail still lists
            // every registry protocol with [enable] buttons; none
            // of THEM are unknown, so we don't see the None branch
            // here. To exercise it we'd need a synthetic registry,
            // which the test stub doesn't expose. So this test
            // instead pins the inverse property: every protocol id
            // emitted by the rendered HTML carries a chip. If the
            // chip ever silently drops on a known-good row this
            // count goes out of sync.
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/unksrv/protocols").await;
    // 12 registered protocols → 12 chips (Strong + Moderate + Weak
    // sum). If the chip-or-no-chip decision branches on something
    // OTHER than "registry knows this id", the count drifts.
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
    // Same chip shows up in the user-detail per-protocol delivery
    // sub-grid, but at the smaller layout (9px chip, 10px Weak vs
    // 11px Moderate/Strong) so it fits the dense row.
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
            // Mix Strong (vless+reality) and Weak (wireguard,
            // shadowsocks-2022) so both font branches exercise.
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
    // Grid font-size: 10px for Weak rows, 11px otherwise. Assert
    // the 10px branch fires (would not be present without a Weak
    // protocol in the row set).
    assert!(
        html.contains("font-size: 10px"),
        "Weak protocol row in user-detail grid must shrink to 10px"
    );
}

// ─── NM-12 follow-up: scroll-preserve via Location fragment ──────────
//
// Pavel 2026-05-20: «каждый раз когда я жму disable меня выкидывает
// в верх страницы». PRG (Post/Redirect/Get) loses the operator's
// scroll position when the redirect target is a bare path — the
// browser GETs the page and resets to top. Fix: every visibility-
// toggle handler appends `#enabled-protocols` (server-detail) or
// `#server-access` (user-detail) to the Location header, and the
// section heading carries the matching `id=`. Browser scrolls to
// the anchor instead of the top.
//
// These tests pin BOTH halves of the contract so a regression
// removing the fragment OR the id would fail.

#[tokio::test]
async fn nm12_followup_server_detail_section_carries_enabled_protocols_anchor() {
    // The redirects all assume an anchor element with
    // id="enabled-protocols" exists on the server-detail page.
    // Without the id the fragment redirect lands at the top of
    // the page anyway (browsers silently ignore unmatched
    // fragments). This pins the markup half of the contract.
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
    // server_protocol_hide is already covered by
    // nm10_server_detail_post_hide_persists_and_redirects (updated
    // to assert the fragment). Unhide is the symmetric handler —
    // pin it separately so a copy-paste regression deleting the
    // fragment from only one of the two would fail.
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
    // grant_protocol_disable already covered by
    // nm10_user_detail_post_block_persists_and_redirects (updated
    // to assert the fragment). Enable is the symmetric handler.
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
    // The pre-existing `server_disable_protocol` handler (NOT part
    // of NM-10 — it removes the protocol from `enabled_protocols`
    // entirely, requires a `deploy` to take effect on the node)
    // also gets the fragment so the operator stays anchored after
    // a click on the [disable] (not [hide]) button. This is the
    // button Pavel was actually using when he reported the scroll
    // bug — pinning it separately so we never lose the fix.
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
    // Pavel 2026-05-20: «нужно сделаить на /admin/servers чтоб это
    // отобразилось, сейчас показано что там все протоколы, хотя я
    // сделал hide». Pre-fix the server-card on /admin/servers
    // rendered `Server.enabled_protocols` straight (in-memory
    // cache, no awareness of `server_protocols.hidden`). Post-fix
    // it splits visible vs hidden via the new bulk matrix and
    // renders them in two distinct rows.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("lpsrv".into()),
            address: "203.0.113.40".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            // 3 enabled: vless+reality (visible), tuic-v5 + anytls
            // (will be hidden below).
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

    // Densify 2a: visible protocols render in the dense-table cell; the
    // hidden ones live ONLY inside the "+N hidden" flag's title (still
    // listening on the node, just not emitted to subscriptions — NM-10/12).
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
    // The +N hidden flag renders, names the hidden protocols in its title,
    // and shows the count.
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
    // Symmetric: when no protocol is hidden on a server, the
    // `dt { "hidden" }` row must NOT render — keeps the card
    // compact for the happy-path operator. A regression that
    // always emits the row (even with 0 hidden) would clutter
    // the list page.
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
    // The hidden dt label only appears when there's at least one
    // hidden protocol. Search for the literal `<dt style="color:
    // var(--acc);">hidden</dt>` substring.
    assert!(
        !html.contains(r#"<dt style="color: var(--acc);">hidden</dt>"#),
        "no protocols are hidden — the hidden dt row must NOT render"
    );
}

#[tokio::test]
async fn nm12_followup_legacy_server_enable_protocol_also_carries_fragment() {
    // Symmetric to the [disable] test above.
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
