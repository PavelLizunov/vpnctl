//! Protocol-specific delivery, multi-protocol ordering, UA gating, and pairing tests
//! for vpn_router_endpoint.

use std::sync::Arc;

use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use tempfile::TempDir;

use vpnctl_core::{KernelId, ProtocolId, Registry, Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;
use vpnctl_kernels::{AmneziaWg, Caddy, SingBox, Xray};
use vpnctl_protocols::{DnsTunnel, Hysteria2, Naive, VlessReality, VlessXhttp, WireGuard};
use vpnctld::router;

use super::common::{
    AWG_DEVICE_ID, DNST_DEVICE_ID, HY2_DEVICE_ID, NAIVE_DEVICE_ID, PAIR_DEVICE_ID,
    XHTTP_DEVICE_ID, get, seed_hy2_opts, seed_state_with_awg, seed_state_with_dns_tunnel,
    seed_state_with_hy2, seed_state_with_naive, seed_state_with_paired_node,
    seed_state_with_xhttp, subscription_lines, subscription_lines_for_ua,
};

/// A naive-granted user gets the naive URI — and it lands STRICTLY AFTER
/// every vless line (two-pass render). The userinfo carries the user id +
/// credential and the host is the ACME domain.
#[tokio::test]
async fn vpn_router_naive_uri_appended_after_all_vless() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_naive(&dir).await;
    let lines = subscription_lines(router(state), NAIVE_DEVICE_ID).await;

    assert_eq!(lines.len(), 2, "expected 1 vless + 1 naive: {lines:?}");
    assert!(
        lines[0].starts_with("vless://") && lines[0].contains("@de.example.com"),
        "vless must be first: {lines:?}"
    );
    let naive = lines.last().unwrap();
    assert!(
        naive.starts_with("naive+https://"),
        "naive must be last: {lines:?}"
    );
    assert!(
        naive.contains("tester-1:NAIVE_TEST_PW@cdn.example.com"),
        "naive userinfo + ACME host: {naive}"
    );
    // Fragment carries the operator's server label, like the vless lines.
    assert!(
        naive.ends_with("#Latvia%20NAIVE%20~tester-1"),
        "naive fragment must carry the server display label: {naive}"
    );
    // naive-only node (no co-located HY2) → no pairing tag.
    assert!(
        !naive.contains("pair="),
        "a naive-only node must not carry a pair param: {naive}"
    );
    // The naive line never precedes a vless line — guards the two-pass order.
    let first_naive = lines
        .iter()
        .position(|l| l.starts_with("naive+https://"))
        .unwrap();
    let last_vless = lines
        .iter()
        .rposition(|l| l.starts_with("vless://"))
        .unwrap();
    assert!(
        first_naive > last_vless,
        "every vless precedes every naive: {lines:?}"
    );
}

/// Kill-switch: hiding naive on the server (NM-10) drops it from the
/// subscription on the very next request — and the vless lines are
/// untouched. This is the instant, redeploy-free abort path.
#[tokio::test]
async fn vpn_router_hidden_naive_excluded_vless_intact() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_naive(&dir).await;
    // All mutations BEFORE the fetch (access-log writer race, see above).
    state
        .inv
        .set_server_protocol_hidden(&ServerId("cdn".into()), &ProtocolId("naive".into()), true)
        .await
        .unwrap();
    let lines = subscription_lines(router(state), NAIVE_DEVICE_ID).await;

    assert!(
        !lines.iter().any(|l| l.starts_with("naive+https://")),
        "hidden naive must be absent: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("@de.example.com")),
        "vless must remain after hiding naive: {lines:?}"
    );
}

/// Opt-in by grant: a user NOT granted on the naive server gets a
/// vless-only blob — byte-identical to the pre-Part-B output. Proves naive
/// cannot break vless for the fleet default (un-opted users).
#[tokio::test]
async fn vpn_router_user_without_naive_grant_gets_no_naive() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_naive(&dir).await;
    // Revoke the naive grant BEFORE the fetch → user granted only on de.
    state
        .inv
        .revoke(&UserId("tester-1".into()), &ServerId("cdn".into()))
        .await
        .unwrap();
    let lines = subscription_lines(router(state), NAIVE_DEVICE_ID).await;

    // Byte-integrity: EXACTLY the de vless line, unchanged shape (uuid,
    // host:port, fragment). Proves the naive append path didn't perturb a
    // single byte of the vless output for an un-opted user — the operator's
    // hard requirement.
    assert_eq!(lines.len(), 1, "exactly the de vless line: {lines:?}");
    assert!(
        !lines[0].starts_with("naive+https://"),
        "ungranted user must get no naive line: {lines:?}"
    );
    assert!(
        lines[0].starts_with("vless://11111111-2222-3333-4444-555555555555@de.example.com:443"),
        "de vless uuid/host/port intact: {}",
        lines[0]
    );
    assert!(
        lines[0].contains("#Germany%20VLESS%20~tester-1"),
        "de vless fragment intact: {}",
        lines[0]
    );
}

/// A user granted ONLY on the naive server (no vless grant) gets a
/// single-line naive-only blob — `make_config_blob` doesn't choke on the
/// vless-empty case and naive renders standalone.
#[tokio::test]
async fn vpn_router_naive_only_user_gets_naive_line() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_naive(&dir).await;
    // Revoke the vless grant → user granted only on cdn (naive).
    state
        .inv
        .revoke(&UserId("tester-1".into()), &ServerId("de".into()))
        .await
        .unwrap();
    let lines = subscription_lines(router(state), NAIVE_DEVICE_ID).await;

    assert_eq!(lines.len(), 1, "exactly the naive line: {lines:?}");
    assert!(
        lines[0].starts_with("naive+https://") && lines[0].contains("@cdn.example.com"),
        "naive-only blob: {lines:?}"
    );
}

/// Injection defence end-to-end: a `naive.domain` carrying a newline +
/// forged `vless://` line is REJECTED by the share_link guard → the naive
/// render errors → the handler logs + serves vless-only. The forged line
/// NEVER reaches the blob, and the legitimate vless line is untouched.
#[tokio::test]
async fn vpn_router_malformed_naive_domain_no_injection_vless_intact() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_naive(&dir).await;
    // Overwrite the cdn domain with an injection payload BEFORE the fetch.
    state
        .inv
        .set_server_secret(
            &ServerId("cdn".into()),
            "naive.domain",
            "evil.com\nvless://forged@9.9.9.9:443?inject=1",
        )
        .await
        .unwrap();
    let lines = subscription_lines(router(state), NAIVE_DEVICE_ID).await;

    assert!(
        !lines.iter().any(|l| l.contains("forged")),
        "no forged line may reach the blob: {lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.starts_with("naive+https://")),
        "the rejected naive server emits no link: {lines:?}"
    );
    // The legitimate de vless line is served unchanged.
    assert_eq!(lines.len(), 1, "vless-only after naive rejected: {lines:?}");
    assert!(
        lines[0].contains("@de.example.com:443"),
        "vless intact: {lines:?}"
    );
}

/// hysteria2 renders AFTER vless, in the official `hysteria2://` URI form,
/// and carries the Salamander obfs params when the server secret is minted
/// (this is what makes it DPI-resistant — the whole point of the protocol).
#[tokio::test]
async fn vpn_router_hysteria2_uri_appended_after_vless_with_obfs() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_hy2(&dir).await;
    let lines = subscription_lines(router(state), HY2_DEVICE_ID).await;

    assert_eq!(lines.len(), 2, "expected 1 vless + 1 hysteria2: {lines:?}");
    assert!(
        lines[0].starts_with("vless://") && lines[0].contains("@de.example.com"),
        "vless must be first: {lines:?}"
    );
    let hy2 = lines.last().unwrap();
    assert!(
        hy2.starts_with("hysteria2://") && hy2.contains("@hy.example.com:8444/"),
        "hysteria2 last, official scheme + UDP port: {lines:?}"
    );
    assert!(
        hy2.contains("obfs=salamander") && hy2.contains("obfs-password="),
        "Salamander obfs params present (DPI-resistant): {hy2}"
    );
    // Fragment carries the operator's server label "{display} HY2 ~{client}"
    // (ninitux house style, like the vless lines) — NOT the bare username.
    assert!(
        hy2.ends_with("#Latvia%20HY2%20~tester-1"),
        "fragment must carry the server display label, not the username: {hy2}"
    );
    // HY2-only node (no co-located naive) → no pairing tag.
    assert!(
        !hy2.contains("pair="),
        "an HY2-only node must not carry a pair param: {hy2}"
    );
}

/// Kill-switch parity with naive: hiding hysteria2 (NM-10) drops it from the
/// subscription on the next request, vless untouched.
#[tokio::test]
async fn vpn_router_hidden_hysteria2_excluded_vless_intact() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_hy2(&dir).await;
    state
        .inv
        .set_server_protocol_hidden(
            &ServerId("hy".into()),
            &ProtocolId("hysteria2".into()),
            true,
        )
        .await
        .unwrap();
    let lines = subscription_lines(router(state), HY2_DEVICE_ID).await;

    assert!(
        !lines.iter().any(|l| l.starts_with("hysteria2://")),
        "hidden hysteria2 must be absent: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("@de.example.com")),
        "vless must remain: {lines:?}"
    );
}

/// hysteria2's per-user auth is `tuic_password`; a user without one is
/// SKIPPED (share_link errs → failure-isolated) and their vless stays
/// byte-intact. This is the fleet-default case (most migrated users have no
/// tuic_password) — proves an extra protocol can't break their vless.
#[tokio::test]
async fn vpn_router_hysteria2_without_tuic_password_skipped_vless_intact() {
    let dir = TempDir::new().unwrap();
    let state = seed_hy2_opts(&dir, None, true).await;
    let lines = subscription_lines(router(state), HY2_DEVICE_ID).await;
    assert_eq!(
        lines.len(),
        1,
        "vless-only when the user has no tuic_password: {lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.starts_with("hysteria2://")),
        "no hy2 line for a credential-less user: {lines:?}"
    );
    assert!(
        lines[0].starts_with("vless://") && lines[0].contains("@de.example.com:443"),
        "vless intact: {lines:?}"
    );
}

/// `require_secret = None`: hysteria2 renders even with NO obfs secret — a
/// bare `hysteria2://` (no `obfs=` params). Pins that the hy2 path does NOT
/// gate on a server secret the way naive gates on `naive.domain`.
#[tokio::test]
async fn vpn_router_hysteria2_without_obfs_secret_emits_bare_uri() {
    let dir = TempDir::new().unwrap();
    let state = seed_hy2_opts(&dir, Some("PW"), false).await;
    let lines = subscription_lines(router(state), HY2_DEVICE_ID).await;
    let hy2 = lines
        .iter()
        .find(|l| l.starts_with("hysteria2://"))
        .expect("hy2 must render even without an obfs secret");
    assert!(
        !hy2.contains("obfs="),
        "no obfs params when the secret is absent: {hy2}"
    );
    assert!(
        hy2.contains("@hy.example.com:8444/"),
        "still a valid hysteria2 endpoint: {hy2}"
    );
}

/// Multi-extra ordering: a user granted vless + naive + hysteria2 gets the
/// blob partitioned as [vless.., naive+https.., hysteria2://] — vless first
/// (byte-stable), then the extras in EXTRA_PROTOCOLS declaration order. Pins
/// the order against a future reorder of that const.
#[tokio::test]
async fn vpn_router_vless_then_naive_then_hysteria2_order() {
    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_kernel(Box::new(Caddy::new())).unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    reg.register_protocol(Box::new(Naive::new())).unwrap();
    reg.register_protocol(Box::new(Hysteria2::new())).unwrap();

    let mk = |id: &str, proto: &str, kernel: &str| Server {
        id: ServerId(id.into()),
        address: format!("{id}.example.com"),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId(kernel.into())],
        enabled_protocols: vec![ProtocolId(proto.into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    let de = mk("de", "vless+reality", "sing-box");
    inv.add_server(&de).await.unwrap();
    inv.set_server_secret(&de.id, "vless.public_key", "PUB_de")
        .await
        .unwrap();
    inv.set_server_secret(&de.id, "vless.short_id", "12345678")
        .await
        .unwrap();
    let cdn = mk("cdn", "naive", "caddy");
    inv.add_server(&cdn).await.unwrap();
    inv.set_server_secret(&cdn.id, "naive.domain", "cdn.example.com")
        .await
        .unwrap();
    let hy = mk("hy", "hysteria2", "sing-box");
    inv.add_server(&hy).await.unwrap();

    let user = User {
        id: UserId("tester-1".into()),
        uuid: "11111111-2222-3333-4444-555555555555".into(),
        tuic_password: Some("PW".into()),
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    };
    inv.add_user(&user).await.unwrap();
    inv.set_vpn_router_device_id(&user.id, HY2_DEVICE_ID)
        .await
        .unwrap();
    for s in ["de", "cdn", "hy"] {
        inv.grant(&user.id, &ServerId(s.into())).await.unwrap();
    }

    let (state, _w) = vpnctld::make_app_state_for_tests(inv, Arc::new(reg));
    let lines = subscription_lines(router(state), HY2_DEVICE_ID).await;
    assert_eq!(lines.len(), 3, "vless + naive + hy2: {lines:?}");
    assert!(lines[0].starts_with("vless://"), "vless first: {lines:?}");
    assert!(
        lines[1].starts_with("naive+https://"),
        "naive second: {lines:?}"
    );
    assert!(
        lines[2].starts_with("hysteria2://"),
        "hysteria2 third: {lines:?}"
    );
    // No display_name on cdn/hy → fragment falls back to the uppercased
    // non-ISO id ("CDN" / "HY"), still in the ninitux house style.
    assert!(
        lines[1].ends_with("#CDN%20NAIVE%20~tester-1"),
        "naive fallback label: {}",
        lines[1]
    );
    assert!(
        lines[2].ends_with("#HY%20HY2%20~tester-1"),
        "hy2 fallback label: {}",
        lines[2]
    );
}

/// A malicious/sloppy server `display_name` (newline + `#`) must NOT forge an
/// extra line into the newline-joined base64 blob nor a second fragment — the
/// whole label is `NINITUX_QUOTE`-encoded before it reaches the URI.
#[tokio::test]
async fn vpn_router_extra_protocol_label_injection_is_neutralized() {
    let dir = TempDir::new().unwrap();
    let state = seed_hy2_opts(&dir, Some("PW"), true).await;
    state
        .inv
        .set_server_display_name(&ServerId("hy".into()), Some("Evil\nLatvia#x"))
        .await
        .unwrap();
    let lines = subscription_lines(router(state), HY2_DEVICE_ID).await;

    // Exactly de-vless + hy2 — the embedded newline did NOT split into a 3rd
    // blob line (it'd be a forged URI line if left raw).
    assert_eq!(lines.len(), 2, "no forged blob line: {lines:?}");
    let hy2 = lines
        .iter()
        .find(|l| l.starts_with("hysteria2://"))
        .expect("hy2 present");
    assert!(
        !hy2.contains("Evil\nLatvia"),
        "raw newline must not survive into the URI: {hy2}"
    );
}

/// A node with BOTH naive + HY2 stamps both share-links with the SAME
/// `pair=<server id>` in the query (before the fragment).
#[tokio::test]
async fn vpn_router_colocated_naive_and_hy2_share_a_pair_param() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_paired_node(&dir).await;
    let lines = subscription_lines(router(state), PAIR_DEVICE_ID).await;
    let naive = lines
        .iter()
        .find(|l| l.starts_with("naive+https://"))
        .expect("naive line");
    let hy2 = lines
        .iter()
        .find(|l| l.starts_with("hysteria2://"))
        .expect("hy2 line");

    // naive had no query → "?pair="; hy2 already had a query → "&pair=".
    assert!(naive.contains("?pair=cdn#"), "naive pair in query: {naive}");
    assert!(hy2.contains("&pair=cdn#"), "hy2 pair in query: {hy2}");

    // Identical pair value on both.
    let pair_of = |u: &str| {
        u.split("pair=")
            .nth(1)
            .and_then(|s| s.split(['#', '&']).next())
            .map(str::to_string)
    };
    assert_eq!(pair_of(naive), Some("cdn".to_string()));
    assert_eq!(
        pair_of(naive),
        pair_of(hy2),
        "naive & hy2 of one node must share the pair"
    );

    // pair lives in the query (before '#'), not the fragment.
    assert!(
        naive.find("pair=").unwrap() < naive.find('#').unwrap(),
        "pair must precede the fragment: {naive}"
    );
}

/// Different nodes get DIFFERENT pair values (each its own server id) — the
/// "разные узлы → разный pair" half of the contract.
#[tokio::test]
async fn vpn_router_two_paired_nodes_get_distinct_pair_values() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_paired_node(&dir).await; // node "cdn" (naive+hy2)

    // A SECOND co-located node "nl2".
    let nl2 = Server {
        id: ServerId("nl2".into()),
        address: "1.2.3.4".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("caddy".into()), KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("naive".into()), ProtocolId("hysteria2".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    state.inv.add_server(&nl2).await.unwrap();
    state
        .inv
        .set_server_secret(&nl2.id, "naive.domain", "nl2.example.com")
        .await
        .unwrap();
    state
        .inv
        .grant(&UserId("tester-1".into()), &ServerId("nl2".into()))
        .await
        .unwrap();
    state
        .inv
        .set_server_udp_pair_enabled(&ServerId("nl2".into()), true)
        .await
        .unwrap();

    let lines = subscription_lines(router(state), PAIR_DEVICE_ID).await;
    let has = |scheme: &str, pair: &str| {
        lines
            .iter()
            .any(|l| l.starts_with(scheme) && l.contains(pair))
    };
    // cdn's pair=cdn on both, nl2's pair=nl2 on both — distinct per node.
    assert!(has("naive+https://", "pair=cdn#"), "cdn naive: {lines:?}");
    assert!(has("hysteria2://", "pair=cdn#"), "cdn hy2: {lines:?}");
    assert!(has("naive+https://", "pair=nl2#"), "nl2 naive: {lines:?}");
    assert!(has("hysteria2://", "pair=nl2#"), "nl2 hy2: {lines:?}");
}

/// The pairing tag is an OPT-IN (UX-3): a node with BOTH naive+HY2 but the
/// `udp_pair_enabled` flag OFF emits NO `pair=` on either link — both still
/// render, just unpaired.
#[tokio::test]
async fn vpn_router_paired_node_without_optin_has_no_pair() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_paired_node(&dir).await; // cdn: opt-in ON by default
    state
        .inv
        .set_server_udp_pair_enabled(&ServerId("cdn".into()), false)
        .await
        .unwrap();
    let lines = subscription_lines(router(state), PAIR_DEVICE_ID).await;
    assert!(
        !lines.iter().any(|l| l.contains("pair=")),
        "no pair tag without the opt-in: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.starts_with("naive+https://")),
        "naive still renders: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.starts_with("hysteria2://")),
        "hy2 still renders: {lines:?}"
    );
}

/// A dns-tunnel-granted user gets a `dns-tunnel://` URI in the blob, AFTER
/// every vless line, fragment carrying the operator's server label. No
/// `pair=` (no co-located UDP sibling).
#[tokio::test]
async fn vpn_router_dns_tunnel_uri_appended_after_all_vless() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_dns_tunnel(&dir).await;
    let lines = subscription_lines(router(state), DNST_DEVICE_ID).await;

    assert_eq!(lines.len(), 2, "expected 1 vless + 1 dns-tunnel: {lines:?}");
    assert!(
        lines[0].starts_with("vless://"),
        "vless must be first: {lines:?}"
    );
    let dnst = lines.last().unwrap();
    assert!(
        dnst.starts_with("dns-tunnel://"),
        "dns-tunnel must be last: {lines:?}"
    );
    // Operator label surfaces in the fragment, like vless/naive. The
    // `WL-BYPASS` tag (whitelist-bypass — the break-glass transport)
    // uses a hyphen so it stays a single token (no space) for any
    // client-side fragment parser; the hyphen is unreserved in
    // NINITUX_QUOTE so it is NOT percent-encoded.
    assert!(
        dnst.ends_with("#Iceland%20WL-BYPASS%20~tester-1"),
        "dns-tunnel fragment must carry the server display label: {dnst}"
    );
    // No co-located UDP sibling → no pairing tag.
    assert!(
        !dnst.contains("pair="),
        "dns-tunnel must not carry a pair param: {dnst}"
    );
    // Two-pass order guard: every vless precedes the dns-tunnel line.
    let first_dnst = lines
        .iter()
        .position(|l| l.starts_with("dns-tunnel://"))
        .unwrap();
    let last_vless = lines
        .iter()
        .rposition(|l| l.starts_with("vless://"))
        .unwrap();
    assert!(
        first_dnst > last_vless,
        "every vless precedes the dns-tunnel line: {lines:?}"
    );
}

/// The dns-tunnel line is delivered ONLY to the custom VPNRouter blob — it
/// must NEVER reach a GENERIC client via the `/sub/<token>` endpoint: not in
/// the sing-box JSON envelope (default UA) nor the v2ray base64 list (v2ray
/// UA). A `dns-tunnel://` line would make a generic client choke; the blob
/// IS the custom channel by design.
#[tokio::test]
async fn vpn_router_dns_tunnel_absent_from_generic_sub_channels() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_dns_tunnel(&dir).await;
    let token = state
        .inv
        .get_user(&UserId("tester-1".into()))
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .unwrap();

    // Default UA → sing-box JSON envelope.
    let (status, body, _ct) =
        get(router(state.clone()), &format!("/sub/{token}"), "okhttp/4").await;
    assert_eq!(status, StatusCode::OK);
    let envelope = String::from_utf8(body).unwrap();
    assert!(
        !envelope.contains("dns-tunnel"),
        "dns-tunnel must never enter the sing-box JSON envelope: {envelope}"
    );

    // v2ray UA → base64 list of share-links; decode and check the scheme.
    let (status, body, _ct) = get(router(state), &format!("/sub/{token}"), "v2rayN/6.62").await;
    assert_eq!(status, StatusCode::OK);
    let decoded =
        String::from_utf8(BASE64_STANDARD.decode(&body).unwrap_or_default()).unwrap_or_default();
    assert!(
        !decoded.contains("dns-tunnel://"),
        "dns-tunnel:// must never enter the v2ray base64 sub: {decoded}"
    );
}

/// Kill-switch parity: hiding dns-tunnel on the server (NM-10) drops it from
/// the blob on the next request, vless untouched.
#[tokio::test]
async fn vpn_router_hidden_dns_tunnel_excluded_vless_intact() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_dns_tunnel(&dir).await;
    state
        .inv
        .set_server_protocol_hidden(
            &ServerId("tun".into()),
            &ProtocolId("dns-tunnel".into()),
            true,
        )
        .await
        .unwrap();
    let lines = subscription_lines(router(state), DNST_DEVICE_ID).await;
    assert!(
        !lines.iter().any(|l| l.starts_with("dns-tunnel://")),
        "hidden dns-tunnel must be excluded: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.starts_with("vless://")),
        "vless must remain after hiding dns-tunnel: {lines:?}"
    );
}

/// A dns-tunnel server provisioned with the domain secret but NO fingerprint
/// yet (half-configured) must NOT abort the blob — the share-link render
/// fails, that server is skipped, vless survives. Built inline so the
/// fingerprint is absent from the start (there is no secret-delete API).
#[tokio::test]
async fn vpn_router_dns_tunnel_missing_fingerprint_skips_server_keeps_vless() {
    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_kernel(Box::new(vpnctl_kernels::DnsTunnel::new()))
        .unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    reg.register_protocol(Box::new(DnsTunnel::new())).unwrap();

    let de = Server {
        id: ServerId("de".into()),
        address: "de.example.com".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&de).await.unwrap();
    inv.set_server_secret(&de.id, "vless.public_key", "PUB_de")
        .await
        .unwrap();
    inv.set_server_secret(&de.id, "vless.short_id", "12345678")
        .await
        .unwrap();

    // dns-tunnel server with domain ONLY — fingerprint never set.
    let tun = Server {
        id: ServerId("tun".into()),
        address: "tun.example.com".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("dns-tunnel".into())],
        enabled_protocols: vec![ProtocolId("dns-tunnel".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&tun).await.unwrap();
    inv.set_server_secret(&tun.id, "dns-tunnel:domain", "tunnel.example.org")
        .await
        .unwrap();

    let user = User {
        id: UserId("tester-1".into()),
        uuid: "11111111-2222-3333-4444-555555555555".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    };
    inv.add_user(&user).await.unwrap();
    inv.set_vpn_router_device_id(&user.id, DNST_DEVICE_ID)
        .await
        .unwrap();
    inv.grant(&user.id, &ServerId("de".into())).await.unwrap();
    inv.grant(&user.id, &ServerId("tun".into())).await.unwrap();
    let (state, _writer) = vpnctld::make_app_state_for_tests(inv, Arc::new(reg));

    let lines = subscription_lines(router(state), DNST_DEVICE_ID).await;
    assert!(
        lines.iter().any(|l| l.starts_with("vless://")),
        "vless must survive a half-configured dns-tunnel server: {lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.starts_with("dns-tunnel://")),
        "a fingerprint-less dns-tunnel server must be skipped: {lines:?}"
    );
}

/// An amneziawg-granted user gets the `awg://` URI — AFTER every vless,
/// carrying the server key (userinfo), the per-peer `/32` (octet 2 for the
/// sole peer, from `with_peers`), the minted obfs, and `s3=s4=0` (1.x).
#[tokio::test]
async fn vpn_router_awg_uri_appended_after_vless() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_awg(&dir).await;
    let lines = subscription_lines_for_ua(router(state), AWG_DEVICE_ID, "VPNRouter").await;

    assert_eq!(lines.len(), 2, "expected 1 vless + 1 awg: {lines:?}");
    assert!(lines[0].starts_with("vless://"), "vless first: {lines:?}");
    let awg = lines.last().unwrap();
    assert!(awg.starts_with("awg://"), "awg must be last: {lines:?}");
    assert!(awg.contains("@203.0.113.50:51820"), "awg host:port: {awg}");
    // Required fields the client's parser hard-requires.
    assert!(
        awg.contains("private_key=") && awg.contains("address=10.66.0.2/32"),
        "awg must carry private_key + the per-peer /32 (octet 2): {awg}"
    );
    // Obfs come straight from the minted server secrets.
    assert!(
        awg.contains("jc=7") && awg.contains("s1=30") && awg.contains("h1=1111111111"),
        "awg obfs must mirror the server secrets: {awg}"
    );
    assert!(
        awg.contains("s3=0") && awg.contains("s4=0"),
        "s3/s4 must be 0 (vpnctl serves AWG 1.x): {awg}"
    );
    assert!(
        awg.ends_with("#Iceland%20AWG%20~tester-1"),
        "awg fragment must carry the server display label: {awg}"
    );
    let first_awg = lines.iter().position(|l| l.starts_with("awg://")).unwrap();
    let last_vless = lines
        .iter()
        .rposition(|l| l.starts_with("vless://"))
        .unwrap();
    assert!(
        first_awg > last_vless,
        "every vless precedes the awg line: {lines:?}"
    );
}

/// Kill-switch: hiding `wireguard` on the server (NM-10) drops `awg://`
/// from the subscription on the next request; vless stays intact.
#[tokio::test]
async fn vpn_router_hidden_wireguard_excludes_awg_vless_intact() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_awg(&dir).await;
    state
        .inv
        .set_server_protocol_hidden(
            &ServerId("aw".into()),
            &ProtocolId("wireguard".into()),
            true,
        )
        .await
        .unwrap();
    let lines = subscription_lines_for_ua(router(state), AWG_DEVICE_ID, "VPNRouter").await;

    assert!(
        !lines.iter().any(|l| l.starts_with("awg://")),
        "hidden wireguard must drop awg://: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.starts_with("vless://")),
        "vless must remain after hiding wireguard: {lines:?}"
    );
}

/// Opt-in by grant: a user not granted the amneziawg server gets a
/// vless-only blob — awg:// cannot break vless for un-opted users.
#[tokio::test]
async fn vpn_router_user_without_awg_grant_gets_no_awg() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_awg(&dir).await;
    state
        .inv
        .revoke(&UserId("tester-1".into()), &ServerId("aw".into()))
        .await
        .unwrap();
    let lines = subscription_lines_for_ua(router(state), AWG_DEVICE_ID, "VPNRouter").await;

    assert!(
        !lines.iter().any(|l| l.starts_with("awg://")),
        "un-granted user must get no awg://: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.starts_with("vless://")),
        "vless must remain: {lines:?}"
    );
}

/// REGRESSION GUARD for the awg:// octet ↔ server `awg0.conf` match.
/// The subscription octet = `2 + position in the FULL users_for_server list`
/// (ORDER BY id), counting granted users WITHOUT a wireguard_pubkey — because
/// the kernel's `awg0.conf` [Peer] octet enumerates the SAME full list,
/// skipping pubkey-less users from OUTPUT but NOT from the index. A
/// pubkey-less user sorting before the awg user therefore shifts the octet to
/// `.3`. If anyone "fixes" one side to skip pubkey-less peers, the two octets
/// diverge and the tunnel routes to the wrong /32 — this test fails first.
#[tokio::test]
async fn vpn_router_awg_octet_counts_pubkeyless_granted_peers() {
    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut reg = Registry::new();
    reg.register_kernel(Box::new(AmneziaWg::new())).unwrap();
    reg.register_protocol(Box::new(WireGuard::new())).unwrap();
    let aw = Server {
        id: ServerId("aw".into()),
        address: "203.0.113.50".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("amneziawg".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&aw).await.unwrap();
    for (k, v) in [
        (
            "wireguard.server_public_key",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
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
        inv.set_server_secret(&aw.id, k, v).await.unwrap();
    }
    // Pubkey-less granted user with a LOWER id ("aaa-novg" < "tester-1") →
    // sorts first in users_for_server, shifting tester-1's octet to .3.
    let novg = User {
        id: UserId("aaa-novg".into()),
        uuid: "00000000-0000-0000-0000-000000000000".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    };
    inv.add_user(&novg).await.unwrap();
    inv.grant(&novg.id, &aw.id).await.unwrap();
    let user = User {
        id: UserId("tester-1".into()),
        uuid: "11111111-2222-3333-4444-555555555555".into(),
        tuic_password: None,
        wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
        wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    };
    inv.add_user(&user).await.unwrap();
    inv.set_vpn_router_device_id(&user.id, AWG_DEVICE_ID)
        .await
        .unwrap();
    inv.grant(&user.id, &aw.id).await.unwrap();
    let (state, _writer) = vpnctld::make_app_state_for_tests(inv, Arc::new(reg));

    let lines = subscription_lines_for_ua(router(state), AWG_DEVICE_ID, "VPNRouter").await;
    let awg = lines
        .iter()
        .find(|l| l.starts_with("awg://"))
        .expect("awg line present");
    assert!(
        awg.contains("address=10.66.0.3/32"),
        "octet must count the pubkey-less peer ahead of tester-1 (→ .3, \
         matching the kernel's enumerate-over-all-users): {awg}"
    );
}

/// UA-gate: awg:// is delivered ONLY to the custom VPNRouter client (the
/// only consumer that parses the scheme). A generic v2ray-family client —
/// even with wireguard visible AND the user holding WG keys — gets a blob
/// with NO awg:// line, so advertising wireguard can't break a v2ray/clash
/// parser fleet-wide. The VPNRouter UA (covered by the tests above) DOES
/// receive it.
#[tokio::test]
async fn vpn_router_awg_ua_gated_out_for_generic_client() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_awg(&dir).await;
    let lines = subscription_lines_for_ua(router(state), AWG_DEVICE_ID, "v2rayN/6.62").await;
    assert!(
        !lines.iter().any(|l| l.starts_with("awg://")),
        "generic client must NOT receive awg:// (UA-gated to VPNRouter): {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.starts_with("vless://")),
        "vless must remain for the generic client: {lines:?}"
    );
}

/// VPNRouter gets the `vless://…type=xhttp` line (after vless), carrying the
/// reality pbk/sid + the xhttp path.
#[tokio::test]
async fn vpn_router_xhttp_delivered_to_vpnrouter_after_vless() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_xhttp(&dir).await;
    let lines = subscription_lines_for_ua(router(state), XHTTP_DEVICE_ID, "VPNRouter").await;

    let xhttp = lines
        .iter()
        .find(|l| l.contains("type=xhttp"))
        .expect("expected a vless://…type=xhttp line for VPNRouter");
    assert!(
        xhttp.starts_with("vless://"),
        "xhttp line is a vless URI: {xhttp}"
    );
    assert!(
        xhttp.contains("@203.0.113.60:9443"),
        "xhttp host:port: {xhttp}"
    );
    assert!(
        xhttp.contains("pbk=PUB_xr") && xhttp.contains("sid=abcdef12"),
        "xhttp reuses the reality pbk/sid: {xhttp}"
    );
    // Lands after every vless+reality line.
    let first_x = lines.iter().position(|l| l.contains("type=xhttp")).unwrap();
    let last_reality = lines
        .iter()
        .rposition(|l| l.starts_with("vless://") && !l.contains("type=xhttp"))
        .unwrap();
    assert!(
        first_x > last_reality,
        "xhttp must land after vless: {lines:?}"
    );
}

/// A generic client (v2ray) must NOT get the xhttp line (UA-gated), but keeps
/// its vless+reality.
#[tokio::test]
async fn vpn_router_xhttp_ua_gated_out_for_generic_client() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_xhttp(&dir).await;
    let lines = subscription_lines_for_ua(router(state), XHTTP_DEVICE_ID, "v2rayN/6.62").await;
    assert!(
        !lines.iter().any(|l| l.contains("type=xhttp")),
        "generic client must NOT receive type=xhttp (UA-gated): {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.starts_with("vless://")),
        "vless+reality must remain for the generic client: {lines:?}"
    );
}
