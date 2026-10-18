use std::sync::Arc;

use tempfile::TempDir;

use vpnctl_core::{KernelId, ProtocolId, Registry, Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;
use vpnctl_kernels::{AmneziaWg, Caddy, SingBox};
use vpnctl_protocols::{Hysteria2, Naive, VlessReality, WireGuard};
use vpnctld::router;

use super::common::{
    AWG_DEVICE_ID, HY2_DEVICE_ID, NAIVE_DEVICE_ID, PAIR_DEVICE_ID, XHTTP_DEVICE_ID, seed_hy2_opts,
    seed_state_with_awg, seed_state_with_awg2, seed_state_with_awg2_and_awg3, seed_state_with_awg3,
    seed_state_with_hy2, seed_state_with_naive, seed_state_with_paired_node, seed_state_with_xhttp,
    subscription_lines, subscription_lines_for_ua,
};

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
    assert!(
        naive.ends_with("#Latvia%20NAIVE%20~tester-1"),
        "naive fragment must carry the server display label: {naive}"
    );
    assert!(
        !naive.contains("pair="),
        "a naive-only node must not carry a pair param: {naive}"
    );
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

#[tokio::test]
async fn vpn_router_hidden_naive_excluded_vless_intact() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_naive(&dir).await;
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

#[tokio::test]
async fn vpn_router_user_without_naive_grant_gets_no_naive() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_naive(&dir).await;
    state
        .inv
        .revoke(&UserId("tester-1".into()), &ServerId("cdn".into()))
        .await
        .unwrap();
    let lines = subscription_lines(router(state), NAIVE_DEVICE_ID).await;

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

#[tokio::test]
async fn vpn_router_naive_only_user_gets_naive_line() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_naive(&dir).await;
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

#[tokio::test]
async fn vpn_router_malformed_naive_domain_no_injection_vless_intact() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_naive(&dir).await;
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
    assert_eq!(lines.len(), 1, "vless-only after naive rejected: {lines:?}");
    assert!(
        lines[0].contains("@de.example.com:443"),
        "vless intact: {lines:?}"
    );
}

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
    assert!(
        hy2.ends_with("#Latvia%20HY2%20~tester-1"),
        "fragment must carry the server display label, not the username: {hy2}"
    );
    assert!(
        !hy2.contains("pair="),
        "an HY2-only node must not carry a pair param: {hy2}"
    );
}

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

    assert!(naive.contains("?pair=cdn#"), "naive pair in query: {naive}");
    assert!(hy2.contains("&pair=cdn#"), "hy2 pair in query: {hy2}");

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

    assert!(
        naive.find("pair=").unwrap() < naive.find('#').unwrap(),
        "pair must precede the fragment: {naive}"
    );
}

#[tokio::test]
async fn vpn_router_two_paired_nodes_get_distinct_pair_values() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_paired_node(&dir).await;

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
    assert!(has("naive+https://", "pair=cdn#"), "cdn naive: {lines:?}");
    assert!(has("hysteria2://", "pair=cdn#"), "cdn hy2: {lines:?}");
    assert!(has("naive+https://", "pair=nl2#"), "nl2 naive: {lines:?}");
    assert!(has("hysteria2://", "pair=nl2#"), "nl2 hy2: {lines:?}");
}

#[tokio::test]
async fn vpn_router_paired_node_without_optin_has_no_pair() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_paired_node(&dir).await;
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
    assert!(
        awg.contains("private_key=") && awg.contains("address=10.66.0.2/32"),
        "awg must carry private_key + the per-peer /32 (octet 2): {awg}"
    );
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

#[tokio::test]
async fn vpn_router_awg2_uri_delivered_to_vpnrouter() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_awg2(&dir).await;
    let lines = subscription_lines_for_ua(router(state), AWG_DEVICE_ID, "VPNRouter").await;

    assert_eq!(lines.len(), 2, "expected 1 vless + 1 awg: {lines:?}");
    assert!(lines[0].starts_with("vless://"), "vless first: {lines:?}");
    let awg = lines.last().unwrap();
    assert!(awg.starts_with("awg://"), "awg must be last: {lines:?}");
    assert!(awg.contains("@203.0.113.60:51821"), "awg2 host:port: {awg}");
    assert!(
        awg.contains("private_key=") && awg.contains("address=10.72."),
        "awg2 must carry private_key + 10.72 address: {awg}"
    );
    assert!(
        awg.contains("jc=") && awg.contains("s1=") && awg.contains("h1="),
        "awg2 obfs must mirror parameters: {awg}"
    );
    assert!(
        awg.ends_with("#Iceland2%20AWG%20~tester-1"),
        "awg2 fragment must carry the server display label: {awg}"
    );
}

#[tokio::test]
async fn vpn_router_awg2_ua_gated_out_for_generic_client() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_awg2(&dir).await;
    let lines = subscription_lines_for_ua(router(state), AWG_DEVICE_ID, "v2rayN/6.62").await;
    assert!(
        !lines.iter().any(|l| l.starts_with("awg://")),
        "generic client must NOT receive awg://: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.starts_with("vless://")),
        "vless must remain for generic client: {lines:?}"
    );
}

#[tokio::test]
async fn vpn_router_awg3_uri_delivered_to_vpnrouter() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_awg3(&dir).await;
    let lines = subscription_lines_for_ua(router(state), AWG_DEVICE_ID, "VPNRouter").await;

    assert_eq!(lines.len(), 2, "expected 1 vless + 1 awg3: {lines:?}");
    assert!(lines[0].starts_with("vless://"), "vless first: {lines:?}");
    let awg3 = lines.last().unwrap();
    assert!(awg3.starts_with("awg3://"), "awg3 must be last: {lines:?}");
    assert!(
        awg3.contains("@203.0.113.60:51822"),
        "awg3 host:port: {awg3}"
    );
    assert!(
        awg3.contains("private_key=") && awg3.contains("address=10.73."),
        "awg3 must carry private_key + 10.73 address: {awg3}"
    );
    assert!(
        awg3.contains("jc=") && awg3.contains("s1=") && awg3.contains("h1="),
        "awg3 obfs must mirror parameters: {awg3}"
    );
    assert!(
        awg3.contains("header_protection_key=")
            && awg3.contains("content_padding_addition=0-32")
            && awg3.contains("random_trailers=true")
            && awg3.contains("disable_cookies=true"),
        "awg3 must contain header protection and v3 params: {awg3}"
    );
    assert!(
        awg3.ends_with("#Iceland3%20AWG3%20~tester-1"),
        "awg3 fragment must carry the server display label with AWG3 tag: {awg3}"
    );
}

#[tokio::test]
async fn vpn_router_dual_awg2_and_awg3_delivered_in_order() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_awg2_and_awg3(&dir).await;
    let lines = subscription_lines_for_ua(router(state), AWG_DEVICE_ID, "VPNRouter").await;

    assert_eq!(
        lines.len(),
        3,
        "expected 1 vless + 1 awg2 + 1 awg3: {lines:?}"
    );
    assert!(lines[0].starts_with("vless://"), "vless first: {lines:?}");

    let awg2 = &lines[1];
    assert!(awg2.starts_with("awg://"), "awg2 scheme: {awg2}");
    assert!(awg2.contains(":51821"), "awg2 port 51821: {awg2}");
    assert!(
        awg2.ends_with("#Iceland%20Dual%20AWG%20~tester-1"),
        "awg2 label: {awg2}"
    );

    let awg3 = &lines[2];
    assert!(awg3.starts_with("awg3://"), "awg3 scheme: {awg3}");
    assert!(awg3.contains(":51822"), "awg3 port 51822: {awg3}");
    assert!(
        awg3.ends_with("#Iceland%20Dual%20AWG3%20~tester-1"),
        "awg3 label: {awg3}"
    );
}

#[tokio::test]
async fn vpn_router_awg3_ua_gated_out_for_generic_client() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_awg3(&dir).await;
    let lines = subscription_lines_for_ua(router(state), AWG_DEVICE_ID, "v2rayN/6.62").await;
    assert!(
        !lines
            .iter()
            .any(|l| l.starts_with("awg3://") || l.starts_with("awg://")),
        "generic client must NOT receive awg/awg3: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.starts_with("vless://")),
        "vless must remain for generic client: {lines:?}"
    );
}
