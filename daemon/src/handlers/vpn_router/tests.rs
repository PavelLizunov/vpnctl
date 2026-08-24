#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

use super::collectors::*;
use super::compat::*;
use super::routes::*;

#[test]
fn vpn_client_ua_matches_known_keywords() {
    for ua in [
        "v2rayN/6.62",
        "v2rayNG/1.9.0",
        "Streisand/1.6 CFNetwork/1390 Darwin/22.0.0",
        "Shadowrocket/2.2.62 CFNetwork/1568 Darwin/24.1.0",
        "sing-box/1.10.0",
        "Hiddify/1.5.3",
        "ClashforWindows/0.20.39",
        "Quantumult/1.0.27",
        "NekoBox/1.3.7",
        "Karing/1.0.0",
        // 2026-05-23 — V2rayTun (iOS) added to the keyword
        // list. Verifies the substring match doesn't depend on
        // the v2rayN-shaped prefix.
        "V2rayTun/2.3.1 CFNetwork/1568 Darwin/24.1.0",
        "v2raytun/2.3.1 (linux probe)",
        // 2026-06-16 — Happ added (was falling through to the raw
        // sing-box JSON branch → «json-error» on import).
        "Happ/1.6.0 (iPhone; iOS 18.0)",
        "happ/2.0 (Android)",
    ] {
        assert!(is_vpn_client_ua(ua), "expected VPN client: {ua}");
    }
}

#[test]
fn browser_ua_takes_json_wrapper_path() {
    for ua in [
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "curl/8.4.0",
        "VPNRouter/2.4.1 (custom mobile app)",
        "",
    ] {
        assert!(!is_vpn_client_ua(ua), "expected non-VPN-client: {ua}");
    }
}

#[test]
fn singbox_transport_capability_excludes_v2ray_core_clients() {
    // V2Ray/Xray-core clients can't parse hysteria2/tuic/anytls —
    // they must NOT receive those share-links (a leading hysteria2://
    // entry breaks their whole VLESS import). 2026-06-16 fix.
    for ua in [
        "V2rayTun/2.3.1 CFNetwork/1568 Darwin/24.1.0",
        "v2raytun/ios",
        "v2rayN/6.62",
        "v2rayNG/1.9.0",
    ] {
        assert!(
            !client_supports_singbox_transports(ua),
            "v2ray-core client must NOT get sing-box transports: {ua}"
        );
    }
    // Sing-box-core clients (and unknown UAs) keep the full set.
    for ua in [
        "Streisand/42 CFNetwork/3860 Darwin",
        "NekoBox/1.3.7",
        "Shadowrocket/2.2.62 CFNetwork/1568 Darwin/24.1.0",
        "Hiddify/1.5.3",
        "sing-box/1.10.0",
        "Karing/1.0.0",
        // Happ runs sing-box core → keeps hysteria2/tuic/anytls.
        "Happ/1.6.0 (iPhone; iOS 18.0)",
        "some-unknown-client/1.0",
    ] {
        assert!(
            client_supports_singbox_transports(ua),
            "sing-box-core / unknown client must keep sing-box transports: {ua}"
        );
    }
}

#[test]
fn country_display_name_maps_iso_codes() {
    assert_eq!(country_display_name("de"), "Germany");
    assert_eq!(country_display_name("is"), "Iceland");
    assert_eq!(country_display_name("fi"), "Finland");
    // Unknown id → uppercased fallback (legacy or test server).
    assert_eq!(country_display_name("stg"), "STG");
    assert_eq!(country_display_name("vps-de-01"), "VPS-DE-01");
    assert_eq!(country_display_name(""), "");
}

#[test]
fn server_display_label_precedence() {
    // 1. Operator custom name wins over the country map.
    assert_eq!(
        server_display_label("de", Some("Germany Prod #2")),
        "Germany Prod #2"
    );
    // 2. Blank / whitespace custom → fall back to the country map.
    assert_eq!(server_display_label("de", Some("   ")), "Germany");
    assert_eq!(server_display_label("de", None), "Germany");
    // 3. No custom + unmapped id → uppercased id (the `kg` bug:
    //    before a custom name it renders "KG", with one it can be
    //    the friendly "Kyrgyzstan").
    assert_eq!(server_display_label("kg", None), "KG");
    assert_eq!(server_display_label("kg", Some("Kyrgyzstan")), "Kyrgyzstan");
    // 4. Custom is trimmed.
    assert_eq!(
        server_display_label("kg", Some("  Kyrgyzstan ")),
        "Kyrgyzstan"
    );
}

#[test]
fn ip_to_throttle_exempts_egress_and_unspecified() {
    use std::net::IpAddr;
    let client: IpAddr = "203.0.113.50".parse().unwrap();
    let egress: IpAddr = "104.194.156.93".parse().unwrap(); // a VPN node
    let unspecified: IpAddr = "0.0.0.0".parse().unwrap();

    // Normal client IP, not a known server → throttle it.
    assert_eq!(ip_to_throttle(Some(client), false), Some(client));
    // THE constraint: a VPN-egress IP (is_known_server=true) is
    // EXEMPT — 33 users on one node must not share a per-IP bucket.
    assert_eq!(ip_to_throttle(Some(egress), true), None);
    // Unspecified (no ConnectInfo / test rig) → can't identify a
    // source → skip per-IP (per-device_id still applies).
    assert_eq!(ip_to_throttle(Some(unspecified), false), None);
    // No IP at all → skip.
    assert_eq!(ip_to_throttle(None, false), None);
    // Even a non-egress client whose IP happens to be flagged known
    // (shouldn't happen, but defensive) is exempt.
    assert_eq!(ip_to_throttle(Some(client), true), None);
}

#[test]
fn render_vless_uri_post_rename_fragment_format() {
    // Post-2026-05-20 rename: fragment is `{Country} VLESS` without
    // port (visible from host) or client_name (user already knows
    // their own name). Pre-rename format was
    // `{server_tag} {port} {client_name}` byte-equivalent with
    // subscription-server — that contract intentionally retired
    // when subscription-server was decommissioned + the operator
    // requirement shifted to user-friendly labels («чтоб
    // пользователь по названию легко мог понять для чего конфиг
    // и что за сервер»).
    let got = render_vless_uri(
        "104.194.156.93",
        443,
        "www.microsoft.com",
        "gDawCMB0X6iGXZkG8nZIFW5TaaW29x0DMzWijN-gc2A",
        "d86e92a0c6dd2271",
        "60063863-d2be-4d57-bc0b-aef4da88528b",
        "Germany",
        "tester-1", // ignored in label — kept for signature compat
    );

    // Post-2026-05-23 V2rayTun-compat fix: `encryption=none`
    // re-added at the front of the query string. See doc-comment
    // on `render_vless_uri` for the full rationale.
    // 2026-06-16 DPI-evasion: `fp=randomized` (was `fp=chrome`).
    let expected = "vless://60063863-d2be-4d57-bc0b-aef4da88528b@104.194.156.93:443?encryption=none&type=tcp&security=reality&pbk=gDawCMB0X6iGXZkG8nZIFW5TaaW29x0DMzWijN-gc2A&fp=randomized&sni=www.microsoft.com&sid=d86e92a0c6dd2271&spx=%2F&flow=xtls-rprx-vision&packetEncoding=xudp#Germany%20VLESS%20~tester-1";
    assert_eq!(got, expected, "vless URI fragment drifted");
}

#[test]
fn render_vless_uri_brackets_ipv6_authority() {
    // Regression: the app-config renderer interpolated
    // `Server.address` raw, so an IPv6 node produced
    // `...@2a00:1450::1:443` — every client parser splits the
    // authority on the wrong `:` and the link is dead. Must reuse
    // `host_for_url` (same as the `/sub` share-link path) and emit
    // a bracketed `@[2a00:1450::1]:443` authority.
    let got = render_vless_uri(
        "2a00:1450::1",
        443,
        "www.microsoft.com",
        "gDawCMB0X6iGXZkG8nZIFW5TaaW29x0DMzWijN-gc2A",
        "d86e92a0c6dd2271",
        "60063863-d2be-4d57-bc0b-aef4da88528b",
        "Germany",
        "tester-1",
    );
    assert!(
        got.contains("@[2a00:1450::1]:443"),
        "IPv6 authority must be bracketed: {got}"
    );
}

#[test]
fn make_config_blob_empty_input_returns_none() {
    assert_eq!(make_config_blob(&[]), None);
}

#[test]
fn make_config_blob_joins_with_newline_then_base64() {
    let uris = vec!["vless://aaa".to_string(), "vless://bbb".to_string()];
    let blob = make_config_blob(&uris).unwrap();
    // Standard base64 of "vless://aaa\nvless://bbb".
    let decoded = BASE64_STANDARD.decode(blob.as_bytes()).unwrap();
    let s = std::str::from_utf8(&decoded).unwrap();
    assert_eq!(s, "vless://aaa\nvless://bbb");
}

#[test]
fn app_config_response_serialises_in_declared_field_order() {
    let body = AppConfigResponse {
        status: "ok",
        app: "vpn-router",
        version: "2.4.1",
        update_available: false,
        config: Some("base64body".to_string()),
        check_interval: 3600,
        timestamp: 1747588800,
    };
    let json = serde_json::to_string(&body).unwrap();
    assert_eq!(
        json,
        r#"{"status":"ok","app":"vpn-router","version":"2.4.1","update_available":false,"config":"base64body","check_interval":3600,"timestamp":1747588800}"#
    );
}

#[test]
fn app_config_response_emits_config_null_when_missing() {
    let body = AppConfigResponse {
        status: "device_not_registered",
        app: "vpn-router",
        version: "2.4.1",
        update_available: false,
        config: None,
        check_interval: 3600,
        timestamp: 0,
    };
    let json = serde_json::to_string(&body).unwrap();
    // Notably: `"config":null` literal, NOT omitted.
    assert!(json.contains(r#""config":null"#), "got: {json}");
    // And status must be the exact string.
    assert!(json.contains(r#""status":"device_not_registered""#));
}
