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
        "V2rayTun/2.3.1 CFNetwork/1568 Darwin/24.1.0",
        "v2raytun/2.3.1 (linux probe)",
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
    for ua in [
        "Streisand/42 CFNetwork/3860 Darwin",
        "NekoBox/1.3.7",
        "Shadowrocket/2.2.62 CFNetwork/1568 Darwin/24.1.0",
        "Hiddify/1.5.3",
        "sing-box/1.10.0",
        "Karing/1.0.0",
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
    assert_eq!(country_display_name("stg"), "STG");
    assert_eq!(country_display_name("vps-de-01"), "VPS-DE-01");
    assert_eq!(country_display_name(""), "");
}

#[test]
fn server_display_label_precedence() {
    assert_eq!(
        server_display_label("de", Some("Germany Prod #2")),
        "Germany Prod #2"
    );
    assert_eq!(server_display_label("de", Some("   ")), "Germany");
    assert_eq!(server_display_label("de", None), "Germany");
    assert_eq!(server_display_label("kg", None), "KG");
    assert_eq!(server_display_label("kg", Some("Kyrgyzstan")), "Kyrgyzstan");
    assert_eq!(
        server_display_label("kg", Some("  Kyrgyzstan ")),
        "Kyrgyzstan"
    );
}

#[test]
fn ip_to_throttle_exempts_egress_and_unspecified() {
    use std::net::IpAddr;
    let client: IpAddr = "203.0.113.50".parse().unwrap();
    let egress: IpAddr = "104.194.156.93".parse().unwrap();
    let unspecified: IpAddr = "0.0.0.0".parse().unwrap();

    assert_eq!(ip_to_throttle(Some(client), false), Some(client));
    assert_eq!(ip_to_throttle(Some(egress), true), None);
    assert_eq!(ip_to_throttle(Some(unspecified), false), None);
    assert_eq!(ip_to_throttle(None, false), None);
    assert_eq!(ip_to_throttle(Some(client), true), None);
}

#[test]
fn render_vless_uri_post_rename_fragment_format() {
    let got = render_vless_uri(
        "104.194.156.93",
        443,
        "www.microsoft.com",
        "gDawCMB0X6iGXZkG8nZIFW5TaaW29x0DMzWijN-gc2A",
        "d86e92a0c6dd2271",
        "60063863-d2be-4d57-bc0b-aef4da88528b",
        "Germany",
        "tester-1",
    );

    let expected = "vless://60063863-d2be-4d57-bc0b-aef4da88528b@104.194.156.93:443?encryption=none&type=tcp&security=reality&pbk=gDawCMB0X6iGXZkG8nZIFW5TaaW29x0DMzWijN-gc2A&fp=randomized&sni=www.microsoft.com&sid=d86e92a0c6dd2271&spx=%2F&flow=xtls-rprx-vision&packetEncoding=xudp#Germany%20VLESS%20~tester-1";
    assert_eq!(got, expected, "vless URI fragment drifted");
}

#[test]
fn render_vless_uri_brackets_ipv6_authority() {
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
    assert!(json.contains(r#""config":null"#), "got: {json}");
    assert!(json.contains(r#""status":"device_not_registered""#));
}
