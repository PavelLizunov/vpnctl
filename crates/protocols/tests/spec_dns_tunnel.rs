#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Spec tests for `vpnctl_protocols::DnsTunnel` (the companion stub to
//! the dns-tunnel kernel). Written from the spec only — share-link wire
//! format, the two-process-bundle contract (`appears_in_sing_box_sub`
//! false), the marker `server_inbound`. If a test fails, the impl is
//! wrong — DO NOT weaken the test.

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use vpnctl_core::{
    DpiRisk, KernelId, Protocol, ProtocolId, RenderCtx, Server, ServerId, User, UserId,
};
use vpnctl_protocols::DnsTunnel;

const FP: &str = "47:1E:87:8F:3E:48:C8:1C:5F:BF:30:2E:B8:A8:3A:05:72:0D:B9:77:A2:11:81:09:E6:E5:EF:92:C4:66:7B:92";
const UUID: &str = "e09b09af-2500-4753-b219-937ce13b5257";

fn srv() -> Server {
    Server {
        id: ServerId("dns-tunnel-node".into()),
        address: "203.0.113.42".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("dns-tunnel".into())],
        enabled_protocols: vec![ProtocolId("dns-tunnel".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn user(name: &str) -> User {
    User {
        id: UserId(name.into()),
        uuid: format!("uuid-{name}"),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

fn secrets() -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("dns-tunnel:domain".into(), "t.example.com".into());
    m.insert("dns-tunnel:fingerprint".into(), FP.into());
    m.insert("dns-tunnel:loopback_uuid".into(), UUID.into());
    m
}

#[test]
fn id_is_dns_tunnel() {
    assert_eq!(DnsTunnel::new().id(), ProtocolId("dns-tunnel".into()));
}

#[test]
fn dpi_risk_is_moderate() {
    // Last-resort transport; НСДИ is a monitored point. Moderate, NOT
    // Strong — do not overrate it.
    assert_eq!(DnsTunnel::new().dpi_risk(), DpiRisk::Moderate);
}

#[test]
fn does_not_appear_in_sing_box_sub() {
    // The client is a two-process bundle (slipstream-client + loopback
    // VLESS), not a single sing-box outbound. A `type: "dns-tunnel"`
    // object would make the whole /sub envelope unparseable.
    assert!(!DnsTunnel::new().appears_in_sing_box_sub());
}

#[test]
fn server_inbound_returns_marker() {
    let s = srv();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let v = DnsTunnel::new().server_inbound(&ctx, &[]).unwrap();
    // Throwaway marker — the kernel renders the real loopback VLESS
    // inbound itself and never reads this value.
    assert_eq!(v["type"], "dns-tunnel");
}

#[test]
fn share_link_scheme_and_required_fields_round_trip() {
    let s = srv();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let link = DnsTunnel::new().share_link(&ctx, &user("alex")).unwrap();
    assert!(link.starts_with("dns-tunnel://"), "scheme: {link}");

    let payload = link
        .strip_prefix("dns-tunnel://")
        .unwrap()
        .split('#')
        .next()
        .unwrap();
    let raw = URL_SAFE_NO_PAD.decode(payload).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(v["v"], 1, "format version: {v}");
    assert_eq!(v["d"], "t.example.com");
    assert_eq!(v["fp"], FP);
    assert_eq!(v["uuid"], UUID);
    assert_eq!(
        v["r"],
        serde_json::json!(["195.208.4.1:53", "195.208.5.1:53"]),
        "default multipath НСДИ resolvers: {v}"
    );
}

#[test]
fn share_link_payload_is_base64url_no_pad() {
    let s = srv();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let link = DnsTunnel::new().share_link(&ctx, &user("alex")).unwrap();
    let payload = link
        .strip_prefix("dns-tunnel://")
        .unwrap()
        .split('#')
        .next()
        .unwrap();
    assert!(
        !payload.ends_with('='),
        "base64url-NO-pad must not end '=': {payload}"
    );
    for c in payload.chars() {
        assert!(
            c.is_ascii_alphanumeric() || c == '-' || c == '_',
            "non-base64url char {c:?} in payload: {payload}"
        );
    }
}

#[test]
fn share_link_label_fragment_is_percent_encoded_user_id() {
    let s = srv();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    // A plain user id passes through unescaped.
    let link = DnsTunnel::new().share_link(&ctx, &user("alex")).unwrap();
    assert!(link.ends_with("#alex"), "label: {link}");
}

#[test]
fn share_link_is_byte_stable_and_lf_only() {
    // Same secrets + user → byte-identical (pins BTreeMap ordering +
    // base64url alphabet). And no CR can sneak into a URL.
    let s = srv();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let a = DnsTunnel::new().share_link(&ctx, &user("alex")).unwrap();
    let b = DnsTunnel::new().share_link(&ctx, &user("alex")).unwrap();
    assert_eq!(a, b, "share_link not byte-stable");
    assert!(!a.contains('\r'), "CR in share_link: {a}");
    assert!(!a.contains('\n'), "LF in share_link: {a}");
}

#[test]
fn share_link_exact_bytes_mutation_resistant() {
    // Full byte-equality pin (cargo-mutants soft-fails on protocols, so
    // an exact-bytes assertion is the regression net). The payload is a
    // deterministic base64url of the lexicographically-ordered JSON
    // `{d, fp, r, uuid, v}`, fragment `#alex`.
    let s = srv();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let link = DnsTunnel::new().share_link(&ctx, &user("alex")).unwrap();

    // Reconstruct the expected payload from the spec'd JSON so the test
    // documents the exact wire shape without hard-coding an opaque blob
    // that nobody can verify by eye.
    let expected_json = serde_json::json!({
        "v": 1,
        "d": "t.example.com",
        "r": ["195.208.4.1:53", "195.208.5.1:53"],
        "fp": FP,
        "uuid": UUID,
    });
    let expected_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&expected_json).unwrap());
    let expected = format!("dns-tunnel://{expected_payload}#alex");
    assert_eq!(link, expected, "share_link bytes drifted");
}

#[test]
fn share_link_honours_resolver_override_trimmed() {
    let s = srv();
    let mut sec = secrets();
    sec.insert(
        "dns-tunnel:resolvers".into(),
        " 9.9.9.9:53 , 8.8.4.4:53 ".into(),
    );
    let ctx = RenderCtx::new(&s, &sec);
    let link = DnsTunnel::new().share_link(&ctx, &user("alex")).unwrap();
    let payload = link
        .strip_prefix("dns-tunnel://")
        .unwrap()
        .split('#')
        .next()
        .unwrap();
    let raw = URL_SAFE_NO_PAD.decode(payload).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(v["r"], serde_json::json!(["9.9.9.9:53", "8.8.4.4:53"]));
}

#[test]
fn share_link_errors_name_the_missing_secret() {
    let s = srv();
    for missing in [
        "dns-tunnel:domain",
        "dns-tunnel:fingerprint",
        "dns-tunnel:loopback_uuid",
    ] {
        let mut sec = secrets();
        sec.remove(missing);
        let ctx = RenderCtx::new(&s, &sec);
        let err = DnsTunnel::new()
            .share_link(&ctx, &user("alex"))
            .unwrap_err();
        assert!(
            format!("{err}").contains(missing),
            "error for missing {missing} must name it: {err}"
        );
    }
}
