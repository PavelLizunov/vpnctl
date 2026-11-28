#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use vpnctl_core::{KernelId, Protocol, ProtocolId, RenderCtx, Server, ServerId, User, UserId};
use vpnctl_protocols::TrustTunnel;

const ALICE_UUID: &str = "69fcc06e-70c5-4f78-9dec-38d5636b4115";
const BOB_UUID: &str = "a2568ff8-d30c-4513-ab96-781667ea15a2";
const DOMAIN: &str = "vpn.example.test";

const CERTIFICATE: &str = concat!(
    "-----BEGIN CERTIFICATE-----\n",
    "MIIDNDCCAhygAwIBAgIUFhtbcyXcOTNNERPbwh6VTM6UZYowDQYJKoZIhvcNAQEL\n",
    "BQAwGzEZMBcGA1UEAwwQdnBuLmV4YW1wbGUudGVzdDAeFw0yNjExMjcxMjIxNTRa\n",
    "Fw0zNjExMjQxMjIxNTRaMBsxGTAXBgNVBAMMEHZwbi5leGFtcGxlLnRlc3QwggEi\n",
    "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvYF0tWakQ/Ujb4xS6yjj5u4Sl\n",
    "PzRpaeQzqR2mSNDTsVP1l07oKPmBOu10I6Z1UBYfi+hYOIHCnSektJwKoThpxTmF\n",
    "g/I8hHBM+p5P2EqWvpt+bDHT01QmlGhgwpx1pgki0DS27wgt0zIP1PrBEmbFcNEW\n",
    "0JMOtbFNAb24xm4MeNmFUFKa494p2sbzvG6V0zzAhyw6chREcuQWpUR4STPoqv/L\n",
    "pxN5WqvvLGfUf5S5Zu1qW5EDgcBvHR5pk00QcA3Jq6OZ8ErcPOu7gwSxzXOlNf/5\n",
    "3UaH4YXUkkhpfeIdM6SG4XX7344efayzI7117vU9wWkj9wV0ZnvGRQszIBAbAgMB\n",
    "AAGjcDBuMB0GA1UdDgQWBBS8uUK7E5aATScfCIbt52/hbud71DAfBgNVHSMEGDAW\n",
    "gBS8uUK7E5aATScfCIbt52/hbud71DAPBgNVHRMBAf8EBTADAQH/MBsGA1UdEQQU\n",
    "MBKCEHZwbi5leGFtcGxlLnRlc3QwDQYJKoZIhvcNAQELBQADggEBAAd8FxTdKiPw\n",
    "GtKkBvrnhZ2mSo36yR9uIw4TiUi7CTNW6ldthyqeUopijWMdC0SGwBncf3aEoEQc\n",
    "wPRDAZunxX2hymo78Yb6mzCm31VGVOlYSaWc900PJcOH8LgXeWoB5D7hNKmyYusz\n",
    "DpquyDtvj/eDBqopJgW6dK1eFtpHU9Q171aEoVYdBXKNdgXQSaJAleQ1MHVeHLjD\n",
    "gKI5C47Fhsr5/AS/4mVfXaCbpymvsdb0kYoN/79ZN8JU1+A9E8c7q5+VtuR6SODH\n",
    "lJJeHoku6+ubeDMG9ufDrtLuNdbRue+jdVG1SGKy0xEmy5AOBgDKh5R9l9A3ib+7\n",
    "O2VcFwG/l0A=\n",
    "-----END CERTIFICATE-----\n",
);

const PRIVATE_KEY: &str = concat!(
    "-----BEGIN ",
    "PRIVATE KEY-----\n",
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCvYF0tWakQ/Ujb\n",
    "4xS6yjj5u4SlPzRpaeQzqR2mSNDTsVP1l07oKPmBOu10I6Z1UBYfi+hYOIHCnSek\n",
    "tJwKoThpxTmFg/I8hHBM+p5P2EqWvpt+bDHT01QmlGhgwpx1pgki0DS27wgt0zIP\n",
    "1PrBEmbFcNEW0JMOtbFNAb24xm4MeNmFUFKa494p2sbzvG6V0zzAhyw6chREcuQW\n",
    "pUR4STPoqv/LpxN5WqvvLGfUf5S5Zu1qW5EDgcBvHR5pk00QcA3Jq6OZ8ErcPOu7\n",
    "gwSxzXOlNf/53UaH4YXUkkhpfeIdM6SG4XX7344efayzI7117vU9wWkj9wV0ZnvG\n",
    "RQszIBAbAgMBAAECggEABwIbUEGOfKrRVuZurmvt7MxQeggHx4JWIyPKBL7jdXNX\n",
    "Je/LeabaGQ7hSCxYP+l0UN7W6SlRfHBhJGTl2N14BW8sSH9j+vKx7Lve2rCwOcxZ\n",
    "Js/RnH8wgecHDRCJ2Dcmt+ISPuxX/YsX9LECDtOIWkPug6k988FRIyWV4RcMUFej\n",
    "1NPwQuoW7SNuJAwgXodT466/0k+qca4M59cujxrjy31vSiQyMFhbE1AUCriZRbR2\n",
    "ZSjpP+GXotr33Nq60XK+ZYqzUGO2hFuSbR0YOPRR1KDqCtfNPyDRVIdd9IhsC/PS\n",
    "UXtMdgRXbz0u/vCZsVpwahCxdlqPCYUW5aiJdC+8pQKBgQDnHdaapGmf+xgXYLG6\n",
    "a3b0yBFFQlhdekRsKcR+M+JrB+xZPzj5m9ZGkpAf3LXmb/VJmzPy7onP1FytRtAS\n",
    "/qmaWurSP78dGUK5hzxgmZo2CHO6aWLPcRCWIahlOVmNebM956cU3SEXr0d1GRR/\n",
    "9hOH49cAgrHKTPhXxKBqryvWJQKBgQDCQi94BVRBNF/KoBfdw4sRx/vnKKJvJ3hq\n",
    "NYaME/UcgC/xfMN5Z6Inkwc2eCeTxFkzGT18yJCDBJyU0WB0Y0WIsXjTOovixgim\n",
    "OOAImPtFnnIQsQJpntX5eZP3hA7onABtQNiX22usV7SSJeUzqL7fOrylJYKQ2iAo\n",
    "hw6jyD3ZPwKBgQCub17iKOVv0dxFCL4brbCC393pIEIBi57I5F1hw1dI4RoJ4iXm\n",
    "fzAi48vTwImp+yZu/60d1dw9+FJale/F5l+sGKLTPTnJhJ9P2DpBzq0NyyNNtuzV\n",
    "FMkoBw9KFxb4KLqYJpd8r8miTrDoOJ24Vso27kgAIqR9w8pMtCM/Yib74QKBgA3L\n",
    "gW92gWs3+u16vPckocWbfAoIWrCmDukL8AgWiruBZuYxQ/hlIaDJ0iNOGRFnSiZU\n",
    "zocD/y8urqfqzny1aASzBa+KYtCx239iXpZ9tqpU/CivSUqS2wMiXR2gpSZjnawk\n",
    "hL0T+et9NveB9WrbuuJDW44mwcTjmJEINkPvPmUlAoGAT6nXNJK/PLZa3fAx8SMP\n",
    "v4xfVS0lasKrgV4/DTbELAlbrxK4XPAleRSdSGAJ4lZQ9DKWGtZ3baq7p23LiCLj\n",
    "ZhaHPtXvWB5sIHSu/zPM8pmZDzYdiezWuBCuDFIQYtI0M6Uk4cHrhX2kUSjRlQjJ\n",
    "GITmDHJetOhY7rJSbQdh8Ng=\n",
    "-----END ",
    "PRIVATE KEY-----\n",
);

/// A structurally valid but unrelated key: it must not satisfy the certificate/key pair check.
const OTHER_PRIVATE_KEY: &str = concat!(
    "-----BEGIN ",
    "PRIVATE KEY-----\n",
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDao2SJjUYGSnVT\n",
    "Te8TbOu6RXAsUga6Hdtx3Oc43PGOc44xmgpFbF+rhgV+1mFepN/vFwscsRsWuAdW\n",
    "ejHNworwj3ybqhZz94i8e3NTvHyUi8YxpxdDPvJdSWeyx7DsXRogQnJG9RqnNt4m\n",
    "bbtrcnpYWQN6jKavQSxJDyLJaQvGPDBE1Rkv5HlgJ33ognxAxfjD36QkkPe+byQp\n",
    "dzYl59R07uoCpCsxCHxpowPOjnuvfjQ3pyR6raFjb9hvfUe/2QMuwO3jSKOzX8pM\n",
    "FEWIIdknFpUuSp2hs42RzbGvDglIHDrmTHXMyQLwMJi5Hg4rbFRV9TLu2woPBkLK\n",
    "ll1pUeT9AgMBAAECggEAFdXsME2m8PFmQs3dgu3lpAqTz6VYjSV2uWozwIrWaCDz\n",
    "0lHdVT4j1uRRb6+29UYXpFADmNe6ShxShUk6aJ+Vkz1tVzmXOPk/k31r0PDZ61cD\n",
    "UgmrSdjDSVxPqjwF2DFbLt4b/ii0Av+4k5NxfKNoAyNOtOJPsmCarOhBU+a1GZTR\n",
    "fTFfkACjUAONg1c6iiFolJLQX7T0h2/v5HMfwP3y4yQ2DNjORsVI0f8VVfudDoJ1\n",
    "Gx1ui+U0HoHygzwy7+NEeylolfW4w177YayDCCYfLzjPbuEZrGo26uCxHmuoHo7b\n",
    "rv7qcH+lD7Uuxw5+I5woKaK8TioNHm5gAzsG9kh0CQKBgQD2JLv6fmvMu2m2MsJC\n",
    "X75fxUMGpGLLrMuWvFgba9eCTlsX16kI926QYEB/PLjN5r4v/R2CfJPBT0PPm0lB\n",
    "SQsI/gPXFyflbsW7jO6ImaoF5+vy1BgeDgc384hjFBlxv0w3NmEMyh1WVk+5HAyX\n",
    "jpjkNLfGldh5c79uwU193CzYFQKBgQDjZLJfIDrLz2OJgYbGVkBZ5bYM0shS/WjK\n",
    "9tNa+9zBigHEnPrB3miRh44ieS0kara0CSgmFOnQwhAWgtdfBVJqsyS6IDeYfdpH\n",
    "qyfIiqW64siNz5n1S2ri8nIrRc6QO0hzjd5PYqsk1BFpl64Attf24UQTG2dnqplj\n",
    "Bt4v07nrSQKBgQDW5x2kR6pQ1rQmGk0W7EbnkO/DJdUIJLafxZNbZZ2ELGtF9smj\n",
    "hXxn21GUhWyIgNQ+S8zu91t9pHn9EYQ01tQmpritm47+tuc2p4Y/h4I1o9aSbXEd\n",
    "FHxi8mJ6trq8YBvn/LdhFjnk/niekom/7QU6AXkOjhexekiCJ41DvO7+PQKBgFjs\n",
    "vyieNQARGU7j3W3guwes4nW/VGHIAdwljF/vUNRLAQf/j7yTGneW+EmY88NjDBH5\n",
    "5r6FvS5LRflXr5vUO/fIGNvEz5kN1nfiggtV1RvxphZ3EjEwDhu0TluH0BDtbhbq\n",
    "av7GikE7wZd2nrBe0LQWQgXq2JRczeFBBVDUzscpAoGAN8y0/hrWyGHl/coA8Hpq\n",
    "yEOYv91XECx4a69dvvWZvT0DzH4TwEX3q/inSy1L2g8RDGvuuSrbVJfnlgi1iUDw\n",
    "P5K84TFHaBwR6PIVXDabhkJZ3gwfbhKGGeNPFiXRO1TXQQOCdEthfOEK4HCJfoST\n",
    "/aX3pXiJSef9lEGdn6b6mr8=\n",
    "-----END ",
    "PRIVATE KEY-----\n",
);

fn srv() -> Server {
    Server {
        id: ServerId("node-1".into()),
        address: "203.0.113.7".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("trusttunnel".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn user(id: &str, uuid: &str) -> User {
    User {
        id: UserId(id.into()),
        uuid: uuid.into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

fn disabled_user(id: &str, uuid: &str) -> User {
    let mut out = user(id, uuid);
    out.disabled = true;
    out
}

fn alice() -> User {
    user("alice", ALICE_UUID)
}

fn secrets(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

fn pin_hex() -> String {
    "cd".repeat(32)
}

fn pin_b64() -> String {
    STANDARD.encode([0xcd; 32])
}

fn managed(extra: &[(&str, &str)]) -> HashMap<String, String> {
    let mut out = secrets(extra);
    out.insert("observed.tls.cert_public_key_sha256".into(), pin_hex());
    out
}

fn custom(extra: &[(&str, &str)]) -> HashMap<String, String> {
    let mut out = secrets(extra);
    out.insert("trusttunnel.domain".into(), DOMAIN.into());
    out.insert("trusttunnel.certificate".into(), CERTIFICATE.into());
    out.insert("trusttunnel.key".into(), PRIVATE_KEY.into());
    out
}

fn inbound(server: &Server, settings: &HashMap<String, String>, users: &[User]) -> Value {
    let ctx = RenderCtx::new(server, settings);
    TrustTunnel
        .server_inbound(&ctx, users)
        .expect("TrustTunnel inbound must render")
}

fn client(server: &Server, settings: &HashMap<String, String>, user: &User) -> Value {
    let ctx = RenderCtx::new(server, settings);
    TrustTunnel
        .client_config(&ctx, user)
        .expect("TrustTunnel outbound must render")
}

fn link(server: &Server, settings: &HashMap<String, String>, user: &User) -> String {
    let ctx = RenderCtx::new(server, settings);
    TrustTunnel
        .share_link(&ctx, user)
        .expect("TrustTunnel share link must render")
}

fn usernames(value: &Value) -> Vec<&str> {
    value
        .get("users")
        .and_then(Value::as_array)
        .expect("users must be an array")
        .iter()
        .map(|user| {
            user.get("username")
                .and_then(Value::as_str)
                .expect("user must have a username")
        })
        .collect()
}

fn assert_inbound_rejected(label: &str, settings: &HashMap<String, String>) {
    let server = srv();
    let ctx = RenderCtx::new(&server, settings);
    assert!(
        TrustTunnel.validate_server(&ctx).is_err(),
        "{label}: validate_server must reject invalid TLS settings"
    );
    assert!(
        TrustTunnel.server_inbound(&ctx, &[alice()]).is_err(),
        "{label}: server_inbound must reject invalid TLS settings"
    );
}

#[test]
fn tt1_id_and_default_listener_are_tcp_and_udp_8444() {
    let protocol = TrustTunnel;
    assert_eq!(protocol.id(), ProtocolId("trusttunnel".into()));
    assert_eq!(protocol.listen_ports(), &[("tcp", 8444), ("udp", 8444)]);
    assert_eq!(
        protocol.effective_listen_ports(&HashMap::new()),
        vec![("tcp", 8444), ("udp", 8444)]
    );
    assert!(
        !protocol.appears_in_sing_box_sub(),
        "legacy sing-box subscriptions must exclude TrustTunnel"
    );
    assert!(
        !protocol.appears_in_stock_sing_box_sub(),
        "stock sing-box cannot render TrustTunnel"
    );
}

#[test]
fn tt2_inbound_defaults_match_the_managed_server_contract() {
    let server = srv();
    let settings = HashMap::new();
    let value = inbound(&server, &settings, &[alice(), user("bob", BOB_UUID)]);

    assert_eq!(
        value.get("type").and_then(Value::as_str),
        Some("trusttunnel")
    );
    assert_eq!(
        value.get("tag").and_then(Value::as_str),
        Some("trusttunnel-in")
    );
    assert_eq!(value.get("listen").and_then(Value::as_str), Some("::"));
    assert_eq!(value.get("listen_port").and_then(Value::as_u64), Some(8444));
    assert_eq!(value.get("quic").and_then(Value::as_bool), Some(true));
    assert_eq!(value.get("udp").and_then(Value::as_bool), Some(true));
    assert_eq!(
        value.get("users"),
        Some(&json!([
            {"username": "alice", "password": ALICE_UUID},
            {"username": "bob", "password": BOB_UUID},
        ]))
    );
    assert_eq!(
        value.pointer("/tls/enabled").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        value
            .pointer("/tls/certificate_path")
            .and_then(Value::as_str),
        Some("/etc/sing-box/cert.pem")
    );
    assert_eq!(
        value.pointer("/tls/key_path").and_then(Value::as_str),
        Some("/etc/sing-box/key.pem")
    );
}

#[test]
fn tt2_inbound_honors_port_and_tuic_certificate_paths() {
    let server = srv();
    let settings = secrets(&[
        ("trusttunnel.listen_port", "9443"),
        ("trusttunnel.quic", "false"),
        ("trusttunnel.udp", "false"),
        ("tuic.cert_path", "/srv/keys/trusttunnel.crt"),
        ("tuic.key_path", "/srv/keys/trusttunnel.key"),
    ]);
    let value = inbound(&server, &settings, &[alice()]);

    assert_eq!(value.get("listen_port").and_then(Value::as_u64), Some(9443));
    assert_eq!(value.get("quic").and_then(Value::as_bool), Some(false));
    assert_eq!(value.get("udp").and_then(Value::as_bool), Some(false));
    assert_eq!(
        value
            .pointer("/tls/certificate_path")
            .and_then(Value::as_str),
        Some("/srv/keys/trusttunnel.crt")
    );
    assert_eq!(
        value.pointer("/tls/key_path").and_then(Value::as_str),
        Some("/srv/keys/trusttunnel.key")
    );
}

#[test]
fn tt2_inbound_drops_disabled_invalid_empty_colon_and_duplicate_users() {
    let server = srv();
    let settings = HashMap::new();
    let users = [
        disabled_user("disabled", BOB_UUID),
        user("bad-uuid", "not-a-uuid"),
        user("", ALICE_UUID),
        user("alice:ops", BOB_UUID),
        alice(),
        user("alice", BOB_UUID),
        user("bob", BOB_UUID),
    ];
    let value = inbound(&server, &settings, &users);

    assert_eq!(usernames(&value), vec!["alice", "bob"]);
    let rendered = value
        .get("users")
        .and_then(Value::as_array)
        .expect("users must be an array");
    assert_eq!(rendered.len(), 2);
    assert_eq!(
        rendered[0].get("password").and_then(Value::as_str),
        Some(ALICE_UUID),
        "the first user with a duplicated name wins"
    );
}

#[test]
fn tt2_inbound_custom_certificate_renders_pem_arrays_without_paths() {
    let server = srv();
    let settings = custom(&[]);
    let ctx = RenderCtx::new(&server, &settings);
    TrustTunnel
        .validate_server(&ctx)
        .expect("matching custom certificate and key must validate");
    let value = inbound(&server, &settings, &[alice()]);

    assert_eq!(
        value.pointer("/tls/enabled").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        value.pointer("/tls/certificate"),
        Some(&json!(CERTIFICATE.lines().collect::<Vec<_>>()))
    );
    assert_eq!(
        value.pointer("/tls/key"),
        Some(&json!(PRIVATE_KEY.lines().collect::<Vec<_>>()))
    );
    assert!(
        value.pointer("/tls/certificate_path").is_none(),
        "custom TLS must not also point at the managed certificate"
    );
    assert!(
        value.pointer("/tls/key_path").is_none(),
        "custom TLS must not also point at the managed key"
    );
}

#[test]
fn tt2_custom_tls_requires_domain_matching_pair_and_unencrypted_key() {
    let mut settings = custom(&[]);
    settings.remove("trusttunnel.domain");
    assert_inbound_rejected("custom TLS without a domain", &settings);

    let mut settings = custom(&[]);
    settings.insert("trusttunnel.domain".into(), "203.0.113.7".into());
    assert_inbound_rejected("custom TLS with an IP domain", &settings);

    let mut settings = custom(&[]);
    settings.insert("trusttunnel.domain".into(), "not a hostname".into());
    assert_inbound_rejected("custom TLS with an invalid domain", &settings);

    let mut settings = custom(&[]);
    settings.insert("trusttunnel.domain".into(), "other.example.test".into());
    assert_inbound_rejected(
        "certificate SAN does not cover the custom domain",
        &settings,
    );

    let mut settings = custom(&[]);
    settings.remove("trusttunnel.certificate");
    assert_inbound_rejected("custom key without certificate", &settings);

    let mut settings = custom(&[]);
    settings.remove("trusttunnel.key");
    assert_inbound_rejected("custom certificate without key", &settings);

    let mut settings = custom(&[]);
    settings.insert("trusttunnel.certificate".into(), "not a PEM chain".into());
    assert_inbound_rejected("malformed certificate PEM", &settings);

    let mut settings = custom(&[]);
    settings.insert("trusttunnel.key".into(), "not a PEM key".into());
    assert_inbound_rejected("malformed private key PEM", &settings);

    let mut settings = custom(&[]);
    settings.insert(
        "trusttunnel.key".into(),
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nZmFrZQ==\n-----END ENCRYPTED PRIVATE KEY-----\n"
            .into(),
    );
    assert_inbound_rejected("encrypted private key", &settings);

    let mut settings = custom(&[]);
    settings.insert("trusttunnel.key".into(), OTHER_PRIVATE_KEY.into());
    assert_inbound_rejected("certificate and key from different pairs", &settings);
}

#[test]
fn tt3_outbound_managed_tls_uses_base64_spki_pin_and_bool_flags() {
    let server = srv();
    let settings = managed(&[]);
    let value = client(&server, &settings, &alice());

    assert_eq!(
        value.get("type").and_then(Value::as_str),
        Some("trusttunnel")
    );
    assert_eq!(
        value.get("tag").and_then(Value::as_str),
        Some("trusttunnel-out")
    );
    assert_eq!(
        value.get("server").and_then(Value::as_str),
        Some("203.0.113.7")
    );
    assert_eq!(value.get("server_port").and_then(Value::as_u64), Some(8444));
    assert_eq!(value.get("username").and_then(Value::as_str), Some("alice"));
    assert_eq!(
        value.get("password").and_then(Value::as_str),
        Some(ALICE_UUID)
    );
    assert_eq!(
        value.pointer("/tls/enabled").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        value.pointer("/tls/server_name").and_then(Value::as_str),
        Some("203.0.113.7")
    );
    assert_eq!(
        value.pointer("/tls/certificate_public_key_sha256"),
        Some(&json!([pin_b64()]))
    );
    assert_eq!(value.get("quic").and_then(Value::as_bool), Some(false));
    assert_eq!(value.get("udp").and_then(Value::as_bool), Some(true));
    assert_eq!(
        value.get("health_check").and_then(Value::as_bool),
        Some(true)
    );
}

#[test]
fn tt3_outbound_server_uses_custom_domain_and_sni_priority() {
    let server = srv();
    let user = alice();

    let settings = managed(&[("tls.server_name", "cdn.example.org")]);
    let value = client(&server, &settings, &user);
    assert_eq!(
        value.get("server").and_then(Value::as_str),
        Some("203.0.113.7")
    );
    assert_eq!(
        value.pointer("/tls/server_name").and_then(Value::as_str),
        Some("cdn.example.org")
    );

    let settings = managed(&[("trusttunnel.sni", "tt.example.org")]);
    let value = client(&server, &settings, &user);
    assert_eq!(
        value.pointer("/tls/server_name").and_then(Value::as_str),
        Some("tt.example.org"),
        "trusttunnel.sni must be used when no custom domain is configured"
    );

    let settings = managed(&[
        ("tls.server_name", "cdn.example.org"),
        ("trusttunnel.sni", "tt.example.org"),
    ]);
    let value = client(&server, &settings, &user);
    assert_eq!(
        value.pointer("/tls/server_name").and_then(Value::as_str),
        Some("tt.example.org"),
        "trusttunnel.sni must override tls.server_name"
    );

    let settings = managed(&[("trusttunnel.domain", DOMAIN)]);
    let ctx = RenderCtx::new(&server, &settings);
    assert!(TrustTunnel.client_config(&ctx, &user).is_err());
    assert!(TrustTunnel.share_link(&ctx, &user).is_err());

    let settings = custom(&[
        ("tls.server_name", "cdn.example.org"),
        ("trusttunnel.sni", "tt.example.org"),
    ]);
    let value = client(&server, &settings, &user);
    assert_eq!(value.get("server").and_then(Value::as_str), Some(DOMAIN));
    assert_eq!(
        value.pointer("/tls/server_name").and_then(Value::as_str),
        Some(DOMAIN),
        "the custom domain must drive both server and server_name"
    );
}

#[test]
fn tt3_outbound_rejects_missing_or_malformed_managed_pin() {
    let server = srv();
    let user = alice();
    let pins: Vec<Option<String>> = vec![
        None,
        Some(String::new()),
        Some("zz".repeat(32)),
        Some("cd".repeat(31)),
        Some("cd".repeat(33)),
        Some("abc".into()),
    ];

    for pin in pins {
        let mut settings = HashMap::new();
        if let Some(pin) = &pin {
            settings.insert("observed.tls.cert_public_key_sha256".into(), pin.clone());
        }
        let ctx = RenderCtx::new(&server, &settings);
        assert!(
            TrustTunnel.client_config(&ctx, &user).is_err(),
            "managed outbound must reject pin {pin:?}"
        );
        assert!(
            TrustTunnel.share_link(&ctx, &user).is_err(),
            "managed share link must reject pin {pin:?}"
        );
    }
}

#[test]
fn tt3_outbound_custom_certificate_never_uses_a_pin() {
    let server = srv();
    let mut settings = custom(&[]);
    settings.insert("observed.tls.cert_public_key_sha256".into(), pin_hex());
    let value = client(&server, &settings, &alice());

    assert_eq!(value.get("server").and_then(Value::as_str), Some(DOMAIN));
    assert_eq!(
        value.pointer("/tls/server_name").and_then(Value::as_str),
        Some(DOMAIN)
    );
    assert_eq!(
        value["tls"],
        json!({"enabled": true, "server_name": DOMAIN}),
        "custom TLS uses system CA verification"
    );
    assert!(
        value
            .pointer("/tls/certificate_public_key_sha256")
            .is_none(),
        "custom certificates must not be pinned"
    );
    assert!(
        !link(&server, &settings, &alice()).contains("pk_sha256"),
        "custom certificate links must not carry pk_sha256"
    );
}

#[test]
fn tt3_outbound_honors_port_and_client_quic() {
    let server = srv();
    let settings = managed(&[
        ("trusttunnel.listen_port", "9443"),
        ("trusttunnel.client_quic", "true"),
    ]);
    let value = client(&server, &settings, &alice());
    assert_eq!(value.get("server_port").and_then(Value::as_u64), Some(9443));
    assert_eq!(value.get("quic").and_then(Value::as_bool), Some(true));

    let link = link(&server, &settings, &alice());
    assert!(
        link.contains("@203.0.113.7:9443?"),
        "share link must use the configured port; got {link}"
    );
    assert!(
        link.contains("quic=1"),
        "share link must reflect client_quic=true; got {link}"
    );
}

#[test]
fn tt4_share_link_default_managed_tls_is_exact() {
    let server = srv();
    let settings = managed(&[]);
    let link = link(&server, &settings, &alice());

    assert_eq!(
        link,
        format!(
            "trusttunnel://alice:{ALICE_UUID}@203.0.113.7:8444?sni=203.0.113.7&quic=0&udp=1&pk_sha256={}#alice",
            pin_hex()
        )
    );
}

#[test]
fn tt4_share_link_percent_encodes_userinfo_and_label() {
    let server = srv();
    let settings = managed(&[]);
    let user = user("alice ops", ALICE_UUID);
    let link = link(&server, &settings, &user);

    assert!(
        link.starts_with(&format!(
            "trusttunnel://alice%20ops:{ALICE_UUID}@203.0.113.7:8444?"
        )),
        "space in the username must be percent-encoded; got {link}"
    );
    assert!(
        link.ends_with("#alice%20ops"),
        "space in the label must be percent-encoded; got {link}"
    );
    assert!(!link.contains("alice ops"), "raw username leaked: {link}");
}

#[test]
fn tt5_port_and_boolean_settings_are_strictly_validated() {
    let server = srv();

    for bad in ["0", "65536", "-1", "abc", ""] {
        let settings = secrets(&[("trusttunnel.listen_port", bad)]);
        let ctx = RenderCtx::new(&server, &settings);
        assert!(
            TrustTunnel.server_inbound(&ctx, &[alice()]).is_err(),
            "listen_port {bad:?} must be rejected"
        );
    }

    for good in ["1", "65535"] {
        let settings = secrets(&[("trusttunnel.listen_port", good)]);
        let expected: u64 = good.parse().expect("test port must parse");
        let value = inbound(&server, &settings, &[alice()]);
        assert_eq!(
            value.get("listen_port").and_then(Value::as_u64),
            Some(expected),
            "listen_port {good:?} must be accepted"
        );
    }

    for key in ["trusttunnel.quic", "trusttunnel.udp"] {
        for bad in ["1", "0", "TRUE", "yes", "on", ""] {
            let settings = secrets(&[(key, bad)]);
            let ctx = RenderCtx::new(&server, &settings);
            assert!(
                TrustTunnel.server_inbound(&ctx, &[alice()]).is_err(),
                "{key}={bad:?} must be rejected"
            );
        }
    }

    for bad in ["1", "0", "TRUE", "yes", "on", ""] {
        let settings = managed(&[("trusttunnel.client_quic", bad)]);
        let ctx = RenderCtx::new(&server, &settings);
        assert!(
            TrustTunnel.client_config(&ctx, &alice()).is_err(),
            "trusttunnel.client_quic={bad:?} must be rejected"
        );
    }
}

#[test]
fn tt5_invalid_custom_domain_is_rejected_for_managed_tls_too() {
    let server = srv();
    for bad in [
        "not a hostname",
        "203.0.113.7",
        "bad..example",
        "vpn.example.test:443",
    ] {
        let settings = managed(&[("trusttunnel.domain", bad)]);
        let ctx = RenderCtx::new(&server, &settings);
        assert!(
            TrustTunnel.client_config(&ctx, &alice()).is_err(),
            "trusttunnel.domain={bad:?} must be rejected"
        );
    }
}

#[test]
fn tt6_ipv6_share_link_authority_is_bracketed() {
    let mut server = srv();
    server.address = "2a00:1450::1".into();
    let settings = managed(&[]);
    let link = link(&server, &settings, &alice());

    assert!(
        link.contains("@[2a00:1450::1]:8444?"),
        "IPv6 authority must be bracketed; got {link}"
    );
    let value = client(&server, &settings, &alice());
    assert_eq!(
        value.get("server").and_then(Value::as_str),
        Some("2a00:1450::1"),
        "the native outbound uses the bare address"
    );
}
