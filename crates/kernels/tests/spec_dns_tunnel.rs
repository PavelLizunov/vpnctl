#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Spec tests for `vpnctl_kernels::DnsTunnel` — the slipstream-rust
//! DNS-over-НСДИ last-resort kernel. Written from the spec only:
//! non-empty supported_protocols, the two-file bundle (slipstream env +
//! loopback VLESS), the loopback-only forward-target guard, the engine
//! seam. If a test fails, the impl is wrong — DO NOT weaken the test.

use std::collections::HashMap;

use vpnctl_core::{
    CoreError, Kernel, KernelId, Protocol, ProtocolId, RenderCtx, Server, ServerId, User, UserId,
};
use vpnctl_kernels::DnsTunnel;
use vpnctl_protocols::DnsTunnel as DnsTunnelProto;

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

fn render(sec: &HashMap<String, String>, users: &[User]) -> vpnctl_core::Result<String> {
    let s = srv();
    let ctx = RenderCtx::new(&s, sec);
    let proto = DnsTunnelProto::new();
    let protos: Vec<&dyn Protocol> = vec![&proto];
    DnsTunnel::new()
        .render_config(&ctx, users, &protos)
        .map(|b| String::from_utf8(b).unwrap())
}

/// Pull the sing-box JSON member out of the multi-file bundle. The bundle
/// format (mirrors wgturn) frames each file with a `====FILE: <path>====`
/// marker line; the sing-box config is the last member, after
/// `/etc/dns-tunnel/tunnel-sb.json`. Returns its raw bytes so the test can
/// `serde_json::from_slice` and assert on the structured `users[]`.
fn extract_sb_json(bundle: &str) -> Vec<u8> {
    let marker = "====FILE: /etc/dns-tunnel/tunnel-sb.json====";
    let after = bundle
        .split_once(marker)
        .unwrap_or_else(|| panic!("sing-box bundle marker missing:\n{bundle}"))
        .1;
    // Drop the leading newline after the marker line; the rest (to EOF) is
    // the JSON member (it's the final file in the bundle).
    after.trim_start_matches('\n').as_bytes().to_vec()
}

#[test]
fn id_is_dns_tunnel() {
    assert_eq!(DnsTunnel::new().id(), KernelId("dns-tunnel".into()));
}

#[test]
fn supported_protocols_is_non_empty_singleton() {
    // LOAD-BEARING: an empty supported_protocols() means the kernel is
    // silently never configured/started by deploy + admin.
    let protos = DnsTunnel::new().supported_protocols();
    assert_eq!(protos.len(), 1, "must be non-empty");
    assert_eq!(protos[0], ProtocolId("dns-tunnel".into()));
}

#[test]
fn render_requires_the_dns_tunnel_protocol() {
    let s = srv();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let err = DnsTunnel::new().render_config(&ctx, &[], &[]).unwrap_err();
    assert!(format!("{err}").contains("dns-tunnel protocol"));
}

#[test]
fn render_emits_both_bundle_file_markers() {
    let sec = secrets();
    let body = render(&sec, &[]).unwrap();
    assert!(
        body.contains("====FILE: /etc/dns-tunnel/slipstream.env===="),
        "slipstream env marker missing:\n{body}"
    );
    assert!(
        body.contains("====FILE: /etc/dns-tunnel/tunnel-sb.json===="),
        "sing-box config marker missing:\n{body}"
    );
}

#[test]
fn render_emits_slipstream_flags_and_loopback_forward() {
    let sec = secrets();
    let body = render(&sec, &[]).unwrap();
    // slipstream-server flags (via the EnvironmentFile shape).
    assert!(
        body.contains("SLIPSTREAM_LISTEN_PORT=53"),
        "listen port:\n{body}"
    );
    assert!(
        body.contains("SLIPSTREAM_FORWARD_TARGET=127.0.0.1:9001"),
        "forward target:\n{body}"
    );
    assert!(
        body.contains("SLIPSTREAM_DOMAIN=t.example.com"),
        "domain:\n{body}"
    );
}

#[test]
fn render_emits_loopback_vless_inbound_with_uuid() {
    let sec = secrets();
    let body = render(&sec, &[]).unwrap();
    // The dedicated loopback-only TLS-less VLESS inbound.
    assert!(
        body.contains("\"type\": \"vless\""),
        "vless inbound:\n{body}"
    );
    assert!(
        body.contains("\"listen\": \"127.0.0.1\""),
        "loopback listen:\n{body}"
    );
    assert!(
        body.contains("\"listen_port\": 9001"),
        "loopback port:\n{body}"
    );
    assert!(body.contains(UUID), "wrapped loopback UUID:\n{body}");
    // The PoC inbound is TLS-less (tunnel already encrypts) — no tls block.
    assert!(!body.contains("\"tls\""), "must be TLS-less:\n{body}");
}

#[test]
fn render_rejects_non_loopback_forward_target() {
    let mut sec = secrets();
    sec.insert(
        "dns-tunnel:forward_target".into(),
        "203.0.113.9:9001".into(),
    );
    let err = render(&sec, &[]).unwrap_err();
    match err {
        CoreError::Render(m) => {
            assert!(m.contains("forward_target"), "msg: {m}");
            assert!(m.contains("loopback"), "msg: {m}");
        }
        other => panic!("expected Render, got {other:?}"),
    }
}

#[test]
fn render_accepts_loopback_forward_target_override() {
    let mut sec = secrets();
    sec.insert("dns-tunnel:forward_target".into(), "127.0.0.5:9100".into());
    let body = render(&sec, &[]).unwrap();
    assert!(body.contains("SLIPSTREAM_FORWARD_TARGET=127.0.0.5:9100"));
    assert!(
        body.contains("\"listen\": \"127.0.0.5\""),
        "inbound host:\n{body}"
    );
    assert!(
        body.contains("\"listen_port\": 9100"),
        "inbound port:\n{body}"
    );
}

#[test]
fn render_missing_domain_is_error() {
    let mut sec = secrets();
    sec.remove("dns-tunnel:domain");
    let err = render(&sec, &[]).unwrap_err();
    assert!(format!("{err}").contains("dns-tunnel:domain"));
}

#[test]
fn render_zero_users_and_no_loopback_uuid_is_error() {
    // With NEITHER any granted user NOR the fallback loopback_uuid secret,
    // the loopback inbound would have zero users — a misconfiguration. The
    // kernel must fail closed with a clear Render error that names both
    // remediation paths (grant a user OR set the fallback secret).
    let mut sec = secrets();
    sec.remove("dns-tunnel:loopback_uuid");
    let err = render(&sec, &[]).unwrap_err();
    match err {
        CoreError::Render(m) => {
            assert!(m.contains("no users"), "msg: {m}");
            assert!(m.contains("dns-tunnel:loopback_uuid"), "msg: {m}");
        }
        other => panic!("expected CoreError::Render, got {other:?}"),
    }
}

#[test]
fn render_zero_users_but_loopback_uuid_set_keeps_backward_compat() {
    // The LIVE box-213 shape: 0 granted users + the fallback
    // `dns-tunnel:loopback_uuid` (e09b09af-…) set. The inbound must carry
    // exactly the 1 loopback entry — the e09b09af deploy keeps working.
    let sec = secrets(); // loopback_uuid = UUID
    let body = render(&sec, &[]).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&extract_sb_json(&body)).unwrap();
    let users = v["inbounds"][0]["users"].as_array().unwrap();
    assert_eq!(users.len(), 1, "exactly the loopback fallback entry");
    assert_eq!(users[0]["uuid"], UUID);
    // PLAIN VLESS — no flow on the loopback entry.
    assert!(
        users[0].get("flow").is_none(),
        "loopback entry must be plain"
    );
}

#[test]
fn render_two_granted_users_emits_both_uuids() {
    // The per-user core: two GRANTED users → the loopback inbound's users[]
    // carries BOTH of their UUIDs (the same uuid each user has for VLESS).
    // No loopback fallback secret here — granted users alone satisfy the
    // non-empty guard.
    let mut sec = secrets();
    sec.remove("dns-tunnel:loopback_uuid");
    let alice = user("alex");
    let bob = user("bob");
    let body = render(&sec, &[alice.clone(), bob.clone()]).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&extract_sb_json(&body)).unwrap();
    let users = v["inbounds"][0]["users"].as_array().unwrap();
    assert_eq!(users.len(), 2, "both granted users present: {users:?}");
    let got: std::collections::HashSet<&str> =
        users.iter().map(|u| u["uuid"].as_str().unwrap()).collect();
    assert!(
        got.contains(alice.uuid.as_str()),
        "alex uuid missing: {got:?}"
    );
    assert!(got.contains(bob.uuid.as_str()), "bob uuid missing: {got:?}");
    // PLAIN VLESS entries — no flow, no reality (tunnel encrypts).
    for u in users {
        assert!(
            u.get("flow").is_none(),
            "per-user entry must be plain VLESS: {u}"
        );
    }
}

#[test]
fn render_granted_users_plus_loopback_uuid_are_deduplicated() {
    // granted users AND the loopback fallback set → all present, and if the
    // loopback uuid equals a granted user's uuid it is NOT double-listed.
    // Use a granted user whose uuid IS the loopback UUID + one distinct
    // user, plus the loopback secret set to UUID.
    let sec = secrets(); // loopback_uuid = UUID
    let mut same_as_loopback = user("dup");
    same_as_loopback.uuid = UUID.to_string();
    let distinct = user("alex"); // uuid-alex
    let body = render(&sec, &[same_as_loopback, distinct.clone()]).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&extract_sb_json(&body)).unwrap();
    let users = v["inbounds"][0]["users"].as_array().unwrap();
    let got: Vec<&str> = users.iter().map(|u| u["uuid"].as_str().unwrap()).collect();
    // Exactly two distinct entries: the shared UUID once + the distinct one.
    assert_eq!(
        users.len(),
        2,
        "loopback uuid must not be double-listed: {got:?}"
    );
    assert_eq!(
        got.iter().filter(|&&u| u == UUID).count(),
        1,
        "the loopback uuid appears exactly once: {got:?}"
    );
    assert!(
        got.contains(&distinct.uuid.as_str()),
        "distinct user missing: {got:?}"
    );
}

#[test]
fn render_rejects_non_numeric_listen_port() {
    let mut sec = secrets();
    sec.insert("dns-tunnel:listen_port".into(), "not-a-port".into());
    let err = render(&sec, &[]).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("dns-tunnel:listen_port"), "msg: {msg}");
    assert!(msg.contains("not-a-port"), "msg: {msg}");
}

#[test]
fn render_emits_default_idle_timeout_180() {
    // With no `dns-tunnel:idle_timeout_seconds` secret the relay env +
    // ExecStart carry the deliberate 180s bump (from upstream's 60s).
    let sec = secrets();
    let body = render(&sec, &[]).unwrap();
    assert!(
        body.contains("SLIPSTREAM_IDLE_TIMEOUT_SECONDS=180"),
        "default idle-timeout env var missing:\n{body}"
    );
}

#[test]
fn render_honours_idle_timeout_override() {
    let mut sec = secrets();
    sec.insert("dns-tunnel:idle_timeout_seconds".into(), "300".into());
    let body = render(&sec, &[]).unwrap();
    assert!(
        body.contains("SLIPSTREAM_IDLE_TIMEOUT_SECONDS=300"),
        "idle-timeout override not honoured:\n{body}"
    );
    assert!(
        !body.contains("SLIPSTREAM_IDLE_TIMEOUT_SECONDS=180"),
        "default leaked alongside override:\n{body}"
    );
}

#[test]
fn render_rejects_non_numeric_idle_timeout() {
    let mut sec = secrets();
    sec.insert("dns-tunnel:idle_timeout_seconds".into(), "forever".into());
    let err = render(&sec, &[]).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("dns-tunnel:idle_timeout_seconds"),
        "msg: {msg}"
    );
    assert!(msg.contains("forever"), "msg: {msg}");
}

#[test]
fn render_rejects_zero_idle_timeout() {
    // 0 disables the idle timeout in slipstream — never wanted here.
    let mut sec = secrets();
    sec.insert("dns-tunnel:idle_timeout_seconds".into(), "0".into());
    let err = render(&sec, &[]).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("dns-tunnel:idle_timeout_seconds"),
        "msg: {msg}"
    );
    assert!(msg.contains("1..=65535"), "msg: {msg}");
}

#[test]
fn render_config_rejects_domain_with_newline_injection() {
    // A newline in the operator-set domain would forge a second
    // `KEY=value` line in the slipstream EnvironmentFile (env-file line
    // injection) — here a bogus `EVIL=1`. The guard must fail closed and
    // the injected env line must NEVER reach the rendered bundle.
    // Mirrors caddy's `render_rejects_domain_with_injection`.
    let mut sec = secrets();
    sec.insert("dns-tunnel:domain".into(), "t.example.com\nEVIL=1".into());
    let result = render(&sec, &[]);
    match &result {
        Err(CoreError::Render(m)) => {
            assert!(m.contains("dns-tunnel:domain"), "msg: {m}");
        }
        other => panic!("expected CoreError::Render, got {other:?}"),
    }
    // The forged `EVIL=1` env line must NEVER reach a rendered bundle. On
    // the (asserted) error path there is no output at all; this guards
    // against a future regression that lets the bad domain render anyway.
    if let Ok(body) = &result {
        assert!(
            !body.contains("EVIL="),
            "forged env line leaked into rendered bundle:\n{body}"
        );
    }
}

#[test]
fn render_config_rejects_control_char_domain() {
    // `is_control()` is the load-bearing check — an embedded NUL is not
    // whitespace and not in the ILLEGAL set, but is still illegal in a
    // hostname destined for an EnvironmentFile + command line.
    let mut sec = secrets();
    sec.insert("dns-tunnel:domain".into(), "t.example\0.com".into());
    let err = render(&sec, &[]).unwrap_err();
    match err {
        CoreError::Render(m) => assert!(m.contains("dns-tunnel:domain"), "msg: {m}"),
        other => panic!("expected CoreError::Render, got {other:?}"),
    }
}

#[test]
fn render_config_rejects_listen_port_zero() {
    // Port 0 parses as a valid u16 but is OS-ephemeral — unreachable for
    // the :53 delegation the relay fronts. Mirrors
    // `render_rejects_non_numeric_listen_port`.
    let mut sec = secrets();
    sec.insert("dns-tunnel:listen_port".into(), "0".into());
    let err = render(&sec, &[]).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("dns-tunnel:listen_port"), "msg: {msg}");
    assert!(msg.contains("1..=65535"), "msg: {msg}");
}

#[test]
fn render_is_byte_stable_and_lf_only() {
    let sec = secrets();
    let a = render(&sec, &[user("alex")]).unwrap();
    let b = render(&sec, &[user("alex")]).unwrap();
    assert_eq!(a, b, "render not byte-stable");
    assert_eq!(
        a.bytes().filter(|&c| c == b'\r').count(),
        0,
        "CRLF present — must be LF-only"
    );
}

#[test]
fn render_rejects_unknown_engine_loudly() {
    let mut sec = secrets();
    sec.insert("dns-tunnel:engine".into(), "wireguard".into());
    let err = render(&sec, &[]).unwrap_err();
    assert!(
        format!("{err}").contains("unknown engine"),
        "must reject loudly: {err}"
    );
}

#[test]
fn render_dnstt_engine_errors_cleanly_as_placeholder() {
    let mut sec = secrets();
    sec.insert("dns-tunnel:engine".into(), "dnstt".into());
    let err = render(&sec, &[]).unwrap_err();
    match err {
        CoreError::Render(m) => assert_eq!(m, "dns-tunnel engine 'dnstt' not yet implemented"),
        other => panic!("expected clean Render placeholder, got {other:?}"),
    }
}

#[test]
fn render_slipstream_engine_explicit_is_accepted() {
    let mut sec = secrets();
    sec.insert("dns-tunnel:engine".into(), "slipstream".into());
    let body = render(&sec, &[]).unwrap();
    assert!(body.contains("SLIPSTREAM_DOMAIN=t.example.com"));
}
