use super::builder::*;
use super::render::*;
use super::*;
use std::collections::HashMap;
use vpnctl_core::{Server, ServerId, UserId};
use vpnctl_protocols::{Naive, VlessWs};

fn vlessws_secrets() -> HashMap<String, String> {
    let mut s = HashMap::new();
    s.insert("vlessws.domain".into(), "de.ninitux.top".into());
    s.insert("vlessws.acme_email".into(), "admin@ninitux.top".into());
    s.insert("vlessws.path".into(), "Ab3x9Zq2Kp7Lm".into());
    s
}

fn dummy_server() -> Server {
    Server {
        id: ServerId("naive-node-1".into()),
        address: "203.0.113.9".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("caddy".into())],
        enabled_protocols: vec![ProtocolId("naive".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn user(name: &str, pw: Option<&str>) -> User {
    User {
        id: UserId(name.into()),
        uuid: format!("uuid-{name}"),
        tuic_password: pw.map(str::to_string),
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

fn secrets() -> HashMap<String, String> {
    let mut s = HashMap::new();
    s.insert("naive.domain".into(), "cdn.example.com".into());
    s.insert("naive.acme_email".into(), "admin@example.com".into());
    s
}

#[test]
fn id_and_supported_protocols() {
    let c = Caddy::new();
    assert_eq!(c.id(), KernelId("caddy".into()));
    assert_eq!(
        c.supported_protocols(),
        vec![ProtocolId("naive".into()), ProtocolId("vless-ws".into())]
    );
}

#[test]
fn default_cache_path_embeds_version_and_pin() {
    // The cache key MUST carry both versions so a Caddy/forwardproxy
    // bump invalidates a stale prebuilt binary instead of silently
    // uploading the wrong one.
    let s = default_caddy_cache_path().to_string_lossy().into_owned();
    assert!(s.contains(CADDY_VERSION), "missing caddy version: {s}");
    assert!(
        s.contains(FORWARDPROXY_PIN),
        "missing forwardproxy pin: {s}"
    );
    assert!(s.ends_with("-amd64"), "must be arch-stamped: {s}");
}

#[test]
fn build_script_verifies_go_tarball_sha256_before_extraction() {
    let s = caddy_build_script();
    // The pinned SHA-256 is embedded.
    assert!(
        s.contains(GO_TARBALL_SHA256),
        "Go tarball SHA-256 must be pinned in the build script: {s}"
    );
    // Verification uses sha256sum -c BEFORE tar extraction.
    assert!(
        s.contains("sha256sum -c -"),
        "must verify the tarball digest via sha256sum -c: {s}"
    );
    let verify = s
        .find("sha256sum -c -")
        .expect("sha256sum verification missing");
    let extract = s
        .find("tar -C /usr/local -xzf")
        .expect("tar extraction missing");
    assert!(
        verify < extract,
        "SHA-256 verification must happen BEFORE tar extraction: {s}"
    );
    // The constant is a valid 64-char hex SHA-256.
    assert_eq!(GO_TARBALL_SHA256.len(), 64);
    assert!(GO_TARBALL_SHA256.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn caddy_present_only_on_exact_present_token() {
    assert!(caddy_present("present"));
    assert!(caddy_present("present\n"));
    assert!(caddy_present("  present  "));
    assert!(!caddy_present("absent"));
    assert!(!caddy_present(""));
    // A noisy probe (e.g. a banner before the token) is NOT "ready".
    assert!(!caddy_present("present extra"));
}

#[test]
fn caddy_reinstall_is_content_aware_not_presence() {
    let cache = "a".repeat(64);
    // Absent on the node (empty `sha256sum … | cut` output) → reinstall.
    assert!(caddy_needs_reinstall(&cache, ""));
    assert!(caddy_needs_reinstall(&cache, "\n"));
    assert!(caddy_needs_reinstall(&cache, "   "));
    // Present but DIFFERENT bytes (operator refreshed the cache) →
    // reinstall. This is the bug being fixed: a bare presence check
    // would skip here.
    assert!(caddy_needs_reinstall(&cache, &"b".repeat(64)));
    // Present AND identical sha (trailing newline from the node) →
    // skip — idempotent no-op.
    assert!(!caddy_needs_reinstall(&cache, &cache));
    assert!(!caddy_needs_reinstall(&cache, &format!("{cache}\n")));
    assert!(!caddy_needs_reinstall(&cache, &format!("  {cache}  ")));
}

#[test]
fn render_missing_naive_protocol_is_render_error() {
    let s = dummy_server();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let err = Caddy::new().render_config(&ctx, &[], &[]).unwrap_err();
    match err {
        CoreError::Render(m) => assert!(m.contains("naive"), "msg: {m}"),
        other => panic!("expected Render, got {other:?}"),
    }
}

#[test]
fn render_emits_443_catchall_and_per_user_basic_auth() {
    let s = dummy_server();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let naive = Naive::new();
    let users = [user("alice", Some("pw-alice")), user("bob", Some("pw-bob"))];
    let bytes = Caddy::new()
        .render_config(&ctx, &users, &[&naive as &dyn Protocol])
        .unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(text.starts_with("# Rendered by vpnctl"));
    // The load-bearing `:443, <domain>` catch-all matcher.
    assert!(text.contains(":443, cdn.example.com {"), "conf:\n{text}");
    assert!(text.contains("basic_auth alice pw-alice\n"));
    assert!(text.contains("basic_auth bob pw-bob\n"));
    assert!(text.contains("probe_resistance\n"));
    assert!(text.contains("root /var/www/naive-site"));
    assert!(text.contains("tls admin@example.com\n"));
}

#[test]
fn render_skips_users_without_password() {
    let s = dummy_server();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let naive = Naive::new();
    let users = [user("alice", Some("pw-alice")), user("nopass", None)];
    let bytes = Caddy::new()
        .render_config(&ctx, &users, &[&naive as &dyn Protocol])
        .unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert_eq!(text.matches("basic_auth ").count(), 1);
    assert!(!text.contains("nopass"));
}

#[test]
fn render_with_no_users_is_plain_site_no_forward_proxy() {
    let s = dummy_server();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let naive = Naive::new();
    let bytes = Caddy::new()
        .render_config(&ctx, &[], &[&naive as &dyn Protocol])
        .unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    // The global `order forward_proxy before file_server` line is
    // always present (harmless no-op when unused) — assert the proxy
    // BLOCK and its auth/probe directives are what's absent.
    assert!(!text.contains("forward_proxy {"));
    assert!(!text.contains("basic_auth"));
    assert!(!text.contains("probe_resistance"));
    assert!(text.contains("file_server"));
}

#[test]
fn render_missing_domain_secret_is_error() {
    let s = dummy_server();
    let sec = HashMap::new(); // no naive.domain
    let ctx = RenderCtx::new(&s, &sec);
    let naive = Naive::new();
    let err = Caddy::new()
        .render_config(
            &ctx,
            &[user("alice", Some("pw"))],
            &[&naive as &dyn Protocol],
        )
        .unwrap_err();
    // server_inbound's ctx.require("naive.domain") surfaces first.
    assert!(
        matches!(err, CoreError::MissingSecret { .. } | CoreError::Render(_)),
        "expected MissingSecret or Render, got {err:?}"
    );
}

#[test]
fn render_rejects_domain_with_injection() {
    let s = dummy_server();
    let mut sec = HashMap::new();
    sec.insert("naive.domain".into(), "evil.com {\n}\nattacker".into());
    let ctx = RenderCtx::new(&s, &sec);
    let naive = Naive::new();
    let err = Caddy::new()
        .render_config(&ctx, &[user("a", Some("p"))], &[&naive as &dyn Protocol])
        .unwrap_err();
    match err {
        CoreError::Render(m) => assert!(m.contains("illegal")),
        other => panic!("expected Render, got {other:?}"),
    }
}

#[test]
fn render_rejects_acme_email_with_injection() {
    let s = dummy_server();
    let mut sec = HashMap::new();
    sec.insert("naive.domain".into(), "cdn.example.com".into());
    sec.insert("naive.acme_email".into(), "a@b.com\nattacker {".into());
    let ctx = RenderCtx::new(&s, &sec);
    let naive = Naive::new();
    let err = Caddy::new()
        .render_config(&ctx, &[user("a", Some("p"))], &[&naive as &dyn Protocol])
        .unwrap_err();
    match err {
        CoreError::Render(m) => assert!(m.contains("acme_email"), "msg: {m}"),
        other => panic!("expected Render, got {other:?}"),
    }
}

#[test]
fn render_byte_stable_across_runs() {
    let s = dummy_server();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let naive = Naive::new();
    let users = [user("alice", Some("pw-alice"))];
    let a = Caddy::new()
        .render_config(&ctx, &users, &[&naive as &dyn Protocol])
        .unwrap();
    let b = Caddy::new()
        .render_config(&ctx, &users, &[&naive as &dyn Protocol])
        .unwrap();
    assert_eq!(a, b);
}

#[test]
fn render_no_crlf() {
    let s = dummy_server();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let naive = Naive::new();
    let bytes = Caddy::new()
        .render_config(&ctx, &[user("a", Some("p"))], &[&naive as &dyn Protocol])
        .unwrap();
    assert_eq!(bytes.iter().filter(|&&b| b == b'\r').count(), 0);
}

// ───────────────────────── vless-ws ──────────────────────────

#[test]
fn supported_protocols_includes_naive_and_vless_ws() {
    let p = Caddy::new().supported_protocols();
    assert!(p.contains(&ProtocolId("naive".into())));
    assert!(p.contains(&ProtocolId("vless-ws".into())));
}

#[test]
fn vlessws_render_is_a_bundle_with_reverse_proxy_and_singbox() {
    let s = dummy_server();
    let sec = vlessws_secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let proto = VlessWs::new();
    let users = [user("alice", Some("pw"))]; // uuid == "uuid-alice"
    let bytes = Caddy::new()
        .render_config(&ctx, &users, &[&proto as &dyn Protocol])
        .unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    // bundle framing — three members
    assert!(text.starts_with("====FILE: /etc/caddy/Caddyfile===="));
    assert!(text.contains("====FILE: /etc/caddy/vlessws-singbox.json===="));
    assert!(text.contains("====FILE: /etc/caddy/.vlessws-deploy.env===="));
    // Caddyfile: alt-port site + secret-path matcher → reverse_proxy + decoy
    assert!(text.contains("de.ninitux.top:8443 {"), "conf:\n{text}");
    assert!(text.contains("@vlessws path /Ab3x9Zq2Kp7Lm"));
    assert!(text.contains("reverse_proxy @vlessws 127.0.0.1:11443"));
    assert!(text.contains("root /var/www/naive-site"));
    // HTTP/3 disabled so caddy never binds UDP on the front port (would
    // collide with a co-tenant TUIC/hysteria2 QUIC listener).
    assert!(text.contains("protocols h1 h2"));
    // sing-box: ws transport + the user uuid; NO tls, NO flow
    assert!(text.contains("\"path\": \"/Ab3x9Zq2Kp7Lm\""));
    assert!(text.contains("uuid-alice"));
    assert!(!text.contains("xtls-rprx-vision"));
    assert!(!text.contains("\"tls\""));
    // firewall meta carries the front port
    assert!(text.contains("VLESSWS_FRONT_PORT=8443"));
    // no CRLF
    assert_eq!(bytes.iter().filter(|&&b| b == b'\r').count(), 0);
}

#[test]
fn vlessws_no_users_renders_decoy_only_no_proxy() {
    let s = dummy_server();
    let sec = vlessws_secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let proto = VlessWs::new();
    let bytes = Caddy::new()
        .render_config(&ctx, &[], &[&proto as &dyn Protocol])
        .unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(!text.contains("reverse_proxy"));
    assert!(!text.contains("@vlessws"));
    // decoy still served + empty sing-box inbounds (valid, does nothing)
    assert!(text.contains("root /var/www/naive-site"));
    assert!(text.contains("\"inbounds\": []"));
}

#[test]
fn vlessws_front_port_override() {
    let s = dummy_server();
    let mut sec = vlessws_secrets();
    sec.insert("vlessws.listen_port".into(), "2087".into());
    let ctx = RenderCtx::new(&s, &sec);
    let proto = VlessWs::new();
    let bytes = Caddy::new()
        .render_config(&ctx, &[user("a", Some("p"))], &[&proto as &dyn Protocol])
        .unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(text.contains("de.ninitux.top:2087 {"));
    assert!(text.contains("VLESSWS_FRONT_PORT=2087"));
}

#[test]
fn vlessws_render_byte_stable() {
    let s = dummy_server();
    let sec = vlessws_secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let proto = VlessWs::new();
    let users = [user("a", Some("p")), user("b", Some("q"))];
    let a = Caddy::new()
        .render_config(&ctx, &users, &[&proto as &dyn Protocol])
        .unwrap();
    let b = Caddy::new()
        .render_config(&ctx, &users, &[&proto as &dyn Protocol])
        .unwrap();
    assert_eq!(a, b);
}

#[test]
fn vlessws_and_naive_both_present_is_render_error() {
    // The caddy kernel serves exactly ONE front protocol per node;
    // enabling BOTH must fail LOUDLY rather than silently dropping
    // naive's Caddyfile (which would break live naive clients).
    let s = dummy_server();
    let mut sec = vlessws_secrets();
    sec.insert("naive.domain".into(), "cdn.example.com".into());
    let ctx = RenderCtx::new(&s, &sec);
    let n = Naive::new();
    let w = VlessWs::new();
    let err = Caddy::new()
        .render_config(
            &ctx,
            &[user("a", Some("p"))],
            &[&n as &dyn Protocol, &w as &dyn Protocol],
        )
        .unwrap_err();
    match err {
        CoreError::Render(m) => assert!(
            m.contains("BOTH") || m.contains("one front protocol"),
            "msg: {m}"
        ),
        other => panic!("expected Render error, got {other:?}"),
    }
}

#[test]
fn vlessws_apply_script_validates_snapshots_and_rolls_back() {
    let s = vlessws_apply_script();
    // validate the NEW Caddyfile BEFORE the swap
    let validate = s
        .find("caddy validate --config /etc/caddy/Caddyfile.new")
        .expect("validate present");
    let swap = s
        .find("mv /etc/caddy/Caddyfile.new /etc/caddy/Caddyfile")
        .expect("atomic swap present");
    assert!(validate < swap, "validate must precede the swap");
    // backend (sing-box) restarted, rollback + exit 1 on failure
    assert!(s.contains("systemctl restart caddy-vlessws"));
    assert!(s.contains("mv /etc/caddy/Caddyfile.bak /etc/caddy/Caddyfile"));
    assert!(s.contains("exit 1"));
    // firewall opens the operator front port from the meta member
    assert!(s.contains("ufw allow \"${VLESSWS_FRONT_PORT}/tcp\""));
}

#[test]
fn naive_apply_script_validates_snapshots_and_rolls_back() {
    let s = naive_apply_script();
    let validate = s
        .find("caddy validate --config /etc/caddy/Caddyfile.new")
        .expect("validate present");
    let snapshot = s
        .find("cp -a /etc/caddy/Caddyfile /etc/caddy/Caddyfile.bak")
        .expect("snapshot present");
    let swap = s
        .find("mv /etc/caddy/Caddyfile.new /etc/caddy/Caddyfile")
        .expect("swap present");
    let restart = s
        .find("systemctl reload-or-restart caddy")
        .expect("restart present");
    assert!(
        validate < snapshot && snapshot < swap && swap < restart,
        "ordering: validate → snapshot → swap → restart"
    );
    assert!(s.contains("HAD_PREV=0"), "must track previous config");
    assert!(
        s.contains("rolling back to previous Caddyfile"),
        "must roll back on failure: {s}"
    );
    assert!(
        s.contains("mv /etc/caddy/Caddyfile.bak /etc/caddy/Caddyfile"),
        "rollback must restore the .bak: {s}"
    );
    assert!(
        s.contains("no previous Caddyfile — removing failed deploy"),
        "must handle first-deploy failure: {s}"
    );
    assert!(
        s.contains("rm -f /etc/caddy/Caddyfile.bak"),
        "success path must remove the transient .bak: {s}"
    );
}

#[test]
fn vlessws_render_rejects_injection_domain() {
    let s = dummy_server();
    let mut sec = vlessws_secrets();
    sec.insert("vlessws.domain".into(), "evil.com {\n}\nx".into());
    let ctx = RenderCtx::new(&s, &sec);
    let proto = VlessWs::new();
    // the protocol's checked_domain rejects this first → Render error
    assert!(
        Caddy::new()
            .render_config(&ctx, &[user("a", Some("p"))], &[&proto as &dyn Protocol])
            .is_err()
    );
}
