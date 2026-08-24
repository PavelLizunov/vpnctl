use super::builder::*;
use super::render::*;
use super::*;
use std::collections::HashMap;
use vpnctl_core::{Server, ServerId, UserId};
use vpnctl_protocols::{Naive, VlessWs};
use vpnctl_ssh::MockTransport;

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
    assert!(
        s.contains(GO_TARBALL_SHA256),
        "Go tarball SHA-256 must be pinned in the build script: {s}"
    );
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
    assert!(!caddy_present("present extra"));
}

#[test]
fn caddy_reinstall_is_content_aware_not_presence() {
    let cache = "a".repeat(64);
    assert!(caddy_needs_reinstall(&cache, ""));
    assert!(caddy_needs_reinstall(&cache, "\n"));
    assert!(caddy_needs_reinstall(&cache, "   "));
    assert!(caddy_needs_reinstall(&cache, &"b".repeat(64)));
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
    assert!(!text.contains("forward_proxy {"));
    assert!(!text.contains("basic_auth"));
    assert!(!text.contains("probe_resistance"));
    assert!(text.contains("file_server"));
}

#[test]
fn render_missing_domain_secret_is_error() {
    let s = dummy_server();
    let sec = HashMap::new();
    let ctx = RenderCtx::new(&s, &sec);
    let naive = Naive::new();
    let err = Caddy::new()
        .render_config(
            &ctx,
            &[user("alice", Some("pw"))],
            &[&naive as &dyn Protocol],
        )
        .unwrap_err();
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
    let users = [user("alice", Some("pw"))];
    let bytes = Caddy::new()
        .render_config(&ctx, &users, &[&proto as &dyn Protocol])
        .unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(text.starts_with("====FILE: /etc/caddy/Caddyfile===="));
    assert!(text.contains("====FILE: /etc/caddy/vlessws-singbox.json===="));
    assert!(text.contains("====FILE: /etc/caddy/.vlessws-deploy.env===="));
    assert!(text.contains("de.ninitux.top:8443 {"), "conf:\n{text}");
    assert!(text.contains("@vlessws path /Ab3x9Zq2Kp7Lm"));
    assert!(text.contains("reverse_proxy @vlessws 127.0.0.1:11443"));
    assert!(text.contains("root /var/www/naive-site"));
    assert!(text.contains("protocols h1 h2"));
    assert!(text.contains("\"path\": \"/Ab3x9Zq2Kp7Lm\""));
    assert!(text.contains("uuid-alice"));
    assert!(!text.contains("xtls-rprx-vision"));
    assert!(!text.contains("\"tls\""));
    assert!(text.contains("VLESSWS_FRONT_PORT=8443"));
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
fn vlessws_render_rejects_injection_domain() {
    let s = dummy_server();
    let mut sec = vlessws_secrets();
    sec.insert("vlessws.domain".into(), "evil.com {\n}\nx".into());
    let ctx = RenderCtx::new(&s, &sec);
    let proto = VlessWs::new();
    assert!(
        Caddy::new()
            .render_config(&ctx, &[user("a", Some("p"))], &[&proto as &dyn Protocol])
            .is_err()
    );
}

#[test]
fn vlessws_and_naive_both_present_is_render_error() {
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

// ───────────────────────── Apply Script Structure & Simulations ──────────────────────────

fn strip_comment_lines(script: &str) -> String {
    script
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn vlessws_apply_script_structure_and_recovery_guards() {
    let s = vlessws_apply_script();
    let stripped = strip_comment_lines(&s);

    assert!(stripped.contains("set -eu"), "must set -eu");
    assert!(
        !stripped.contains("trap 'recover' ERR") && !stripped.contains("trap \"recover\" ERR"),
        "no ERR trap allowed"
    );

    let validate = stripped
        .find("caddy validate --config /etc/caddy/Caddyfile.new")
        .expect("validate present");
    let snapshot_caddy = stripped
        .find("cp -a /etc/caddy/Caddyfile /etc/caddy/Caddyfile.bak")
        .expect("snapshot caddy present");
    let snapshot_sb = stripped
        .find("cp -a /etc/caddy/vlessws-singbox.json /etc/caddy/vlessws-singbox.json.bak")
        .expect("snapshot backend config present");
    let snapshot_env = stripped
        .find("cp -a /etc/caddy/.vlessws-deploy.env /etc/caddy/.vlessws-deploy.env.bak")
        .expect("snapshot deploy env present");
    let record_caddy_enabled = stripped
        .find("HAD_CADDY_ENABLED=0")
        .expect("record caddy enabled present");
    let record_vlessws_enabled = stripped
        .find("HAD_VLESSWS_ENABLED=0")
        .expect("record vlessws enabled present");
    let recover_def = stripped
        .find("recover() {")
        .expect("recover definition present");
    let swap_caddy = stripped
        .find("mv /etc/caddy/Caddyfile.new /etc/caddy/Caddyfile || recover \"\"")
        .expect("swap caddyfile guarded by recover");
    let swap_sb = stripped
        .find("mv /etc/caddy/vlessws-singbox.json.new /etc/caddy/vlessws-singbox.json || recover \"\"")
        .expect("swap backend config guarded by recover");
    let swap_env = stripped
        .find(
            "mv /etc/caddy/.vlessws-deploy.env.new /etc/caddy/.vlessws-deploy.env || recover \"\"",
        )
        .expect("swap deploy env guarded by recover");
    let enable_vlessws = stripped
        .find("systemctl enable caddy-vlessws >/dev/null 2>&1 || recover \"caddy-vlessws\"")
        .expect("enable vlessws guarded by recover");
    let restart_vlessws = stripped
        .find("systemctl restart caddy-vlessws || recover \"caddy-vlessws\"")
        .expect("restart vlessws guarded by recover");
    let enable_caddy = stripped
        .find("systemctl enable caddy >/dev/null 2>&1 || recover \"caddy\"")
        .expect("enable caddy guarded by recover");
    let restart_caddy = stripped
        .find("systemctl reload-or-restart caddy || recover \"caddy\"")
        .expect("restart caddy guarded by recover");
    let rm_caddy_bak = stripped[restart_caddy..]
        .find("rm -f /etc/caddy/Caddyfile.bak || true")
        .expect("rm caddy snapshot present")
        + restart_caddy;
    let rm_sb_bak = stripped[rm_caddy_bak..]
        .find("rm -f /etc/caddy/vlessws-singbox.json.bak || true")
        .expect("rm singbox snapshot present")
        + rm_caddy_bak;
    let rm_env_bak = stripped[rm_sb_bak..]
        .find("rm -f /etc/caddy/.vlessws-deploy.env.bak || true")
        .expect("rm deploy env snapshot present")
        + rm_sb_bak;

    assert!(validate < snapshot_caddy);
    assert!(snapshot_caddy < snapshot_sb);
    assert!(snapshot_sb < snapshot_env);
    assert!(snapshot_env < record_caddy_enabled);
    assert!(record_caddy_enabled < record_vlessws_enabled);
    assert!(record_vlessws_enabled < recover_def);
    assert!(recover_def < swap_caddy);
    assert!(swap_caddy < swap_sb);
    assert!(swap_sb < swap_env);
    assert!(swap_env < enable_vlessws);
    assert!(enable_vlessws < restart_vlessws);
    assert!(restart_vlessws < enable_caddy);
    assert!(enable_caddy < restart_caddy);
    assert!(restart_caddy < rm_caddy_bak);
    assert!(rm_caddy_bak < rm_sb_bak);
    assert!(rm_sb_bak < rm_env_bak);

    let exit1_pos = stripped[recover_def..]
        .find("exit 1")
        .expect("exit 1 missing")
        + recover_def;
    let recover_body = &stripped[recover_def..exit1_pos];
    assert!(
        recover_body.contains("set +e"),
        "recover must disable set -e"
    );
    assert!(
        stripped.contains("_in_recover=0")
            && recover_body.contains("[ \"$_in_recover\" = 1 ] && return 1"),
        "recover must guard against recursion"
    );
    assert!(recover_body.contains("mv /etc/caddy/Caddyfile.bak /etc/caddy/Caddyfile"));
    assert!(
        recover_body
            .contains("mv /etc/caddy/vlessws-singbox.json.bak /etc/caddy/vlessws-singbox.json")
    );
    assert!(
        recover_body
            .contains("mv /etc/caddy/.vlessws-deploy.env.bak /etc/caddy/.vlessws-deploy.env")
    );
    assert!(
        !recover_body.contains("chown"),
        "recovery must not force chown, preserving exact snapshot metadata"
    );
    assert!(
        !recover_body.contains("chmod"),
        "recovery must not force chmod, preserving exact snapshot metadata"
    );
    assert!(recover_body.contains("systemctl restart caddy-vlessws"));
    assert!(recover_body.contains("systemctl reload-or-restart caddy"));
}

#[test]
fn naive_apply_script_structure_and_recovery_guards() {
    let s = naive_apply_script();
    let stripped = strip_comment_lines(&s);

    assert!(stripped.contains("set -eu"), "must set -eu");
    assert!(
        !stripped.contains("trap 'recover' ERR") && !stripped.contains("trap \"recover\" ERR"),
        "no ERR trap allowed"
    );

    let validate = stripped
        .find("caddy validate --config /etc/caddy/Caddyfile.new")
        .expect("validate present");
    let snapshot_caddy = stripped
        .find("cp -a /etc/caddy/Caddyfile /etc/caddy/Caddyfile.bak")
        .expect("snapshot caddy present");
    let snapshot_sb = stripped
        .find("cp -a /etc/caddy/vlessws-singbox.json /etc/caddy/vlessws-singbox.json.bak")
        .expect("snapshot backend config present");
    let snapshot_env = stripped
        .find("cp -a /etc/caddy/.vlessws-deploy.env /etc/caddy/.vlessws-deploy.env.bak")
        .expect("snapshot deploy env present");
    let record_caddy_enabled = stripped
        .find("HAD_CADDY_ENABLED=0")
        .expect("record caddy enabled present");
    let record_vlessws_enabled = stripped
        .find("HAD_VLESSWS_ENABLED=0")
        .expect("record vlessws enabled present");
    let recover_def = stripped
        .find("recover() {")
        .expect("recover definition present");
    let swap_caddy = stripped
        .find("mv /etc/caddy/Caddyfile.new /etc/caddy/Caddyfile || recover \"\"")
        .expect("swap caddyfile guarded by recover");
    let enable_caddy = stripped
        .find("systemctl enable caddy >/dev/null 2>&1 || recover \"caddy\"")
        .expect("enable caddy guarded by recover");
    let restart_caddy = stripped
        .find("systemctl reload-or-restart caddy || recover \"caddy\"")
        .expect("restart caddy guarded by recover");
    let stop_vlessws = stripped
        .find("systemctl stop caddy-vlessws || recover \"caddy-vlessws\"")
        .expect("stop vlessws guarded by recover");
    let disable_vlessws = stripped
        .find("systemctl disable caddy-vlessws || recover \"caddy-vlessws\"")
        .expect("disable vlessws guarded by recover");
    let rm_sb = stripped[disable_vlessws..]
        .find("rm -f /etc/caddy/vlessws-singbox.json || recover \"\"")
        .expect("rm live singbox config guarded by recover")
        + disable_vlessws;
    let rm_env = stripped[rm_sb..]
        .find("rm -f /etc/caddy/.vlessws-deploy.env || recover \"\"")
        .expect("rm live deploy env guarded by recover")
        + rm_sb;
    let rm_sb_bak = stripped[rm_env..]
        .find("rm -f /etc/caddy/vlessws-singbox.json.bak || true")
        .expect("rm singbox snapshot present")
        + rm_env;
    let rm_env_bak = stripped[rm_sb_bak..]
        .find("rm -f /etc/caddy/.vlessws-deploy.env.bak || true")
        .expect("rm deploy env snapshot present")
        + rm_sb_bak;
    let rm_caddy_bak = stripped[rm_env_bak..]
        .find("rm -f /etc/caddy/Caddyfile.bak || true")
        .expect("rm caddy snapshot present")
        + rm_env_bak;

    assert!(validate < snapshot_caddy);
    assert!(snapshot_caddy < snapshot_sb);
    assert!(snapshot_sb < snapshot_env);
    assert!(snapshot_env < record_caddy_enabled);
    assert!(record_caddy_enabled < record_vlessws_enabled);
    assert!(record_vlessws_enabled < recover_def);
    assert!(recover_def < swap_caddy);
    assert!(swap_caddy < enable_caddy);
    assert!(enable_caddy < restart_caddy);
    assert!(restart_caddy < stop_vlessws);
    assert!(stop_vlessws < disable_vlessws);
    assert!(disable_vlessws < rm_sb);
    assert!(rm_sb < rm_env);
    assert!(rm_env < rm_sb_bak);
    assert!(rm_sb_bak < rm_env_bak);
    assert!(rm_env_bak < rm_caddy_bak);
}

fn sim_env(script: &str, initial_files: &[(&str, &str)], custom_mocks: &str, post_checks: &str) {
    let mut file_setup = String::new();
    for (name, content) in initial_files {
        if *name == ".vlessws-bundle.new" {
            file_setup.push_str(
                "cat > \"$TMP_DIR/etc/caddy/.vlessws-bundle.new\" <<BUNDLE_EOF\n\
====FILE: $TMP_DIR/etc/caddy/Caddyfile====\n\
NEW_CADDYFILE\n\
====FILE: $TMP_DIR/etc/caddy/vlessws-singbox.json====\n\
NEW_SINGBOX\n\
====FILE: $TMP_DIR/etc/caddy/.vlessws-deploy.env====\n\
VLESSWS_FRONT_PORT=8443\n\
BUNDLE_EOF\n",
            );
        } else {
            file_setup.push_str(&format!(
                "cat > \"$TMP_DIR/etc/caddy/{name}\" <<'F_EOF'\n{content}\nF_EOF\n"
            ));
        }
    }

    let test_script = format!(
        r#"
        set -eu
        TMP_DIR=$(mktemp -d)
        trap 'rm -rf "$TMP_DIR"' EXIT
        mkdir -p "$TMP_DIR/etc/caddy"
        CMD_LOG="$TMP_DIR/systemctl.log"
        touch "$CMD_LOG"

        {file_setup}

        caddy() {{ :; }}
        chown() {{ :; }}
        chmod() {{ :; }}
        journalctl() {{ :; }}
        ufw() {{ :; }}
        sleep() {{ :; }}
        systemctl() {{
            action="$1"; shift
            echo "$action $*" >> "$CMD_LOG"
            case "$action" in
                is-enabled) return 0 ;;
                is-active) echo "active"; return 0 ;;
                *) return 0 ;;
            esac
        }}

        {custom_mocks}

        EVAL_SCRIPT=$(cat <<'EOF'
{script}
EOF
)
        EVAL_SCRIPT=$(echo "$EVAL_SCRIPT" | sed "s|/etc/caddy|$TMP_DIR/etc/caddy|g" | sed "s|/usr/local/bin/caddy|caddy|g")

        set +e
        OUTPUT=$(eval "$EVAL_SCRIPT" 2>&1)
        STATUS=$?
        set -e

        {post_checks}
        "#
    );

    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(&test_script)
        .output()
        .expect("failed to execute sh simulation");

    assert!(
        out.status.success(),
        "Simulation failed:\nSTDOUT:\n{}\nSTDERR:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn vlessws_apply_preswap_snapshot_failure_aborts_without_recover_e2e() {
    let script = vlessws_apply_script();
    sim_env(
        &script,
        &[
            ("Caddyfile", "OLD_CADDY"),
            ("vlessws-singbox.json", "OLD_SB"),
            (".vlessws-deploy.env", "OLD_ENV"),
            (".vlessws-bundle.new", ""),
        ],
        r#"
        cp() {
            if [ "${1:-}" = "-a" ]; then
                return 1
            fi
            command cp "$@"
        }
        "#,
        r#"
        [ "$STATUS" -ne 0 ] || exit 1
        if echo "$OUTPUT" | grep -q "rolling back"; then
            echo "FAIL: recover invoked on pre-swap snapshot error" >&2
            exit 1
        fi
        [ "$(cat "$TMP_DIR/etc/caddy/Caddyfile")" = "OLD_CADDY" ] || exit 1
        [ "$(cat "$TMP_DIR/etc/caddy/vlessws-singbox.json")" = "OLD_SB" ] || exit 1
        [ "$(cat "$TMP_DIR/etc/caddy/.vlessws-deploy.env")" = "OLD_ENV" ] || exit 1
        "#,
    );
}

#[test]
fn vlessws_apply_postswap_fs_failure_invokes_recover_e2e() {
    let script = vlessws_apply_script();
    sim_env(
        &script,
        &[
            ("Caddyfile", "OLD_CADDY"),
            ("vlessws-singbox.json", "OLD_SB"),
            (".vlessws-deploy.env", "OLD_ENV"),
            (".vlessws-bundle.new", ""),
        ],
        r#"
        mv() {
            for arg in "$@"; do
                if [ "$arg" = "$TMP_DIR/etc/caddy/vlessws-singbox.json.new" ]; then
                    return 1
                fi
            done
            command mv "$@"
        }
        "#,
        r#"
        [ "$STATUS" -eq 1 ] || exit 1
        echo "$OUTPUT" | grep -q "rolling back Caddyfile to previous config" || exit 1
        [ "$(cat "$TMP_DIR/etc/caddy/Caddyfile")" = "OLD_CADDY" ] || exit 1
        [ "$(cat "$TMP_DIR/etc/caddy/vlessws-singbox.json")" = "OLD_SB" ] || exit 1
        [ "$(cat "$TMP_DIR/etc/caddy/.vlessws-deploy.env")" = "OLD_ENV" ] || exit 1
        "#,
    );
}

#[test]
fn vlessws_apply_backend_failure_invokes_recover_e2e() {
    let script = vlessws_apply_script();
    sim_env(
        &script,
        &[("Caddyfile", "OLD_CADDY"), (".vlessws-bundle.new", "")],
        r#"
        systemctl() {
            action="$1"; shift
            echo "$action $*" >> "$CMD_LOG"
            if [ "$action" = "restart" ] && [ "${1:-}" = "caddy-vlessws" ]; then
                return 1
            fi
            case "$action" in
                is-enabled) return 0 ;;
                is-active) echo "active"; return 0 ;;
                *) return 0 ;;
            esac
        }
        "#,
        r#"
        [ "$STATUS" -eq 1 ] || exit 1
        echo "$OUTPUT" | grep -q "caddy-vlessws did not become active" || exit 1
        [ "$(cat "$TMP_DIR/etc/caddy/Caddyfile")" = "OLD_CADDY" ] || exit 1
        "#,
    );
}

#[test]
fn vlessws_apply_caddy_failure_invokes_recover_e2e() {
    let script = vlessws_apply_script();
    sim_env(
        &script,
        &[("Caddyfile", "OLD_CADDY"), (".vlessws-bundle.new", "")],
        r#"
        systemctl() {
            action="$1"; shift
            echo "$action $*" >> "$CMD_LOG"
            if [ "$action" = "reload-or-restart" ] && [ "${1:-}" = "caddy" ]; then
                return 1
            fi
            case "$action" in
                is-enabled) return 0 ;;
                is-active) echo "active"; return 0 ;;
                *) return 0 ;;
            esac
        }
        "#,
        r#"
        [ "$STATUS" -eq 1 ] || exit 1
        echo "$OUTPUT" | grep -q "caddy did not become active" || exit 1
        [ "$(cat "$TMP_DIR/etc/caddy/Caddyfile")" = "OLD_CADDY" ] || exit 1
        "#,
    );
}

#[test]
fn vlessws_apply_poll_timeout_invokes_recover_e2e() {
    let script = vlessws_apply_script();
    sim_env(
        &script,
        &[("Caddyfile", "OLD_CADDY"), (".vlessws-bundle.new", "")],
        r#"
        systemctl() {
            action="$1"; shift
            echo "$action $*" >> "$CMD_LOG"
            if [ "$action" = "is-active" ]; then
                echo "failed"
                return 1
            fi
            return 0
        }
        "#,
        r#"
        [ "$STATUS" -eq 1 ] || exit 1
        echo "$OUTPUT" | grep -q "did not become active" || exit 1
        [ "$(cat "$TMP_DIR/etc/caddy/Caddyfile")" = "OLD_CADDY" ] || exit 1
        "#,
    );
}

#[test]
fn vlessws_apply_first_deploy_failure_cleanup_e2e() {
    let script = vlessws_apply_script();
    sim_env(
        &script,
        &[(".vlessws-bundle.new", "")],
        r#"
        systemctl() {
            action="$1"; shift
            echo "$action $*" >> "$CMD_LOG"
            case "$action" in
                is-enabled|is-active) return 1 ;;
                restart)
                    if [ "${1:-}" = "caddy-vlessws" ]; then return 1; fi
                    return 0
                    ;;
                *) return 0 ;;
            esac
        }
        "#,
        r#"
        [ "$STATUS" -eq 1 ] || exit 1
        echo "$OUTPUT" | grep -q "no previous Caddyfile — removing failed deploy" || exit 1
        echo "$OUTPUT" | grep -q "no previous backend config — removing failed deploy" || exit 1
        [ ! -f "$TMP_DIR/etc/caddy/Caddyfile" ] || exit 1
        [ ! -f "$TMP_DIR/etc/caddy/vlessws-singbox.json" ] || exit 1
        [ ! -f "$TMP_DIR/etc/caddy/.vlessws-deploy.env" ] || exit 1
        grep -q "stop caddy-vlessws" "$CMD_LOG" || exit 1
        grep -q "disable caddy-vlessws" "$CMD_LOG" || exit 1
        grep -q "stop caddy" "$CMD_LOG" || exit 1
        grep -q "disable caddy" "$CMD_LOG" || exit 1
        "#,
    );
}

#[test]
fn vlessws_apply_mixed_prior_state_recovery_e2e() {
    let script = vlessws_apply_script();
    sim_env(
        &script,
        &[
            ("Caddyfile", "OLD_CADDY"),
            ("vlessws-singbox.json", "OLD_SB"),
            (".vlessws-deploy.env", "OLD_ENV"),
            (".vlessws-bundle.new", ""),
        ],
        r#"
        systemctl() {
            action="$1"; shift
            echo "$action $*" >> "$CMD_LOG"
            case "$action" in
                is-enabled)
                    [ "${1:-}" = "caddy" ] && return 0
                    return 1
                    ;;
                is-active)
                    if [ "${1:-}" = "caddy" ]; then
                        echo "active"
                        return 0
                    fi
                    echo "inactive"
                    return 3
                    ;;
                reload-or-restart)
                    if [ "${1:-}" = "caddy" ]; then
                        if ! grep -q "fail_reload_trigger" "$CMD_LOG"; then
                            echo "fail_reload_trigger" >> "$CMD_LOG"
                            return 1
                        fi
                    fi
                    return 0
                    ;;
                *) return 0 ;;
            esac
        }
        "#,
        r#"
        [ "$STATUS" -eq 1 ] || exit 1
        [ "$(cat "$TMP_DIR/etc/caddy/Caddyfile")" = "OLD_CADDY" ] || exit 1
        [ "$(cat "$TMP_DIR/etc/caddy/vlessws-singbox.json")" = "OLD_SB" ] || exit 1

        grep -q "disable caddy-vlessws" "$CMD_LOG" || exit 1
        grep -q "stop caddy-vlessws" "$CMD_LOG" || exit 1
        grep -q "enable caddy" "$CMD_LOG" || exit 1
        grep -q "reload-or-restart caddy" "$CMD_LOG" || exit 1
        "#,
    );
}

#[test]
fn vlessws_apply_success_path_e2e() {
    let script = vlessws_apply_script();
    sim_env(
        &script,
        &[("Caddyfile", "OLD_CADDY"), (".vlessws-bundle.new", "")],
        "",
        r#"
        [ "$STATUS" -eq 0 ] || exit 1
        [ "$(cat "$TMP_DIR/etc/caddy/Caddyfile")" = "NEW_CADDYFILE" ] || exit 1
        [ "$(cat "$TMP_DIR/etc/caddy/vlessws-singbox.json")" = "NEW_SINGBOX" ] || exit 1
        [ -f "$TMP_DIR/etc/caddy/.vlessws-deploy.env" ] || exit 1
        [ ! -f "$TMP_DIR/etc/caddy/.vlessws-bundle.new" ] || exit 1
        [ ! -f "$TMP_DIR/etc/caddy/Caddyfile.bak" ] || exit 1
        [ ! -f "$TMP_DIR/etc/caddy/vlessws-singbox.json.bak" ] || exit 1
        [ ! -f "$TMP_DIR/etc/caddy/.vlessws-deploy.env.bak" ] || exit 1
        "#,
    );
}

#[test]
fn naive_apply_preswap_snapshot_failure_aborts_without_recover_e2e() {
    let script = naive_apply_script();
    sim_env(
        &script,
        &[("Caddyfile", "OLD_CADDY"), ("Caddyfile.new", "NEW_CADDY")],
        r#"
        cp() {
            if [ "${1:-}" = "-a" ]; then
                return 1
            fi
            command cp "$@"
        }
        "#,
        r#"
        [ "$STATUS" -ne 0 ] || exit 1
        if echo "$OUTPUT" | grep -q "rolling back"; then
            echo "FAIL: recover invoked on pre-swap snapshot error" >&2
            exit 1
        fi
        [ "$(cat "$TMP_DIR/etc/caddy/Caddyfile")" = "OLD_CADDY" ] || exit 1
        "#,
    );
}

#[test]
fn naive_apply_postswap_fs_failure_invokes_recover_e2e() {
    let script = naive_apply_script();
    sim_env(
        &script,
        &[("Caddyfile", "OLD_CADDY"), ("Caddyfile.new", "NEW_CADDY")],
        r#"
        chown() { return 1; }
        "#,
        r#"
        [ "$STATUS" -eq 1 ] || exit 1
        echo "$OUTPUT" | grep -q "rolling back Caddyfile to previous config" || exit 1
        [ "$(cat "$TMP_DIR/etc/caddy/Caddyfile")" = "OLD_CADDY" ] || exit 1
        "#,
    );
}

#[test]
fn naive_apply_caddy_failure_invokes_recover_e2e() {
    let script = naive_apply_script();
    sim_env(
        &script,
        &[("Caddyfile", "OLD_CADDY"), ("Caddyfile.new", "NEW_CADDY")],
        r#"
        systemctl() {
            action="$1"; shift
            echo "$action $*" >> "$CMD_LOG"
            if [ "$action" = "reload-or-restart" ] && [ "${1:-}" = "caddy" ]; then
                return 1
            fi
            case "$action" in
                is-enabled) return 0 ;;
                is-active) echo "active"; return 0 ;;
                *) return 0 ;;
            esac
        }
        "#,
        r#"
        [ "$STATUS" -eq 1 ] || exit 1
        echo "$OUTPUT" | grep -q "rolling back Caddyfile to previous config" || exit 1
        [ "$(cat "$TMP_DIR/etc/caddy/Caddyfile")" = "OLD_CADDY" ] || exit 1
        "#,
    );
}

#[test]
fn naive_apply_poll_timeout_invokes_recover_e2e() {
    let script = naive_apply_script();
    sim_env(
        &script,
        &[("Caddyfile", "OLD_CADDY"), ("Caddyfile.new", "NEW_CADDY")],
        r#"
        systemctl() {
            action="$1"; shift
            echo "$action $*" >> "$CMD_LOG"
            if [ "$action" = "is-active" ]; then
                echo "inactive"
                return 1
            fi
            return 0
        }
        "#,
        r#"
        [ "$STATUS" -eq 1 ] || exit 1
        echo "$OUTPUT" | grep -q "did not become active" || exit 1
        [ "$(cat "$TMP_DIR/etc/caddy/Caddyfile")" = "OLD_CADDY" ] || exit 1
        "#,
    );
}

#[test]
fn naive_apply_first_deploy_failure_cleanup_e2e() {
    let script = naive_apply_script();
    sim_env(
        &script,
        &[("Caddyfile.new", "NEW_CADDY")],
        r#"
        systemctl() {
            action="$1"; shift
            echo "$action $*" >> "$CMD_LOG"
            case "$action" in
                is-enabled|is-active) return 1 ;;
                reload-or-restart)
                    if [ "${1:-}" = "caddy" ]; then return 1; fi
                    return 0
                    ;;
                *) return 0 ;;
            esac
        }
        "#,
        r#"
        [ "$STATUS" -eq 1 ] || exit 1
        echo "$OUTPUT" | grep -q "no previous Caddyfile — removing failed deploy" || exit 1
        [ ! -f "$TMP_DIR/etc/caddy/Caddyfile" ] || exit 1
        grep -q "stop caddy" "$CMD_LOG" || exit 1
        grep -q "disable caddy" "$CMD_LOG" || exit 1
        grep -q "stop caddy-vlessws" "$CMD_LOG" || exit 1
        grep -q "disable caddy-vlessws" "$CMD_LOG" || exit 1
        "#,
    );
}

#[test]
fn naive_apply_transition_from_vlessws_success_e2e() {
    let script = naive_apply_script();
    sim_env(
        &script,
        &[
            ("Caddyfile", "VLESSWS_CADDY"),
            ("vlessws-singbox.json", "VLESSWS_SB"),
            (".vlessws-deploy.env", "VLESSWS_ENV"),
            ("Caddyfile.new", "NAIVE_CADDY"),
        ],
        "",
        r#"
        [ "$STATUS" -eq 0 ] || exit 1
        [ "$(cat "$TMP_DIR/etc/caddy/Caddyfile")" = "NAIVE_CADDY" ] || exit 1
        [ ! -f "$TMP_DIR/etc/caddy/vlessws-singbox.json" ] || exit 1
        [ ! -f "$TMP_DIR/etc/caddy/.vlessws-deploy.env" ] || exit 1
        [ ! -f "$TMP_DIR/etc/caddy/Caddyfile.bak" ] || exit 1
        [ ! -f "$TMP_DIR/etc/caddy/vlessws-singbox.json.bak" ] || exit 1
        [ ! -f "$TMP_DIR/etc/caddy/.vlessws-deploy.env.bak" ] || exit 1

        grep -q "stop caddy-vlessws" "$CMD_LOG" || exit 1
        grep -q "disable caddy-vlessws" "$CMD_LOG" || exit 1
        grep -q "reload-or-restart caddy" "$CMD_LOG" || exit 1
        "#,
    );
}

#[test]
fn naive_apply_retire_backend_failure_invokes_recover_e2e() {
    let script = naive_apply_script();
    sim_env(
        &script,
        &[
            ("Caddyfile", "VLESSWS_CADDY"),
            ("vlessws-singbox.json", "VLESSWS_SB"),
            (".vlessws-deploy.env", "VLESSWS_ENV"),
            ("Caddyfile.new", "NAIVE_CADDY"),
        ],
        r#"
        systemctl() {
            action="$1"; shift
            echo "$action $*" >> "$CMD_LOG"
            case "$action" in
                stop)
                    if [ "${1:-}" = "caddy-vlessws" ]; then
                        if ! grep -q "stop_fail_triggered" "$CMD_LOG"; then
                            echo "stop_fail_triggered" >> "$CMD_LOG"
                            return 1
                        fi
                    fi
                    return 0
                    ;;
                is-enabled) return 0 ;;
                is-active) echo "active"; return 0 ;;
                *) return 0 ;;
            esac
        }
        "#,
        r#"
        [ "$STATUS" -eq 1 ] || exit 1
        echo "$OUTPUT" | grep -q "rolling back Caddyfile to previous config" || exit 1
        echo "$OUTPUT" | grep -q "rolling back backend config to previous config" || exit 1
        [ "$(cat "$TMP_DIR/etc/caddy/Caddyfile")" = "VLESSWS_CADDY" ] || exit 1
        [ "$(cat "$TMP_DIR/etc/caddy/vlessws-singbox.json")" = "VLESSWS_SB" ] || exit 1
        [ "$(cat "$TMP_DIR/etc/caddy/.vlessws-deploy.env")" = "VLESSWS_ENV" ] || exit 1

        grep -q "enable caddy-vlessws" "$CMD_LOG" || exit 1
        grep -q "restart caddy-vlessws" "$CMD_LOG" || exit 1
        grep -q "reload-or-restart caddy" "$CMD_LOG" || exit 1
        "#,
    );
}

#[test]
fn prologue_recover_preserves_exact_metadata_without_chown_chmod() {
    let s = caddy_state_machine_prologue(
        CADDYFILE_PATH,
        VLESSWS_SINGBOX_CONFIG,
        VLESSWS_DEPLOY_ENV,
        VLESSWS_UNIT,
    );
    let recover_fn = s.find("recover() {").expect("recover function present");
    let body = &s[recover_fn..];
    assert!(!body.contains("chown"), "recover must not force chown");
    assert!(!body.contains("chmod"), "recover must not force chmod");
}

#[test]
fn naive_apply_transition_live_artifact_rm_failure_invokes_recover_e2e() {
    let script = naive_apply_script();
    sim_env(
        &script,
        &[
            ("Caddyfile", "VLESSWS_CADDY"),
            ("vlessws-singbox.json", "VLESSWS_SB"),
            (".vlessws-deploy.env", "VLESSWS_ENV"),
            ("Caddyfile.new", "NAIVE_CADDY"),
        ],
        r#"
        rm() {
            for arg in "$@"; do
                if [ "$arg" = "$TMP_DIR/etc/caddy/vlessws-singbox.json" ]; then
                    return 1
                fi
            done
            command rm "$@"
        }
        "#,
        r#"
        [ "$STATUS" -eq 1 ] || exit 1
        echo "$OUTPUT" | grep -q "rolling back Caddyfile to previous config" || exit 1
        echo "$OUTPUT" | grep -q "rolling back backend config to previous config" || exit 1
        [ "$(cat "$TMP_DIR/etc/caddy/Caddyfile")" = "VLESSWS_CADDY" ] || exit 1
        [ "$(cat "$TMP_DIR/etc/caddy/vlessws-singbox.json")" = "VLESSWS_SB" ] || exit 1
        [ "$(cat "$TMP_DIR/etc/caddy/.vlessws-deploy.env")" = "VLESSWS_ENV" ] || exit 1

        grep -q "enable caddy-vlessws" "$CMD_LOG" || exit 1
        grep -q "restart caddy-vlessws" "$CMD_LOG" || exit 1
        grep -q "reload-or-restart caddy" "$CMD_LOG" || exit 1
        "#,
    );
}

#[test]
fn naive_apply_transition_snapshot_cleanup_failure_does_not_fail_deploy_e2e() {
    let script = naive_apply_script();
    sim_env(
        &script,
        &[
            ("Caddyfile", "VLESSWS_CADDY"),
            ("vlessws-singbox.json", "VLESSWS_SB"),
            (".vlessws-deploy.env", "VLESSWS_ENV"),
            ("Caddyfile.new", "NAIVE_CADDY"),
        ],
        r#"
        rm() {
            for arg in "$@"; do
                case "$arg" in
                    *.bak) return 1 ;;
                esac
            done
            command rm "$@"
        }
        "#,
        r#"
        [ "$STATUS" -eq 0 ] || exit 1
        [ "$(cat "$TMP_DIR/etc/caddy/Caddyfile")" = "NAIVE_CADDY" ] || exit 1
        [ ! -f "$TMP_DIR/etc/caddy/vlessws-singbox.json" ] || exit 1
        [ ! -f "$TMP_DIR/etc/caddy/.vlessws-deploy.env" ] || exit 1

        if echo "$OUTPUT" | grep -q "rolling back"; then
            echo "FAIL: recover invoked on snapshot cleanup error" >&2
            exit 1
        fi
        grep -q "reload-or-restart caddy" "$CMD_LOG" || exit 1
        "#,
    );
}

#[test]
fn vlessws_apply_snapshot_cleanup_failure_does_not_fail_deploy_e2e() {
    let script = vlessws_apply_script();
    sim_env(
        &script,
        &[
            ("Caddyfile", "OLD_CADDY"),
            ("vlessws-singbox.json", "OLD_SB"),
            (".vlessws-deploy.env", "OLD_ENV"),
            (".vlessws-bundle.new", ""),
        ],
        r#"
        rm() {
            for arg in "$@"; do
                case "$arg" in
                    *.bak) return 1 ;;
                esac
            done
            command rm "$@"
        }
        "#,
        r#"
        [ "$STATUS" -eq 0 ] || exit 1
        [ "$(cat "$TMP_DIR/etc/caddy/Caddyfile")" = "NEW_CADDYFILE" ] || exit 1
        [ "$(cat "$TMP_DIR/etc/caddy/vlessws-singbox.json")" = "NEW_SINGBOX" ] || exit 1
        [ -f "$TMP_DIR/etc/caddy/.vlessws-deploy.env" ] || exit 1

        if echo "$OUTPUT" | grep -q "rolling back"; then
            echo "FAIL: recover invoked on snapshot cleanup error" >&2
            exit 1
        fi
        "#,
    );
}

#[test]
fn caddy_scripts_no_multi_operand_rm_mixing_live_and_backups() {
    for (name, script) in [
        ("vlessws_apply_script", vlessws_apply_script()),
        ("naive_apply_script", naive_apply_script()),
    ] {
        let stripped = strip_comment_lines(&script);
        for line in stripped.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("rm ") {
                let parts: Vec<&str> = trimmed
                    .split_whitespace()
                    .filter(|p| {
                        !p.starts_with('-')
                            && *p != "rm"
                            && *p != "||"
                            && *p != "true"
                            && *p != "recover"
                            && *p != "\"\""
                    })
                    .collect();
                let has_bak = parts
                    .iter()
                    .any(|p| p.ends_with(".bak") || p.ends_with(".bak;"));
                let has_live = parts
                    .iter()
                    .any(|p| !p.ends_with(".bak") && !p.ends_with(".bak;"));
                assert!(
                    !(has_bak && has_live),
                    "script {name} contains rm mixing live and backup files on line: {trimmed}"
                );
                assert!(
                    parts.len() <= 1,
                    "script {name} contains multi-operand rm on line: {trimmed}"
                );
            }
        }
    }
}

// ───────────────────────── status, restart & transition ──────────────────────────

#[test]
fn restart_command_restarts_backend_if_managed_before_caddy() {
    let cmd = caddy_restart_command();
    let backend_idx = cmd
        .find("systemctl restart caddy-vlessws")
        .expect("backend restart present");
    let caddy_idx = cmd
        .rfind("systemctl restart caddy")
        .expect("caddy restart present");
    assert!(
        backend_idx < caddy_idx,
        "backend must restart before caddy so upstream is reachable: {cmd}"
    );
    assert!(
        cmd.contains("-f /etc/caddy/vlessws-singbox.json"),
        "must check config presence for single-unit / naive safety: {cmd}"
    );
    assert!(
        cmd.contains("systemctl is-active --quiet caddy-vlessws"),
        "must check is-active for backend: {cmd}"
    );
}

#[test]
fn vlessws_status_command_checks_config_and_active_state() {
    let cmd = caddy_vlessws_status_command();
    assert!(
        cmd.contains("/etc/caddy/vlessws-singbox.json"),
        "must check vlessws config path: {cmd}"
    );
    assert!(
        cmd.contains("caddy-vlessws"),
        "must target caddy-vlessws unit: {cmd}"
    );
    assert!(
        cmd.contains("echo absent"),
        "must output absent for Naive-only deployment: {cmd}"
    );
    assert!(
        cmd.contains("echo active"),
        "must output active when backend is active: {cmd}"
    );
    assert!(
        cmd.contains("echo inactive"),
        "must output inactive when backend is down: {cmd}"
    );
}

#[tokio::test]
async fn caddy_status_naive_deployment_active() {
    let ssh = MockTransport::new();
    ssh.expect("systemctl is-active caddy 2>/dev/null || true", "active\n");
    ssh.expect(&caddy_vlessws_status_command(), "absent\n");
    ssh.expect(
        "/usr/local/bin/caddy version 2>/dev/null | awk '{print $1; exit}'",
        "v2.11.4\n",
    );

    let status = Caddy::new().status(&ssh).await.expect("status ok");
    assert!(
        status.active,
        "Naive deployment with active caddy must report active"
    );
    assert_eq!(status.version.as_deref(), Some("v2.11.4"));
}

#[tokio::test]
async fn caddy_status_naive_deployment_caddy_down() {
    let ssh = MockTransport::new();
    ssh.expect(
        "systemctl is-active caddy 2>/dev/null || true",
        "inactive\n",
    );
    ssh.expect(&caddy_vlessws_status_command(), "absent\n");
    ssh.expect(
        "/usr/local/bin/caddy version 2>/dev/null | awk '{print $1; exit}'",
        "v2.11.4\n",
    );

    let status = Caddy::new().status(&ssh).await.expect("status ok");
    assert!(!status.active, "Inactive caddy must report inactive");
}

#[tokio::test]
async fn caddy_status_vlessws_both_units_active() {
    let ssh = MockTransport::new();
    ssh.expect("systemctl is-active caddy 2>/dev/null || true", "active\n");
    ssh.expect(&caddy_vlessws_status_command(), "active\n");
    ssh.expect(
        "/usr/local/bin/caddy version 2>/dev/null | awk '{print $1; exit}'",
        "v2.11.4\n",
    );

    let status = Caddy::new().status(&ssh).await.expect("status ok");
    assert!(
        status.active,
        "VLESS-WS deployment with both caddy and backend active must report active"
    );
    assert_eq!(status.version.as_deref(), Some("v2.11.4"));
}

#[tokio::test]
async fn caddy_status_vlessws_backend_down_reports_inactive_aud_010() {
    let ssh = MockTransport::new();
    ssh.expect("systemctl is-active caddy 2>/dev/null || true", "active\n");
    ssh.expect(&caddy_vlessws_status_command(), "inactive\n");
    ssh.expect(
        "/usr/local/bin/caddy version 2>/dev/null | awk '{print $1; exit}'",
        "v2.11.4\n",
    );

    let status = Caddy::new().status(&ssh).await.expect("status ok");
    assert!(
        !status.active,
        "AUD-010: VLESS-WS with dead backend must report inactive (preventing green 502)"
    );
}

#[tokio::test]
async fn caddy_status_vlessws_caddy_down_backend_active() {
    let ssh = MockTransport::new();
    ssh.expect(
        "systemctl is-active caddy 2>/dev/null || true",
        "inactive\n",
    );
    ssh.expect(&caddy_vlessws_status_command(), "active\n");

    let status = Caddy::new().status(&ssh).await.expect("status ok");
    assert!(
        !status.active,
        "Caddy down must report inactive even if backend is active"
    );
}

#[tokio::test]
async fn caddy_restart_executes_restart_command() {
    let ssh = MockTransport::new();
    ssh.expect(&caddy_restart_command(), "");

    Caddy::new().restart(&ssh).await.expect("restart ok");
}

#[tokio::test]
async fn caddy_apply_naive_executes_script_retiring_vlessws() {
    let ssh = MockTransport::new();
    let config = b"# Rendered by vpnctl\n:443, cdn.example.com {\n\tfile_server\n}\n";
    ssh.expect(&naive_apply_script(), "");

    Caddy::new()
        .apply_config(&ssh, config)
        .await
        .expect("naive apply ok");
    assert_eq!(
        ssh.uploaded("/etc/caddy/Caddyfile.new"),
        Some(config.to_vec())
    );
}

#[tokio::test]
async fn caddy_apply_vlessws_executes_bundle_apply_script() {
    let ssh = MockTransport::new();
    let config =
        format!("{BUNDLE_DELIMITER}/etc/caddy/Caddyfile{BUNDLE_DELIMITER_END}\n# Caddyfile\n")
            .into_bytes();
    ssh.expect(&vlessws_apply_script(), "");

    Caddy::new()
        .apply_config(&ssh, &config)
        .await
        .expect("vlessws apply ok");
    assert_eq!(ssh.uploaded("/etc/caddy/.vlessws-bundle.new"), Some(config));
}

#[tokio::test]
async fn vlessws_to_naive_transition_retired_state_reports_active() {
    let ssh = MockTransport::new();
    ssh.expect("systemctl is-active caddy 2>/dev/null || true", "active\n");
    ssh.expect(&caddy_vlessws_status_command(), "absent\n");
    ssh.expect(
        "/usr/local/bin/caddy version 2>/dev/null | awk '{print $1; exit}'",
        "v2.11.4\n",
    );

    let status = Caddy::new().status(&ssh).await.expect("status ok");
    assert!(
        status.active,
        "Retired VLESS-WS state (absent) must report active when caddy is active"
    );
    assert_eq!(status.version.as_deref(), Some("v2.11.4"));
}

#[tokio::test]
async fn caddy_status_backend_probe_empty_reports_inactive() {
    let ssh = MockTransport::new();
    ssh.expect("systemctl is-active caddy 2>/dev/null || true", "active\n");
    ssh.expect(&caddy_vlessws_status_command(), "\n");
    ssh.expect(
        "/usr/local/bin/caddy version 2>/dev/null | awk '{print $1; exit}'",
        "v2.11.4\n",
    );

    let status = Caddy::new().status(&ssh).await.expect("status ok");
    assert!(
        !status.active,
        "Empty backend probe output must report inactive (only exact 'active' or 'absent' is healthy)"
    );
}

#[tokio::test]
async fn caddy_status_backend_probe_unknown_reports_inactive() {
    let ssh = MockTransport::new();
    ssh.expect("systemctl is-active caddy 2>/dev/null || true", "active\n");
    ssh.expect(&caddy_vlessws_status_command(), "unknown\n");
    ssh.expect(
        "/usr/local/bin/caddy version 2>/dev/null | awk '{print $1; exit}'",
        "v2.11.4\n",
    );

    let status = Caddy::new().status(&ssh).await.expect("status ok");
    assert!(
        !status.active,
        "Unknown backend probe output must report inactive"
    );
}
