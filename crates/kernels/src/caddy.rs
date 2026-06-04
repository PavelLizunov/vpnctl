//! Caddy + `forwardproxy@naive` — the kernel that serves the [`Naive`]
//! protocol with a **real masquerade website**.
//!
//! [`Naive`]: vpnctl_protocols::Naive
//!
//! # Why a separate Kernel (not sing-box)
//!
//! sing-box HAS a `naive` inbound, but it `400`s every non-proxy
//! request — an active probe sees a bare error, a dead giveaway. The
//! only way to serve a genuine cover website (HTTP 200) to probes while
//! tunnelling authenticated clients is Caddy's `forwardproxy` fork with
//! `probe_resistance` + `file_server`. Different daemon ⇒ different
//! Kernel. This is the same split as WireGuard (wire format) ↔
//! AmneziaWg (daemon).
//!
//! # Trait-impedance fix (same shape as `amnezia_wg`)
//!
//! sing-box renders JSON; Caddy renders a Caddyfile (text). The
//! [`Naive`] protocol's `server_inbound` returns a STABLE JSON ENVELOPE
//! (`{ domain, acme_email, auth: [{username, password}] }`); this kernel
//! deserialises it and assembles the Caddyfile. The protocol never
//! knows it's Caddy; the kernel never hard-codes per-user secrets.
//!
//! # Install (built from source, like `wgturn`)
//!
//! The stock `caddy` apt package has NO forwardproxy. `ensure_installed`
//! installs Go (pinned [`GO_VERSION`]) and `xcaddy build`s Caddy
//! ([`CADDY_VERSION`]) with `klzgrad/forwardproxy` (pinned
//! [`FORWARDPROXY_PIN`]). On a ≤1 GB box the Go build is RAM-heavy, so
//! the script adds a temporary 1 GB swapfile and removes it after.
//! Idempotent: skips the whole build if `caddy list-modules` already
//! reports `forward_proxy`.
//!
//! # ACME
//!
//! Caddy's BUILT-IN ACME mints the Let's Encrypt cert for the domain —
//! this kernel needs no cert plumbing of its own (closing the "vpnctl
//! has no ACME" gap). Prerequisites that vpnctl CANNOT do (operator's
//! job): a DNS A record `<domain> → <node-ip>` and open TCP 80+443.
//!
//! # Port
//!
//! Caddy binds 80+443. A naive node therefore MUST NOT also run a
//! 443-TCP sing-box protocol (VLESS+REALITY / Trojan). This is operator
//! policy for now — the cross-kernel port-conflict preflight that would
//! enforce it is still pending (docs/NAIVE_CADDY_PLAN.md §3).

use async_trait::async_trait;
use serde::Deserialize;
use vpnctl_core::{
    CoreError, Kernel, KernelId, KernelStatus, Protocol, ProtocolId, RenderCtx, Result,
    SshTransport, User,
};

/// Pinned Go toolchain for the on-node `xcaddy` build. Bump in lockstep
/// with [`CADDY_VERSION`] when Caddy needs a newer Go. (wgturn pins its
/// Go the same way.)
pub(crate) const GO_VERSION: &str = "go1.26.4";

/// Pinned Caddy release the plugin is compiled against. xcaddy's
/// `build <version>` keeps the binary reproducible across nodes.
pub(crate) const CADDY_VERSION: &str = "v2.11.4";

/// Pinned `klzgrad/forwardproxy` commit (the `naive` branch tip at
/// 2026-06 — `v0.0.0-20250118002110-d62c80d3dd2c`). Pinning the exact
/// commit (not the moving `@naive` branch) makes the supply chain
/// reproducible — a force-push to the branch can't change what we ship.
pub(crate) const FORWARDPROXY_PIN: &str = "d62c80d3dd2c";

/// The masquerade site served to unauthenticated probes. Constant
/// (no per-deploy state), so it's provisioned once in `ensure_installed`
/// rather than re-rendered every `apply_config`.
const MASQUERADE_INDEX_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>edge cache</title>
<style>
  :root{color-scheme:light dark}
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;
       display:flex;min-height:100vh;align-items:center;justify-content:center;background:#0f1115;color:#e6e8ec}
  .card{max-width:440px;padding:2.5rem;text-align:center}
  h1{font-size:1.4rem;font-weight:600;margin:0 0 .5rem}
  p{color:#9aa0a6;line-height:1.5;margin:.4rem 0}
  .dot{display:inline-block;width:.55rem;height:.55rem;border-radius:50%;background:#3fb950;margin-right:.4rem}
  code{color:#7d8590;font-size:.85rem}
</style>
</head>
<body>
  <div class="card">
    <h1><span class="dot"></span>edge node operational</h1>
    <p>This endpoint serves static assets from the edge cache.</p>
    <p><code>cache: HIT &middot; region: eu-central</code></p>
  </div>
</body>
</html>
"#;

#[derive(Debug, Default)]
pub struct Caddy;

impl Caddy {
    pub fn new() -> Self {
        Self
    }
}

/// JSON envelope returned by `Naive::server_inbound`. Deserialised here,
/// walked to assemble the Caddyfile. Private to the kernel: the contract
/// is "consume the protocol's envelope shape".
#[derive(Debug, Deserialize)]
struct NaiveEnvelope {
    domain: String,
    #[serde(default)]
    acme_email: String,
    auth: Vec<NaiveAuth>,
}

#[derive(Debug, Deserialize)]
struct NaiveAuth {
    username: String,
    password: String,
}

#[async_trait]
impl Kernel for Caddy {
    fn id(&self) -> KernelId {
        KernelId("caddy".to_string())
    }

    fn supported_protocols(&self) -> Vec<ProtocolId> {
        vec![ProtocolId("naive".to_string())]
    }

    async fn ensure_installed(&self, ssh: &dyn SshTransport) -> Result<()> {
        // Built from source (stock apt caddy has no forwardproxy), same
        // shape as wgturn's Go build. Heavy on a 1-vCPU/1-GB box (~10
        // min, RAM-tight) — hence the temporary build swapfile and
        // `GOFLAGS=-p=1` to cap parallelism/peak-RAM. Fully idempotent:
        // a node that already has the plugin skips straight to the
        // user/site/unit provisioning.
        let script = format!(
            r#"
            set -eu
            export DEBIAN_FRONTEND=noninteractive

            if command -v /usr/local/bin/caddy >/dev/null 2>&1 \
               && /usr/local/bin/caddy list-modules 2>/dev/null | grep -q forward_proxy; then
                echo "caddy+forwardproxy already present: $(/usr/local/bin/caddy version | head -1)"
            else
                apt-get update -qq
                apt-get install -y --no-install-recommends git curl ca-certificates

                # Temporary build swap on low-RAM boxes (Go build peaks
                # well above 960 MB). Removed again after the build.
                ADDED_SWAP=0
                if ! swapon --show 2>/dev/null | grep -q /caddy-build-swap; then
                    total_mb=$(free -m | awk '/Mem/{{print $2}}')
                    if [ "$total_mb" -lt 1300 ]; then
                        fallocate -l 1G /caddy-build-swap 2>/dev/null \
                            || dd if=/dev/zero of=/caddy-build-swap bs=1M count=1024 status=none
                        chmod 600 /caddy-build-swap
                        mkswap /caddy-build-swap >/dev/null
                        swapon /caddy-build-swap
                        ADDED_SWAP=1
                    fi
                fi

                curl -fsSL -o /tmp/go.tgz "https://go.dev/dl/{go_version}.linux-amd64.tar.gz"
                rm -rf /usr/local/go
                tar -C /usr/local -xzf /tmp/go.tgz
                rm -f /tmp/go.tgz
                export PATH="$PATH:/usr/local/go/bin:/root/go/bin"
                export GOFLAGS=-p=1 GOMAXPROCS=1 CGO_ENABLED=0

                go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
                /root/go/bin/xcaddy build {caddy_version} \
                    --with github.com/caddyserver/forwardproxy=github.com/klzgrad/forwardproxy@{fp_pin} \
                    --output /usr/local/bin/caddy

                /usr/local/bin/caddy list-modules | grep -q forward_proxy

                if [ "$ADDED_SWAP" = 1 ]; then
                    swapoff /caddy-build-swap 2>/dev/null || true
                    rm -f /caddy-build-swap
                fi
            fi

            # Service user, data dir, web root, config dir.
            id caddy >/dev/null 2>&1 \
                || useradd --system --home /var/lib/caddy --shell /usr/sbin/nologin caddy
            install -d -o caddy -g caddy -m 0755 /var/lib/caddy /var/www/naive-site
            install -d -m 0755 /etc/caddy

            # Masquerade site (constant — provisioned once here).
            cat > /var/www/naive-site/index.html <<'NAIVE_SITE_EOF'
{site}NAIVE_SITE_EOF
            chown -R caddy:caddy /var/www/naive-site

            # systemd unit. Type=notify + CAP_NET_BIND_SERVICE so the
            # non-root caddy user can bind 80/443.
            cat > /etc/systemd/system/caddy.service <<'CADDY_UNIT_EOF'
[Unit]
Description=Caddy (naive forward proxy)
Documentation=https://caddyserver.com/docs/
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=caddy
Group=caddy
Environment=XDG_DATA_HOME=/var/lib/caddy
Environment=XDG_CONFIG_HOME=/var/lib/caddy
ExecStart=/usr/local/bin/caddy run --config /etc/caddy/Caddyfile
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile --force
TimeoutStartSec=120
TimeoutStopSec=5s
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
CADDY_UNIT_EOF
            systemctl daemon-reload

            # naive needs 80 (ACME HTTP) + 443. vpnctl doesn't manage the
            # firewall elsewhere, but a closed 80/443 here means no cert
            # and no service — so open them best-effort when ufw is present.
            if command -v ufw >/dev/null 2>&1; then
                ufw allow 80/tcp  >/dev/null 2>&1 || true
                ufw allow 443/tcp >/dev/null 2>&1 || true
            fi

            command -v /usr/local/bin/caddy
            "#,
            go_version = GO_VERSION,
            caddy_version = CADDY_VERSION,
            fp_pin = FORWARDPROXY_PIN,
            site = MASQUERADE_INDEX_HTML,
        );
        ssh.exec(&script).await?;
        Ok(())
    }

    fn render_config(
        &self,
        ctx: &RenderCtx<'_>,
        users: &[User],
        protocols: &[&dyn Protocol],
    ) -> Result<Vec<u8>> {
        // Locate the naive protocol — the only thing this kernel serves.
        // Registry::validate_server should have caught a mismatch; this
        // is the defense-in-depth layer (mirrors amnezia_wg).
        let naive = protocols
            .iter()
            .find(|p| p.id() == ProtocolId("naive".to_string()))
            .ok_or_else(|| {
                CoreError::Render("caddy kernel requires the naive protocol in `protocols`".into())
            })?;

        let envelope_json = naive.server_inbound(ctx, users)?;
        let env: NaiveEnvelope = serde_json::from_value(envelope_json)
            .map_err(|e| CoreError::Render(format!("naive envelope parse: {e}")))?;

        if env.domain.trim().is_empty() {
            return Err(CoreError::Render(
                "naive requires a non-empty `naive.domain` secret".into(),
            ));
        }
        // Fail closed: EVERY operator-supplied field written into the
        // Caddyfile (domain, acme_email, and each basic_auth user/pass)
        // is rejected if it carries a char that could break out of its
        // line/block and inject a directive. Upstream constraints (user
        // ids `^[a-z0-9._-]{2,32}$`, generated passwords) make this
        // defense-in-depth today; `caddy validate` in apply_config is a
        // backstop, not the primary defence.
        const ILLEGAL: [char; 5] = ['\n', '\r', ' ', '{', '}'];
        if env.domain.contains(ILLEGAL) {
            return Err(CoreError::Render(format!(
                "naive.domain contains illegal characters: {:?}",
                env.domain
            )));
        }
        if env.acme_email.contains(ILLEGAL) {
            return Err(CoreError::Render(format!(
                "naive.acme_email contains illegal characters: {:?}",
                env.acme_email
            )));
        }
        for a in &env.auth {
            if a.username.contains(ILLEGAL) || a.password.contains(ILLEGAL) {
                return Err(CoreError::Render(format!(
                    "naive basic_auth for '{}' contains illegal characters",
                    a.username
                )));
            }
        }

        // Assemble the Caddyfile. Structure verified live on the
        // experimental node (docs/NAIVE_CADDY_PLAN.md Phase 0). The
        // `:443, <domain>` form is LOAD-BEARING: a proxy CONNECT carries
        // the *target* host as `:authority`, so a bare `<domain> {`
        // block never matches it — the `:443` catch-all matcher does.
        let mut out = String::with_capacity(1024);
        out.push_str("# Rendered by vpnctl. Do not hand-edit \u{2014} your changes will be\n");
        out.push_str("# overwritten on next `vpnctl deploy`.\n");
        out.push_str("{\n");
        out.push_str("\torder forward_proxy before file_server\n");
        if !env.acme_email.trim().is_empty() {
            out.push_str(&format!("\temail {}\n", env.acme_email));
        }
        out.push_str("\tlog {\n\t\texclude http.log.error\n\t}\n");
        out.push_str("}\n\n");

        out.push_str(&format!(":443, {} {{\n", env.domain));
        if !env.acme_email.trim().is_empty() {
            out.push_str(&format!("\ttls {}\n", env.acme_email));
        }
        out.push_str("\tencode\n");
        out.push_str("\theader -Server\n");

        if env.auth.is_empty() {
            // No granted users yet → no proxy, just the cover website.
            // (probe_resistance without basic_auth is meaningless and
            // can reject config; a plain file_server is the correct
            // degenerate render.)
            out.push_str("\tfile_server {\n\t\troot /var/www/naive-site\n\t}\n");
        } else {
            out.push_str("\tforward_proxy {\n");
            for a in &env.auth {
                out.push_str(&format!("\t\tbasic_auth {} {}\n", a.username, a.password));
            }
            out.push_str("\t\thide_ip\n");
            out.push_str("\t\thide_via\n");
            out.push_str("\t\tprobe_resistance\n");
            out.push_str("\t}\n");
            out.push_str("\tfile_server {\n\t\troot /var/www/naive-site\n\t}\n");
        }
        out.push_str("}\n");

        Ok(out.into_bytes())
    }

    async fn apply_config(&self, ssh: &dyn SshTransport, config: &[u8]) -> Result<()> {
        ssh.upload("/etc/caddy/Caddyfile.new", config).await?;
        // Validate BEFORE swapping in (a bad Caddyfile must never take
        // down a running proxy). Atomic rename, lock perms, reload.
        // First start has to obtain the ACME cert, which can take
        // ~10-20 s, so the active-poll window is wider than sing-box's
        // 8 s (CLAUDE.md staging-deploy lesson #3 — never report
        // "complete" on a crash-loop).
        let cmd = r#"
            set -eu
            /usr/local/bin/caddy validate --config /etc/caddy/Caddyfile.new
            mv /etc/caddy/Caddyfile.new /etc/caddy/Caddyfile
            chown caddy:caddy /etc/caddy/Caddyfile
            chmod 0644 /etc/caddy/Caddyfile

            systemctl enable caddy >/dev/null 2>&1 || true
            systemctl reload-or-restart caddy

            for i in $(seq 1 10); do
                state=$(systemctl is-active caddy || true)
                [ "$state" = "active" ] && exit 0
                sleep 3
            done

            echo "caddy did not become active. Last 20 log lines:" >&2
            journalctl -u caddy --no-pager -n 20 >&2 || true
            exit 1
        "#;
        ssh.exec(cmd).await?;
        Ok(())
    }

    async fn restart(&self, ssh: &dyn SshTransport) -> Result<()> {
        ssh.exec("systemctl restart caddy").await?;
        Ok(())
    }

    async fn status(&self, ssh: &dyn SshTransport) -> Result<KernelStatus> {
        let active = ssh
            .exec("systemctl is-active caddy")
            .await?
            .trim()
            .eq("active");
        let version = ssh
            .exec("/usr/local/bin/caddy version 2>/dev/null | head -1")
            .await
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        Ok(KernelStatus {
            active,
            version,
            uptime_seconds: None,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use vpnctl_core::{Server, ServerId, UserId};
    use vpnctl_protocols::Naive;

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
        assert_eq!(c.supported_protocols(), vec![ProtocolId("naive".into())]);
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
}
