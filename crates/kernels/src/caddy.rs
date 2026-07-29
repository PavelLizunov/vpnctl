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
use sha2::{Digest, Sha256};
use vpnctl_core::{
    CoreError, Kernel, KernelId, KernelStatus, Protocol, ProtocolId, RenderCtx, Result,
    SshTransport, User,
};

/// Pinned Go toolchain for the on-node `xcaddy` build. Bump in lockstep
/// with [`CADDY_VERSION`] when Caddy needs a newer Go. (wgturn pins its
/// Go the same way.)
pub(crate) const GO_VERSION: &str = "go1.26.4";

/// Pinned SHA-256 of the official Go toolchain tarball downloaded by
/// the on-node build fallback. Source: `https://go.dev/dl/` — each
/// release publishes a `.sha256` sidecar (fetched 2026-07-29 from
/// `https://dl.google.com/go/go1.26.4.linux-amd64.tar.gz.sha256`).
/// Bumping [`GO_VERSION`] REQUIRES re-fetching the new digest.
const GO_TARBALL_SHA256: &str = "1153d3d50e0ac764b447adfe05c2bcf08e889d42a02e0fe0259bd47f6733ad7f";

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

// ───────────── vless-ws (VLESS/WebSocket+TLS direct) ─────────────
// The caddy kernel ALSO serves the `vless-ws` protocol: caddy terminates
// a real Let's-Encrypt cert on an alt-port, serves the decoy site at `/`,
// and reverse_proxies ONE secret path to a loopback sing-box VLESS+ws
// inbound. The kernel owns BOTH units (caddy + `caddy-vlessws` sing-box)
// via the `BUNDLE_DELIMITER` + second-systemd-unit pattern `dns_tunnel`
// already runs in prod. See `crates/protocols/src/vless_ws.rs`.

/// Loopback port the sing-box VLESS+ws backend listens on (caddy's
/// `reverse_proxy` upstream). Loopback-only + uniform across the fleet,
/// so it's never in a firewall rule and never the public-facing port. A
/// node running dns-tunnel (loopback :9001) and vless-ws (loopback :11443)
/// doesn't conflict.
const VLESSWS_BACKEND_PORT: u16 = 11443;

/// On-node Caddyfile path (shared by the naive single-file path and the
/// vless-ws bundle).
const CADDYFILE_PATH: &str = "/etc/caddy/Caddyfile";
/// On-node path of the loopback sing-box config + its systemd unit name.
const VLESSWS_SINGBOX_CONFIG: &str = "/etc/caddy/vlessws-singbox.json";
const VLESSWS_UNIT: &str = "caddy-vlessws";
/// Rendered firewall-meta member: carries the operator-chosen front port
/// so `apply_config` can `ufw allow` it without re-parsing the Caddyfile.
const VLESSWS_DEPLOY_ENV: &str = "/etc/caddy/.vlessws-deploy.env";

/// Multi-file bundle delimiter — identical framing to
/// `crates/kernels/src/dns_tunnel.rs::BUNDLE_DELIMITER`. The vless-ws
/// `render_config` emits `Caddyfile` + sing-box JSON + the firewall meta
/// in this shape; `apply_config` unpacks it. The naive render (a single
/// Caddyfile starting with `# Rendered by vpnctl`) never begins with this
/// marker, so `apply_config` dispatches the two shapes unambiguously.
const BUNDLE_DELIMITER: &str = "====FILE: ";
const BUNDLE_DELIMITER_END: &str = "====";

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

/// JSON envelope returned by `VlessWs::server_inbound`. Deserialised here,
/// walked to assemble the Caddyfile (decoy + `reverse_proxy` of the secret
/// path) AND the loopback sing-box ws config. Private to the kernel: the
/// contract is "consume the protocol's envelope shape".
#[derive(Debug, Deserialize)]
struct VlessWsEnvelope {
    domain: String,
    #[serde(default)]
    acme_email: String,
    front_port: u16,
    /// Secret ws path WITH the leading slash (`/<secret>`), as the protocol
    /// emits it — used verbatim in both the Caddyfile `path` matcher and
    /// the sing-box `transport.path` so they agree byte-for-byte.
    path: String,
    #[serde(default)]
    users: Vec<VlessWsUser>,
}

#[derive(Debug, Deserialize)]
struct VlessWsUser {
    uuid: String,
    #[serde(default)]
    name: String,
}

/// Path on the CONTROL node where a prebuilt **static** (CGO-free) amd64
/// `caddy` (with the naive forwardproxy) is cached. When present,
/// `ensure_installed` uploads it to the target node — seconds, with no
/// Go toolchain / build swap / RAM pressure on the node. The SAME static
/// binary runs on any Linux amd64 host (Go static binaries have no libc
/// dependency), so one build serves the whole fleet. Populate it once
/// (CI artifact or `scp` from any already-built node). Override the path
/// via the `VPNCTL_CADDY_CACHE` env var.
pub(crate) fn caddy_cache_path() -> std::path::PathBuf {
    std::env::var_os("VPNCTL_CADDY_CACHE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(default_caddy_cache_path)
}

/// Default cache path, stamped with the Caddy + forwardproxy versions so
/// a version bump invalidates the old cache (a stale binary would
/// silently ship the wrong version). Pure (reads no env) → deterministic
/// to test.
pub(crate) fn default_caddy_cache_path() -> std::path::PathBuf {
    std::path::PathBuf::from(format!(
        "/var/lib/vpnctl/cache/caddy-{CADDY_VERSION}-{FORWARDPROXY_PIN}-amd64"
    ))
}

/// Classify the idempotency-probe stdout. Pure (testable) so an inverted
/// branch can't slip through CI: the node is "ready" only when the probe
/// printed exactly `present` (caddy on PATH AND the forward_proxy module
/// compiled in).
fn caddy_present(probe_stdout: &str) -> bool {
    probe_stdout.trim() == "present"
}

/// Decide whether the on-node caddy binary must be (re)installed from the
/// control-node cache. Content-aware (sha256), NOT a bare presence check:
/// an operator who replaces the cached binary with a patched build (same
/// path, different bytes) MUST get it pushed on the next `vpnctl deploy`
/// without first deleting the on-node binary by hand.
///
/// * `cache_sha` — lowercase hex sha256 of the cache binary's bytes
///   (computed control-side; the same digest fed to `sha256sum -c`).
/// * `node_sha_stdout` — raw stdout of `sha256sum <bin> | cut -d' ' -f1`
///   on the node; EMPTY (binary absent) or any value `!= cache_sha`
///   means reinstall.
///
/// Pure → unit-tested directly so an inverted branch can't slip past CI.
/// Mirrors `dns_tunnel::slipstream_needs_reinstall`.
fn caddy_needs_reinstall(cache_sha: &str, node_sha_stdout: &str) -> bool {
    node_sha_stdout.trim() != cache_sha
}

/// On-node build fallback (no cache present): install Go + xcaddy and
/// build caddy with the naive forwardproxy. Heavy on a 1-vCPU/1-GB box
/// (~10 min, RAM-tight) — hence the temporary build swapfile and
/// `GOFLAGS=-p=1`. `CGO_ENABLED=0` makes the result the same portable
/// static binary the cache path ships.
fn caddy_build_script() -> String {
    format!(
        r#"
        set -eu
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y --no-install-recommends git curl ca-certificates

        # Temporary build swap on low-RAM boxes (Go build peaks well above
        # 960 MB). Removed again after the build.
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
        # Verify the tarball digest BEFORE extraction. The pinned
        # SHA-256 comes from the official go.dev/dl .sha256 sidecar
        # (see GO_TARBALL_SHA256).
        echo "{go_sha256}  /tmp/go.tgz" | sha256sum -c - >/dev/null
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
        "#,
        go_version = GO_VERSION,
        go_sha256 = GO_TARBALL_SHA256,
        caddy_version = CADDY_VERSION,
        fp_pin = FORWARDPROXY_PIN,
    )
}

/// Provision the node runtime regardless of how the binary arrived:
/// service user, masquerade web root + site, systemd unit, firewall.
/// Idempotent — safe to re-run on every deploy.
fn caddy_runtime_provision_script() -> String {
    format!(
        r#"
        set -eu
        id caddy >/dev/null 2>&1 \
            || useradd --system --home /var/lib/caddy --shell /usr/sbin/nologin caddy
        install -d -o caddy -g caddy -m 0755 /var/lib/caddy /var/www/naive-site
        install -d -m 0755 /etc/caddy

        # Masquerade site (constant — provisioned here).
        cat > /var/www/naive-site/index.html <<'NAIVE_SITE_EOF'
{site}NAIVE_SITE_EOF
        chown -R caddy:caddy /var/www/naive-site

        # systemd unit. Type=notify + CAP_NET_BIND_SERVICE so the non-root
        # caddy user can bind 80/443.
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

        # vless-ws loopback sing-box backend unit (caddy's reverse_proxy
        # upstream). Provisioned unconditionally — harmless on a naive node
        # (never started; only apply_config's vless-ws path starts it, once
        # its config exists). References the box's existing /usr/bin/sing-box.
        cat > /etc/systemd/system/{vlessws_unit}.service <<'VLESSWS_UNIT_EOF'
[Unit]
Description=sing-box VLESS+ws backend for vless-ws (loopback 127.0.0.1:11443) — vpnctl-managed
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/sing-box run -c {vlessws_config}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
VLESSWS_UNIT_EOF
        systemctl daemon-reload

        # naive needs 80 (ACME HTTP) + 443. vpnctl doesn't manage the
        # firewall elsewhere, but a closed 80/443 here means no cert and
        # no service — so open them best-effort when ufw is present.
        if command -v ufw >/dev/null 2>&1; then
            ufw allow 80/tcp  >/dev/null 2>&1 || true
            ufw allow 443/tcp >/dev/null 2>&1 || true
        fi

        command -v /usr/local/bin/caddy
        "#,
        site = MASQUERADE_INDEX_HTML,
        vlessws_unit = VLESSWS_UNIT,
        vlessws_config = VLESSWS_SINGBOX_CONFIG,
    )
}

/// Render the vless-ws deploy BUNDLE: the Caddyfile (decoy `file_server` +
/// `reverse_proxy` of the secret path → loopback sing-box) + the loopback
/// sing-box ws config + a firewall-port meta file, in the
/// `BUNDLE_DELIMITER` framing `apply_config` unpacks. Mirrors
/// `dns_tunnel::render_config`'s two-file bundle.
fn render_vlessws_bundle(
    ctx: &RenderCtx<'_>,
    users: &[User],
    proto: &dyn Protocol,
) -> Result<Vec<u8>> {
    let env_json = proto.server_inbound(ctx, users)?;
    let env: VlessWsEnvelope = serde_json::from_value(env_json)
        .map_err(|e| CoreError::Render(format!("vless-ws envelope parse: {e}")))?;

    // Defense-in-depth: the protocol already injection-guards domain/path,
    // but re-reject here before they land in the Caddyfile (mirrors the
    // naive render's ILLEGAL guard). `caddy validate` in apply_config is a
    // backstop, not the primary defence.
    const ILLEGAL: [char; 5] = ['\n', '\r', ' ', '{', '}'];
    if env.domain.trim().is_empty() || env.domain.contains(ILLEGAL) {
        return Err(CoreError::Render(format!(
            "vless-ws domain is empty or contains illegal characters: {:?}",
            env.domain
        )));
    }
    if env.acme_email.contains(ILLEGAL) {
        return Err(CoreError::Render(format!(
            "vless-ws acme_email contains illegal characters: {:?}",
            env.acme_email
        )));
    }
    // `path` is `/<secret>`; the secret is `[A-Za-z0-9_-]` (protocol-checked).
    // Re-reject anything that could break the Caddyfile `path` token / JSON.
    if !env.path.starts_with('/')
        || env.path.len() < 2
        || !env.path[1..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(CoreError::Render(format!(
            "vless-ws path must be `/<[A-Za-z0-9_-]+>`: {:?}",
            env.path
        )));
    }

    let has_users = !env.users.is_empty();

    // ── 1. Caddyfile ──────────────────────────────────────────────────
    let mut cf = String::with_capacity(1024);
    cf.push_str("# Rendered by vpnctl. Do not hand-edit \u{2014} your changes will be\n");
    cf.push_str("# overwritten on next `vpnctl deploy`.\n");
    cf.push_str("{\n");
    if !env.acme_email.trim().is_empty() {
        cf.push_str(&format!("\temail {}\n", env.acme_email));
    }
    // Disable HTTP/3 — caddy otherwise binds UDP on the front port, which
    // collides with a co-tenant QUIC protocol (TUIC / hysteria2) sharing
    // that port number on the node (caught on `is`: tuic-v5 holds UDP:8443,
    // so caddy's h3 listener failed with `address already in use`). The ws
    // tunnel is TCP-only, so h3 buys nothing here.
    cf.push_str("\tservers {\n\t\tprotocols h1 h2\n\t}\n");
    cf.push_str("\tlog {\n\t\texclude http.log.error\n\t}\n");
    cf.push_str("}\n\n");

    cf.push_str(&format!("{}:{} {{\n", env.domain, env.front_port));
    if !env.acme_email.trim().is_empty() {
        cf.push_str(&format!("\ttls {}\n", env.acme_email));
    }
    cf.push_str("\tencode\n");
    cf.push_str("\theader -Server\n");
    if has_users {
        // Route ONLY the secret path to the ws backend; everything else
        // (including a wrong path) falls through to the decoy file_server
        // → an active probe sees a real site, never a bare-proxy tell.
        // `reverse_proxy` upgrades the WebSocket transparently.
        cf.push_str(&format!("\t@vlessws path {}\n", env.path));
        cf.push_str(&format!(
            "\treverse_proxy @vlessws 127.0.0.1:{VLESSWS_BACKEND_PORT}\n"
        ));
    }
    cf.push_str("\tfile_server {\n\t\troot /var/www/naive-site\n\t}\n");
    cf.push_str("}\n");

    // ── 2. Loopback sing-box VLESS+ws config ──────────────────────────
    // NO `tls` (caddy is the sole TLS edge), NO `flow` (XTLS-Vision is
    // incompatible with a ws transport). The vless inbound exists ONLY
    // when there are users; an empty `inbounds` is a valid sing-box config
    // (the unit starts cleanly and does nothing) — mirrors naive's
    // decoy-only degenerate render.
    let inbounds = if has_users {
        let users_json: Vec<serde_json::Value> = env
            .users
            .iter()
            .map(|u| serde_json::json!({ "uuid": u.uuid, "name": u.name }))
            .collect();
        serde_json::json!([{
            "type": "vless",
            "tag": "vlessws-in",
            "listen": "127.0.0.1",
            "listen_port": VLESSWS_BACKEND_PORT,
            "users": users_json,
            "transport": { "type": "ws", "path": env.path }
        }])
    } else {
        serde_json::json!([])
    };
    let sb = serde_json::json!({
        "log": { "level": "warn" },
        "inbounds": inbounds,
        "outbounds": [ { "type": "direct", "tag": "direct" } ]
    });
    let sb_json = serde_json::to_string_pretty(&sb)
        .map_err(|e| CoreError::Render(format!("vless-ws sing-box config marshal: {e}")))?;

    // ── 3. Firewall meta (front port for apply_config's ufw) ──────────
    let meta = format!("VLESSWS_FRONT_PORT={}\n", env.front_port);

    // ── Assemble the bundle (dns_tunnel framing) ──────────────────────
    let mut bundle = String::with_capacity(cf.len() + sb_json.len() + meta.len() + 256);
    for (path, body) in [
        (CADDYFILE_PATH, cf.as_str()),
        (VLESSWS_SINGBOX_CONFIG, sb_json.as_str()),
        (VLESSWS_DEPLOY_ENV, meta.as_str()),
    ] {
        bundle.push_str(BUNDLE_DELIMITER);
        bundle.push_str(path);
        bundle.push_str(BUNDLE_DELIMITER_END);
        bundle.push('\n');
        bundle.push_str(body);
        if !body.ends_with('\n') {
            bundle.push('\n');
        }
    }
    Ok(bundle.into_bytes())
}

/// The bundle-unpack + atomic-swap + verify + ROLLBACK script run after the
/// vless-ws deploy bundle has been uploaded to `…/.vlessws-bundle.new`.
/// Two units: the loopback sing-box BACKEND (restarted FIRST so caddy's
/// `reverse_proxy` upstream is up) and caddy itself. Mirrors
/// `dns_tunnel::dns_tunnel_apply_script`'s snapshot/rollback discipline,
/// plus a `caddy validate` before the swap and a wider (caddy ACME) poll.
fn vlessws_apply_script() -> String {
    format!(
        r#"
            set -eu
            BUNDLE=/etc/caddy/.vlessws-bundle.new
            test -f "$BUNDLE"

            # Unpack the bundle (same framing as dns_tunnel). awk splits on
            # the marker line and writes each member to `<path>.new`.
            awk '
                BEGIN {{ outfile = ""; }}
                /^====FILE: .*====$/ {{
                    if (outfile != "") {{ close(outfile); }}
                    path = $0
                    sub(/^====FILE: /, "", path)
                    sub(/====$/, "", path)
                    outfile = path ".new"
                    next
                }}
                {{
                    if (outfile != "") {{ print > outfile }}
                }}
            ' "$BUNDLE"

            # Validate the NEW Caddyfile BEFORE swapping (a bad Caddyfile
            # must never take down the running edge).
            /usr/local/bin/caddy validate --config {caddyfile}.new

            # Snapshot live configs for rollback (guarded on existence —
            # first deploy has none; -a preserves owner/mode).
            for f in {caddyfile} {sb_config}; do
                [ -f "$f" ] && cp -a "$f" "$f.bak" || true
            done

            # Atomic swaps + perms.
            mv {caddyfile}.new {caddyfile}
            chown caddy:caddy {caddyfile}
            chmod 0644 {caddyfile}
            mv {sb_config}.new {sb_config}
            chown root:root {sb_config}
            chmod 0644 {sb_config}
            mv {deploy_env}.new {deploy_env}
            chmod 0644 {deploy_env}
            rm -f "$BUNDLE"

            # Firewall: open ACME :80 + the operator-chosen front port
            # (best-effort; a host without ufw is a clean no-op). The front
            # port comes from the rendered meta member.
            if command -v ufw >/dev/null 2>&1; then
                ufw allow 80/tcp >/dev/null 2>&1 || true
                . {deploy_env} 2>/dev/null || true
                if [ -n "${{VLESSWS_FRONT_PORT:-}}" ]; then
                    ufw allow "${{VLESSWS_FRONT_PORT}}/tcp" >/dev/null 2>&1 || true
                fi
            fi

            # Restart the BACKEND (loopback sing-box) FIRST so caddy's
            # reverse_proxy upstream is reachable when caddy reloads.
            systemctl enable {vlessws_unit} >/dev/null 2>&1 || true
            systemctl restart {vlessws_unit}
            systemctl enable caddy >/dev/null 2>&1 || true
            systemctl reload-or-restart caddy

            # Poll BOTH units. caddy's first ACME issue can take ~20 s, so
            # 15x2 s. On ANY unit failing, roll BOTH configs back + restart
            # both (backend-first), returning the node to last-good instead
            # of crash-looping. Each restore step `|| true`-guarded so the
            # branch always reaches `exit 1`.
            for s in {vlessws_unit} caddy; do
                ok=0
                for i in $(seq 1 15); do
                    [ "$(systemctl is-active "$s" 2>/dev/null || true)" = active ] && {{ ok=1; break; }}
                    sleep 2
                done
                if [ "$ok" != 1 ]; then
                    echo "$s did not become active. Last 20 log lines:" >&2
                    journalctl -u "$s" --no-pager -n 20 >&2 || true
                    [ -f {caddyfile}.bak ] && mv {caddyfile}.bak {caddyfile} || true
                    [ -f {sb_config}.bak ] && mv {sb_config}.bak {sb_config} || true
                    systemctl restart {vlessws_unit} || true
                    systemctl reload-or-restart caddy || true
                    exit 1
                fi
            done

            # Both up — drop the transient snapshots.
            rm -f {caddyfile}.bak {sb_config}.bak
        "#,
        caddyfile = CADDYFILE_PATH,
        sb_config = VLESSWS_SINGBOX_CONFIG,
        deploy_env = VLESSWS_DEPLOY_ENV,
        vlessws_unit = VLESSWS_UNIT,
    )
}

#[async_trait]
impl Kernel for Caddy {
    fn id(&self) -> KernelId {
        KernelId("caddy".to_string())
    }

    fn supported_protocols(&self) -> Vec<ProtocolId> {
        vec![
            ProtocolId("naive".to_string()),
            ProtocolId("vless-ws".to_string()),
        ]
    }

    async fn ensure_installed(&self, ssh: &dyn SshTransport) -> Result<()> {
        // FAST PATH: a prebuilt static (CGO-free) amd64 caddy cached on
        // the CONTROL node — upload it (seconds; no Go/swap/RAM pressure
        // on the target). The same binary runs on any amd64 node.
        // SLOW FALLBACK: build on the node via xcaddy (~10 min) when no
        // cache is present (e.g. a CLI deploy from a host without it).
        let cache = caddy_cache_path();
        match std::fs::read(&cache) {
            Ok(bytes) => {
                // Content-aware idempotency: SHA256 the cache bytes up front
                // (the same digest fed to `sha256sum -c` on the transfer) and
                // probe the on-node binary's sha (empty when absent). Reinstall
                // when the on-node binary is absent OR its sha differs from the
                // cache sha, so an operator who refreshes the cached binary
                // (same path, patched bytes) gets it pushed WITHOUT first
                // deleting the on-node copy by hand. A bare presence check
                // would skip the refresh. Mirrors dns_tunnel::ensure_installed.
                let digest = format!("{:x}", Sha256::digest(&bytes));
                let node_sha = ssh
                    .exec("sha256sum /usr/local/bin/caddy 2>/dev/null | cut -d' ' -f1")
                    .await?;
                if caddy_needs_reinstall(&digest, &node_sha) {
                    // Integrity-verify on the node before installing it as a
                    // root systemd service: upload the cache bytes to .new,
                    // `sha256sum -c` the control-side digest there, then atomic
                    // mv. `set -eu` aborts the deploy on a corrupted/truncated
                    // upload.
                    ssh.upload("/usr/local/bin/caddy.new", &bytes).await?;
                    ssh.exec(&format!(
                        "set -eu\n\
                         echo '{digest}  /usr/local/bin/caddy.new' | sha256sum -c - >/dev/null\n\
                         chmod 0755 /usr/local/bin/caddy.new\n\
                         mv -f /usr/local/bin/caddy.new /usr/local/bin/caddy\n\
                         /usr/local/bin/caddy list-modules | grep -q forward_proxy"
                    ))
                    .await?;
                }
            }
            // No cache → build on the node, gated on a presence probe (caddy
            // on PATH AND forward_proxy compiled in). A cache path that's SET
            // but unreadable (bad VPNCTL_CADDY_CACHE, wrong perms, a dir)
            // fails loudly rather than silently triggering a 10-min build.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let present = ssh
                    .exec(
                        "command -v /usr/local/bin/caddy >/dev/null 2>&1 \
                         && /usr/local/bin/caddy list-modules 2>/dev/null | grep -q forward_proxy \
                         && echo present || echo absent",
                    )
                    .await?;
                if !caddy_present(&present) {
                    ssh.exec(&caddy_build_script()).await?;
                }
            }
            Err(e) => return Err(CoreError::Io(e)),
        }

        // Provision the runtime (user, masquerade site, systemd unit,
        // firewall) regardless of how the binary arrived. Idempotent.
        ssh.exec(&caddy_runtime_provision_script()).await?;
        Ok(())
    }

    fn render_config(
        &self,
        ctx: &RenderCtx<'_>,
        users: &[User],
        protocols: &[&dyn Protocol],
    ) -> Result<Vec<u8>> {
        // The caddy kernel serves naive OR vless-ws — EXACTLY ONE per node.
        // Both manage the LE cert and bind the front port, and this kernel
        // renders one Caddyfile shape (not a merged one). vless-ws renders a
        // multi-file BUNDLE (Caddyfile + loopback sing-box); naive a single
        // Caddyfile.
        let vlessws = protocols
            .iter()
            .find(|p| p.id() == ProtocolId("vless-ws".to_string()));
        let naive_present = protocols
            .iter()
            .any(|p| p.id() == ProtocolId("naive".to_string()));
        if let Some(vlessws) = vlessws {
            // Refuse a node that enables BOTH rather than silently dropping
            // naive's config (which would break live naive clients). The
            // operator must disable one on the server. (The fleet never does
            // both — cdn=naive, de/is/nl=vless-ws — so this is a guard, not
            // a limitation hit in practice.)
            if naive_present {
                return Err(CoreError::Render(
                    "caddy kernel: a server has BOTH `naive` and `vless-ws` enabled, but the \
                     caddy kernel serves exactly one front protocol per node (they contend for \
                     the LE cert + front port). Disable one of them on this server."
                        .into(),
                ));
            }
            return render_vlessws_bundle(ctx, users, *vlessws);
        }

        // Locate the naive protocol. Registry::validate_server should have
        // caught a mismatch; this is the defense-in-depth layer (mirrors
        // amnezia_wg).
        let naive = protocols
            .iter()
            .find(|p| p.id() == ProtocolId("naive".to_string()))
            .ok_or_else(|| {
                CoreError::Render(
                    "caddy kernel requires the naive or vless-ws protocol in `protocols`".into(),
                )
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
        // The caddy kernel emits TWO artefact shapes: a vless-ws multi-file
        // BUNDLE (starts with the `====FILE: ` delimiter) or a single naive
        // Caddyfile. Dispatch on the discriminator so the naive path stays
        // byte-for-byte unchanged.
        if config.starts_with(BUNDLE_DELIMITER.as_bytes()) {
            ssh.upload("/etc/caddy/.vlessws-bundle.new", config).await?;
            ssh.exec(&vlessws_apply_script()).await?;
            return Ok(());
        }
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
}
