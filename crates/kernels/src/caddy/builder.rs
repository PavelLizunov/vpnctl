use super::render::{VLESSWS_SINGBOX_CONFIG, VLESSWS_UNIT};

/// Pinned Go toolchain for the on-node `xcaddy` build. Bump in lockstep
/// with [`CADDY_VERSION`] when Caddy needs a newer Go.
pub(crate) const GO_VERSION: &str = "go1.26.4";

/// Pinned SHA-256 of the official Go toolchain tarball downloaded by
/// the on-node build fallback. Source: `https://go.dev/dl/` — each
/// release publishes a `.sha256` sidecar (fetched 2026-07-29 from
/// `https://dl.google.com/go/go1.26.4.linux-amd64.tar.gz.sha256`).
/// Bumping [`GO_VERSION`] REQUIRES re-fetching the new digest.
pub(crate) const GO_TARBALL_SHA256: &str =
    "1153d3d50e0ac764b447adfe05c2bcf08e889d42a02e0fe0259bd47f6733ad7f";

/// Pinned Caddy release the plugin is compiled against. xcaddy's
/// `build <version>` keeps the binary reproducible across nodes.
pub(crate) const CADDY_VERSION: &str = "v2.11.4";

/// Pinned `klzgrad/forwardproxy` commit (the `naive` branch tip at
/// 2026-06 — `v0.0.0-20250118002110-d62c80d3dd2c`). Pinning the exact
/// commit (not the moving `@naive` branch) makes the supply chain
/// reproducible — a force-push to the branch can't change what we ship.
pub(crate) const FORWARDPROXY_PIN: &str = "d62c80d3dd2c";

pub(crate) const CADDY_RESTART_IF_ACTIVE: &str =
    "if systemctl is-active --quiet caddy; then systemctl restart caddy; fi";

/// Minimal restart command for the caddy kernel. Restarts the managed
/// `caddy-vlessws` backend unit FIRST if it exists/active/enabled (so caddy's
/// `reverse_proxy` upstream is ready), then restarts `caddy`. On Naive-only
/// deployments where the backend is absent, skips the backend without error.
pub(crate) fn caddy_restart_command() -> String {
    format!(
        "if [ -f {sb_config} ] || systemctl is-active --quiet {vlessws_unit} 2>/dev/null || systemctl is-enabled --quiet {vlessws_unit} 2>/dev/null; then systemctl restart {vlessws_unit}; fi && systemctl restart caddy",
        sb_config = VLESSWS_SINGBOX_CONFIG,
        vlessws_unit = VLESSWS_UNIT,
    )
}

/// Status probe command for the managed `caddy-vlessws` backend unit.
/// Outputs:
/// - `active` if the backend is managed and active
/// - `inactive` if the backend is managed (config exists or unit enabled/active) but down
/// - `absent` if the backend is not part of this deployment (Naive-only)
pub(crate) fn caddy_vlessws_status_command() -> String {
    format!(
        "if [ -f {sb_config} ] || systemctl is-active --quiet {vlessws_unit} 2>/dev/null || systemctl is-enabled --quiet {vlessws_unit} 2>/dev/null; then systemctl is-active --quiet {vlessws_unit} 2>/dev/null && echo active || echo inactive; else echo absent; fi",
        sb_config = VLESSWS_SINGBOX_CONFIG,
        vlessws_unit = VLESSWS_UNIT,
    )
}

/// The masquerade site served to unauthenticated probes. Constant
/// (no per-deploy state), so it's provisioned once in `ensure_installed`
/// rather than re-rendered every `apply_config`.
pub(crate) const MASQUERADE_INDEX_HTML: &str = r#"<!doctype html>
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
pub(crate) fn caddy_present(probe_stdout: &str) -> bool {
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
pub(crate) fn caddy_needs_reinstall(cache_sha: &str, node_sha_stdout: &str) -> bool {
    node_sha_stdout.trim() != cache_sha
}

/// On-node build fallback (no cache present): install Go + xcaddy and
/// build caddy with the naive forwardproxy. Heavy on a 1-vCPU/1-GB box
/// (~10 min, RAM-tight) — hence the temporary build swapfile and
/// `GOFLAGS=-p=1`. `CGO_ENABLED=0` makes the result the same portable
/// static binary the cache path ships.
pub(crate) fn caddy_build_script() -> String {
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
pub(crate) fn caddy_runtime_provision_script() -> String {
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
