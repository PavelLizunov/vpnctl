//! dns-tunnel kernel — slipstream-rust «DNS-over-НСДИ» last-resort
//! transport.
//!
//! The 4th fallback in the РФ-DPI stack (after VLESS+REALITY / TUIC /
//! NAIVE): when РКН flips to white-list mode and rubs out everything
//! else, this tunnels TCP-over-DNS to the НСДИ resolvers
//! (`195.208.4.1` / `195.208.5.1`), which stay reachable even under an
//! IP-whitelist. Engine = **slipstream-rust** (Mygod/slipstream-rust,
//! QUIC-over-DNS; ~246 KB/s multipath over both resolvers). PoC proven
//! and deployed standalone on box 213.155.15.93 (2026-06-08); the exact
//! flags, units and ports live in `DNS-TUNNEL.md`,
//! `configs/dns-tunnel-*.service` and `configs/tunnel-singbox-server.json.tpl`.
//!
//! ## Architecture — TWO systemd units (relay + backend)
//!
//! ```text
//! Internet (UDP 53)
//!     │  DNS-tunnelled QUIC (slipstream)
//!     ▼
//! dns-tunnel.service          ── forwards decapsulated TCP ──▶ dns-tunnel-singbox.service
//! (slipstream-server :53)        to 127.0.0.1:9001               (loopback-only, TLS-less
//!                                                                 VLESS inbound on 127.0.0.1:9001
//!                                                                 — the tunnel already encrypts)
//! ```
//!
//! This kernel OWNS BOTH units (slipstream-server relay + loopback
//! sing-box backend). The composition with sing-box is
//! INTERNAL — there is NO cross-kernel API in vpnctl and we do not
//! invent one; the only coupling is the `127.0.0.1:9001` forward-target
//! string shared between the slipstream `-a` flag and the VLESS inbound
//! `listen_port`.
//!
//!   * `dns-tunnel.service`         — slipstream-server, public UDP 53.
//!     Flags: `-l 53 -a 127.0.0.1:9001 -d <domain> -c <cert> -k <key>
//!     --reset-seed <seed>` (auto-generates the ECDSA-P256 leaf cert on
//!     first run).
//!   * `dns-tunnel-singbox.service` — a dedicated loopback-only VLESS
//!     sing-box inbound on `127.0.0.1:9001` (config shape =
//!     `configs/tunnel-singbox-server.json.tpl`). DISTINCT from any
//!     public sing-box on the box — this one is TLS-less + loopback-only.
//!
//! ## Multi-file deploy bundle
//!
//! `render_config` returns a single `Vec<u8>` but we render TWO files
//! (the slipstream server config + the sing-box JSON), so we use
//! a delimited multi-file bundle (`BUNDLE_DELIMITER`). See
//! `apply_config` for the unpack-then-restart orchestration.
//!
//! ## Binary provisioning — prebuilt cache + SHA256 verify (NOT on-node)
//!
//! slipstream-rust needs ≥2 GB RAM to build (Rust LTO + picoquic/C) and
//! the target box has 960 MB — an on-node build is IMPOSSIBLE. So provisioning copies the
//! **caddy prebuilt-cache + SHA256-verify** pattern instead
//! (`crates/kernels/src/caddy.rs`): a control-node cache at
//! `/var/lib/vpnctl/cache/slipstream-<ver>-amd64`, uploaded + SHA256-
//! verified on the node, **failing LOUD on cache-miss** (NOT a silent
//! on-node-build fallback — there's nothing to fall back TO on a 960 MB
//! box), with an **amd64 arch guard** (error clearly on a non-amd64 node
//! rather than installing a non-executable binary). The cache is
//! populated out-of-band by the docker build on node 192.168.0.236
//! (DNS-TUNNEL.md §6).
//!
//! ## Kernel orthogonality
//!
//! Adding this kernel touches ONLY:
//!   * `crates/kernels/src/dns_tunnel.rs` (this file)
//!   * `crates/kernels/src/lib.rs` (`mod` + `pub use`)
//!   * `crates/protocols/src/dns_tunnel.rs` (companion stub protocol)
//!   * `crates/protocols/src/lib.rs` (`mod` + `pub use`)
//!   * `cli/src/registry.rs` + `daemon/src/app.rs::build_registry`
//!     — one `register_*` line each
//!
//! No edits to `core`, `ssh`, `crypto`, `inventory`, or
//! `cli/src/cmd/*` per CLAUDE.md's Kernel × Protocol invariant.

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use vpnctl_core::{
    CoreError, Kernel, KernelId, KernelStatus, KernelVersionPolicy, KernelVersionRequirement,
    Protocol, ProtocolId, RenderCtx, Result, SshTransport, User,
};

/// Pinned slipstream-rust build the cache binary is compiled from.
/// Stamps the cache path so a version bump invalidates a stale prebuilt
/// binary (a stale one would silently ship the wrong version). The
/// docker build on node 192.168.0.236 (DNS-TUNNEL.md §6) produces this
/// version. Bumping requires deliberate operator action: edit this
/// constant + repopulate the cache + re-deploy.
const SLIPSTREAM_VERSION: &str = "v0.1.0";

/// Public UDP port the slipstream-server listens on for DNS-tunnel
/// ingress. 53 is load-bearing: НСДИ delegation routes
/// `<data>.<domain>` queries to this node's `:53` (DNS-TUNNEL.md §3).
/// Operator-overridable via `dns-tunnel:listen_port` (a hoster that
/// reserves :53 could move it), validated as u16 at render time.
const DEFAULT_LISTEN_PORT: u16 = 53;

/// Loopback forward-target the slipstream-server decapsulates TCP onto
/// — the dedicated TLS-less VLESS sing-box inbound. Matches the PoC
/// `tunnel-singbox-server.json.tpl` (`127.0.0.1:9001`). The ONLY
/// coupling between this kernel's two units; operator-overridable via
/// `dns-tunnel:forward_target` but REJECTED at render time if it isn't
/// a loopback address (a public forward-target would expose the
/// TLS-less inbound to the internet).
const DEFAULT_FORWARD_TARGET: &str = "127.0.0.1:9001";

/// QUIC idle-timeout (seconds) the slipstream-server enforces on tunnel
/// connections — rendered into the relay ExecStart as
/// `--idle-timeout-seconds`. The upstream slipstream default is 60s, but
/// the recursive НСДИ resolver intermittently stalls the covert-DNS
/// stream for a handful of seconds (rate-limit / state eviction; see
/// `plans/dns-tunnel-server-side-2026-06-11.md`). A 60s idle window tears
/// the QUIC connection on such a hiccup, forcing a full re-handshake; we
/// bump the DEFAULT to **180s** so the connection survives a short
/// resolver stall and recovers without re-handshaking. Operator-
/// overridable via `dns-tunnel:idle_timeout_seconds`, validated as a
/// non-zero u16 at render time (mirrors the `listen_port` guard).
const DEFAULT_IDLE_TIMEOUT_SECONDS: u16 = 180;

/// On-node working directory holding the slipstream binary, its
/// auto-generated cert/key/reset-seed, and the sing-box tunnel config.
/// Mirrors the PoC `/root/dnstt-run/` layout (DNS-TUNNEL.md §4) but
/// under `/etc` so it's clearly vpnctl-managed config state.
const NODE_RUN_DIR: &str = "/etc/dns-tunnel";

/// Absolute paths of the two rendered member files + the slipstream
/// runtime assets. Kept as constants so `render_config` (which writes
/// the bundle markers) and `apply_config` (which unpacks + chowns them)
/// can't drift.
const SLIPSTREAM_CONFIG_PATH: &str = "/etc/dns-tunnel/slipstream.env";
const SINGBOX_CONFIG_PATH: &str = "/etc/dns-tunnel/tunnel-sb.json";
const CERT_PATH: &str = "/etc/dns-tunnel/sl-cert.pem";
const KEY_PATH: &str = "/etc/dns-tunnel/sl-key.pem";
const RESET_SEED_PATH: &str = "/etc/dns-tunnel/sl-reset";
const SLIPSTREAM_BINARY: &str = "/usr/local/bin/slipstream-server";

/// The two systemd unit names this kernel manages. Backend (sing-box)
/// is restarted FIRST so the relay's forward-target is reachable when
/// it starts.
const RELAY_UNIT: &str = "dns-tunnel";
const BACKEND_UNIT: &str = "dns-tunnel-singbox";

/// Multi-file bundle delimiter. `render_config`
/// emits text in this shape; `apply_config` parses it. Format:
///
/// ```text
/// ====FILE: <absolute path>====
/// <file bytes>
/// ====FILE: <another absolute path>====
/// <file bytes>
/// ```
///
/// Each path line starts at column 0 with `====FILE: ` and ends
/// `====`. We do NOT escape `==` runs in file bodies: the slipstream
/// `KEY=value` env file legally can't contain a leading `====FILE: `
/// line, and the sing-box JSON config never does either.
const BUNDLE_DELIMITER: &str = "====FILE: ";
const BUNDLE_DELIMITER_END: &str = "====";

/// Which DNS-tunnel ENGINE backs the relay. The seam exists so a future
/// `dnstt` (Go/Noise+KCP — the DNS-TUNNEL.md §2 backup transport) can be
/// wired without a new kernel, but we **ship Slipstream only**: the
/// `Dnstt` arm returns a clean placeholder error rather than silently
/// half-deploying an unwired engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Engine {
    Slipstream,
    Dnstt,
}

impl Engine {
    /// Parse the `dns-tunnel:engine` secret. Default `Slipstream` (the
    /// boevoy transport). Unknown values are REJECTED LOUDLY — a typo
    /// must surface as a clear `CoreError::Render`, never fall through
    /// to a default that silently deploys the wrong transport.
    fn parse(raw: &str) -> Result<Self> {
        match raw.trim() {
            "slipstream" => Ok(Engine::Slipstream),
            "dnstt" => Ok(Engine::Dnstt),
            other => Err(CoreError::Render(format!(
                "dns-tunnel: unknown engine {other:?} — supported values are \
                 'slipstream' (default, shipped) and 'dnstt' (placeholder, not \
                 yet implemented)"
            ))),
        }
    }
}

/// Path on the CONTROL node where the prebuilt **static amd64**
/// slipstream-server binary is cached. When present, `ensure_installed`
/// uploads it to the target node + SHA256-verifies it there — seconds,
/// with no ≥2 GB-RAM Rust/picoquic build on the (960 MB) node. The
/// cache is populated out-of-band by the docker build on node
/// 192.168.0.236 (DNS-TUNNEL.md §6). Override the path via the
/// `VPNCTL_SLIPSTREAM_CACHE` env var.
pub(crate) fn slipstream_cache_path() -> std::path::PathBuf {
    std::env::var_os("VPNCTL_SLIPSTREAM_CACHE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(default_slipstream_cache_path)
}

/// Default cache path, stamped with the slipstream version + `-amd64`
/// arch so a version bump invalidates a stale prebuilt binary instead
/// of silently uploading the wrong one. Pure (reads no env) →
/// deterministic to test. Mirrors `caddy::default_caddy_cache_path`.
pub(crate) fn default_slipstream_cache_path() -> std::path::PathBuf {
    std::path::PathBuf::from(format!(
        "/var/lib/vpnctl/cache/slipstream-{SLIPSTREAM_VERSION}-amd64"
    ))
}

/// Decide whether the on-node slipstream binary must be (re)installed
/// from the control-node cache. Content-aware (sha256), NOT a bare
/// presence check: an operator who replaces the cached binary with a
/// patched build (same path, different bytes) MUST get it pushed on the
/// next `vpnctl deploy` without first deleting the on-node binary by
/// hand.
///
/// * `cache_sha` — lowercase hex sha256 of the cache binary's bytes
///   (computed control-side; the same digest fed to `sha256sum -c`).
/// * `node_sha_stdout` — raw stdout of `sha256sum <bin> | cut -d' ' -f1`
///   on the node; EMPTY (binary absent) or any value `!= cache_sha`
///   means reinstall.
///
/// Pure → unit-tested directly so an inverted branch can't slip past CI.
fn slipstream_needs_reinstall(cache_sha: &str, node_sha_stdout: &str) -> bool {
    node_sha_stdout.trim() != cache_sha
}

/// Reject a forward-target that isn't a loopback address — a public
/// forward-target would expose the TLS-less VLESS inbound to the open
/// internet (the tunnel is what's meant to protect it). Accepts the
/// IPv4 loopback `/8` (`127.0.0.0/8`) and the IPv6 loopback `::1`.
/// Pure → unit-tested directly.
fn is_loopback_forward_target(target: &str) -> bool {
    // Split host:port. IPv6 literals are bracketed (`[::1]:9001`).
    let host = if let Some(rest) = target.strip_prefix('[') {
        // `[::1]:9001` → take up to the closing bracket.
        match rest.split_once(']') {
            Some((h, _)) => h,
            None => return false,
        }
    } else {
        // `127.0.0.1:9001` → host is everything before the LAST colon
        // (there's exactly one for IPv4 host:port).
        match target.rsplit_once(':') {
            Some((h, _)) => h,
            None => target,
        }
    };
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
    }
}

/// The on-node runtime provisioning script: service user, run dir,
/// and BOTH systemd unit files. Idempotent — safe to re-run on every
/// deploy. The unit ExecStarts mirror `configs/dns-tunnel-*.service`
/// exactly, but read paths under `/etc/dns-tunnel` (vpnctl-managed)
/// rather than the PoC's `/root/dnstt-run`.
///
/// `dns-tunnel.service` reads its flags from the rendered
/// `slipstream.env` `EnvironmentFile` (so the public-facing command
/// line carries no secrets in `systemctl cat` — same hygiene as the
/// vpnctld EnvironmentFile pattern in CLAUDE.md).
fn runtime_provision_script() -> String {
    format!(
        r#"
        set -eu
        install -d -m 0750 {run_dir}

        # Dedicated unprivileged service user for the slipstream relay.
        # CAP_NET_BIND_SERVICE (granted in the unit) lets it bind :53
        # without running as root.
        id dns-tunnel >/dev/null 2>&1 \
            || useradd --system --home {run_dir} --shell /usr/sbin/nologin dns-tunnel

        # ── Relay unit: slipstream-server on public UDP :53. ──────────
        cat > /etc/systemd/system/{relay}.service <<'RELAY_UNIT_EOF'
[Unit]
Description=slipstream-rust DNS tunnel server (over НСДИ) — vpnctl-managed
Documentation=https://github.com/Mygod/slipstream-rust
After=network-online.target {backend}.service
Wants=network-online.target

[Service]
Type=simple
User=dns-tunnel
Group=dns-tunnel
WorkingDirectory={run_dir}
EnvironmentFile={slipstream_env}
ExecStart={binary} -l ${{SLIPSTREAM_LISTEN_PORT}} -a ${{SLIPSTREAM_FORWARD_TARGET}} -d ${{SLIPSTREAM_DOMAIN}} -c {cert} -k {key} --reset-seed {reset} --idle-timeout-seconds ${{SLIPSTREAM_IDLE_TIMEOUT_SECONDS}}
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={run_dir}
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native
UMask=0077

[Install]
WantedBy=multi-user.target
RELAY_UNIT_EOF

        # ── Backend unit: loopback-only TLS-less VLESS sing-box. ──────
        # Restarted FIRST by apply_config so the relay's forward-target
        # is reachable on boot. Resolves the absolute path to the sing-box
        # binary dynamically (e.g. /usr/local/bin/sing-box or /usr/bin/sing-box)
        # so custom or standard PATH locations are executed accurately.
        SB_BIN=$(command -v sing-box 2>/dev/null || echo /usr/bin/sing-box)
        cat > /etc/systemd/system/{backend}.service <<BACKEND_UNIT_EOF
[Unit]
Description=sing-box VLESS inbound for DNS tunnel (loopback :9001) — vpnctl-managed
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$SB_BIN run -c {sb_config}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
BACKEND_UNIT_EOF
        systemctl daemon-reload

        command -v {binary} >/dev/null 2>&1 || command -v slipstream-server
        "#,
        run_dir = NODE_RUN_DIR,
        relay = RELAY_UNIT,
        backend = BACKEND_UNIT,
        slipstream_env = SLIPSTREAM_CONFIG_PATH,
        binary = SLIPSTREAM_BINARY,
        cert = CERT_PATH,
        key = KEY_PATH,
        reset = RESET_SEED_PATH,
        sb_config = SINGBOX_CONFIG_PATH,
    )
}

#[derive(Debug, Default)]
pub struct DnsTunnel;

impl DnsTunnel {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Kernel for DnsTunnel {
    fn id(&self) -> KernelId {
        KernelId("dns-tunnel".to_string())
    }

    fn supported_protocols(&self) -> Vec<ProtocolId> {
        // LOAD-BEARING: a kernel with an empty supported_protocols() is
        // silently NEVER configured/started (deploy + admin both
        // `if protocols_for_k.is_empty() { continue; }`). The dns-tunnel
        // wire shape is exactly one protocol.
        vec![ProtocolId("dns-tunnel".to_string())]
    }

    fn version_requirement(&self) -> Option<KernelVersionRequirement> {
        Some(KernelVersionRequirement {
            policy: KernelVersionPolicy::Pin,
            value: SLIPSTREAM_VERSION,
        })
    }

    async fn ensure_installed(&self, ssh: &dyn SshTransport) -> Result<()> {
        // ── 1. Read the cache binary FIRST (NO on-node build fallback). ──
        // slipstream-rust needs ≥2 GB RAM to build (Rust LTO +
        // picoquic/C); the target box has 960 MB. So unlike caddy
        // (which falls back to an on-node xcaddy build on cache-miss)
        // there is NOTHING to fall back to here — a cache-miss is a
        // HARD, LOUD failure pointing the operator at the docker build
        // that populates the cache. We read it up front because its
        // sha256 is what the content-aware reinstall decision compares
        // the on-node binary against (and it's the integrity digest fed
        // to `sha256sum -c` on the transfer).
        let cache = slipstream_cache_path();
        let bytes = match std::fs::read(&cache) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(CoreError::Render(format!(
                    "dns-tunnel: prebuilt slipstream binary not found at {} — \
                     slipstream-rust needs ≥2 GB RAM to build so there is no on-node \
                     build fallback. Populate the cache via the docker build on node \
                     192.168.0.236 (DNS-TUNNEL.md §6), or point VPNCTL_SLIPSTREAM_CACHE \
                     at the built binary.",
                    cache.display()
                )));
            }
            // A cache path that's SET but unreadable (bad
            // VPNCTL_SLIPSTREAM_CACHE, wrong perms, a directory)
            // fails loudly rather than being mistaken for a miss.
            Err(e) => return Err(CoreError::Io(e)),
        };
        let digest = format!("{:x}", Sha256::digest(&bytes));

        // ── 2. Ensure sing-box backend is installed. ──────────────────
        // dns-tunnel uses sing-box as its loopback backend (dns-tunnel-singbox.service).
        // If sing-box is absent, provision it using the canonical sing-box setup script.
        crate::SingBox::new().ensure_installed(ssh).await?;

        // Content-aware idempotency probe: the on-node binary's sha256
        // (empty when absent).
        let node_sha = ssh
            .exec("sha256sum /usr/local/bin/slipstream-server 2>/dev/null | cut -d' ' -f1")
            .await?;

        let binary_changed = slipstream_needs_reinstall(&digest, &node_sha);
        if binary_changed {
            // ── amd64 arch guard. ─────────────────────────────────────
            // The cache binary is a static amd64 build (DNS-TUNNEL.md
            // §6). Installing it on a non-amd64 node would write a
            // non-executable file that crash-loops the relay with a
            // cryptic exec-format error. Fail clearly instead. `set -eu`
            // + the explicit `exit 1` abort the deploy.
            let arch = ssh.exec("uname -m").await?;
            let arch = arch.trim();
            if arch != "x86_64" && arch != "amd64" {
                return Err(CoreError::Render(format!(
                    "dns-tunnel: node arch is {arch:?}, but the slipstream cache binary \
                     is amd64-only (slipstream-rust needs ≥2 GB RAM to build, so there is \
                     no on-node build fallback). Provision an amd64 node, or extend the \
                     docker build on 192.168.0.236 (DNS-TUNNEL.md §6) for this arch."
                )));
            }

            // Integrity-verify on the node before installing it as a
            // root systemd service: upload the cache bytes to .new,
            // `sha256sum -c` the control-side digest there, then atomic
            // mv. `set -eu` aborts the deploy on a corrupted/truncated
            // upload. Same shape as caddy's cache-install path.
            ssh.upload("/usr/local/bin/slipstream-server.new", &bytes)
                .await?;
            ssh.exec(&format!(
                "set -eu\n\
                 echo '{digest}  /usr/local/bin/slipstream-server.new' | sha256sum -c - >/dev/null\n\
                 chmod 0755 /usr/local/bin/slipstream-server.new\n\
                 mv -f /usr/local/bin/slipstream-server.new /usr/local/bin/slipstream-server\n\
                 test -x /usr/local/bin/slipstream-server"
            ))
            .await?;
        }

        // Provision the runtime (service user, run dir, both systemd
        // units) regardless of how the binary arrived. Idempotent. The
        // .conf files the units reference don't exist until
        // apply_config has run — that's why both units are
        // enabled+started by apply_config, not here.
        ssh.exec(&runtime_provision_script()).await?;

        // update-kernels gap fix (2026-06-14): `ensure_installed` only
        // UPLOADS the new binary — the restart that makes it take effect
        // lives in `apply_config`. So an `update-kernels` run (which calls
        // ONLY `ensure_installed`, no config re-apply) would atomically
        // swap the file but leave slipstream running the OLD inode, i.e.
        // the "upgrade" silently does nothing until the next full deploy.
        // When we actually changed the binary AND the relay is already up
        // (an upgrade — NOT a fresh install, where the unit is started
        // later by apply_config once its config exists), restart it so the
        // new binary is live. The `is-active` guard makes this a no-op on
        // a first install. `|| true` so a stopped/absent unit isn't a hard
        // error.
        if binary_changed {
            ssh.exec(
                "systemctl is-active --quiet dns-tunnel && systemctl restart dns-tunnel || true",
            )
            .await?;
        }
        Ok(())
    }

    fn render_config(
        &self,
        ctx: &RenderCtx<'_>,
        users: &[User],
        protocols: &[&dyn Protocol],
    ) -> Result<Vec<u8>> {
        // Defense-in-depth: Registry::validate_server should reject a
        // `kernels=[dns-tunnel]` + a non-dns-tunnel protocol set earlier,
        // but the kernel still verifies its own contract (mirrors
        // caddy).
        let _proto = protocols
            .iter()
            .find(|p| p.id() == ProtocolId("dns-tunnel".to_string()))
            .ok_or_else(|| {
                CoreError::Render(
                    "dns-tunnel kernel requires the dns-tunnel protocol in `protocols`".into(),
                )
            })?;

        // Engine seam — read ONLY from ctx.secrets. Default Slipstream;
        // unknown values rejected loudly by Engine::parse.
        let engine = match ctx.secrets.get("dns-tunnel:engine") {
            None => Engine::Slipstream,
            Some(s) => Engine::parse(s)?,
        };
        if engine == Engine::Dnstt {
            // Ship Slipstream only. The dnstt arm is a placeholder — NEVER
            // silently deploy a half-wired engine.
            return Err(CoreError::Render(
                "dns-tunnel engine 'dnstt' not yet implemented".into(),
            ));
        }

        // Tunnel domain (slipstream -d / QUIC SNI) — operator-set,
        // required.
        let domain = ctx.secrets.get("dns-tunnel:domain").ok_or_else(|| {
            CoreError::Render(
                "dns-tunnel kernel: missing secret `dns-tunnel:domain` — \
                 set the slipstream tunnel domain via /admin/servers/<id>"
                    .into(),
            )
        })?;
        // Fail closed: the domain lands VERBATIM in the systemd
        // EnvironmentFile line `SLIPSTREAM_DOMAIN=<domain>` (loaded into
        // the relay env + ExecStart) and in the `====FILE:` bundle. A
        // newline forges a second `KEY=value` env line (env-file line
        // injection) or breaks the bundle framing. Mirrors the operator-
        // set-domain guards in `crates/kernels/src/caddy.rs` (Caddyfile)
        // and `crates/protocols/src/naive.rs` (client URI). `is_control`
        // is load-bearing — it catches NUL and the newline.
        const ILLEGAL: [char; 5] = ['\n', '\r', ' ', '{', '}'];
        if domain.is_empty()
            || domain.chars().count() > 253
            || domain.contains(ILLEGAL)
            || domain.chars().any(|c| c.is_control())
        {
            return Err(CoreError::Render(format!(
                "dns-tunnel kernel: `dns-tunnel:domain` {domain:?} is invalid — must be a \
                 non-empty hostname <=253 chars with no control characters or whitespace \
                 (it lands verbatim in the slipstream EnvironmentFile and command line)"
            )));
        }

        // Wrapped loopback VLESS inbound `users[]`. Per-user identity is
        // the standard vpnctl user model: every user GRANTED the
        // dns-tunnel protocol on this server arrives here in `users`
        // (the same `users_for_server` slice every kernel's
        // `render_config` receives — the grant path is protocol-agnostic),
        // carrying the SAME `User.uuid` they already use for VLESS-REALITY.
        // We render one PLAIN VLESS entry per granted user (no `flow`, no
        // reality — the tunnel itself provides the encryption, so the
        // loopback inbound is intentionally TLS-less + auth-by-UUID only).
        //
        // Backward-compat: the historical single server-wide
        // `dns-tunnel:loopback_uuid` secret (the PoC `${TUNNEL_UUID}`, live
        // on box 213) stays supported as an OPTIONAL admin/fallback entry —
        // when set, it's appended to `users[]`, de-duplicated against the
        // granted users so it's never double-listed. This keeps the live
        // `e09b09af-…` deploy working untouched AND lets per-user identities
        // ride the same inbound.
        let loopback_uuid = ctx.secrets.get("dns-tunnel:loopback_uuid");
        // dedup(granted users' uuids ++ [loopback_uuid if set]), preserving
        // the granted-users order (stable `ORDER BY id` from inventory) so
        // the rendered config is byte-stable, with the fallback appended.
        let mut inbound_uuids: Vec<&str> = Vec::with_capacity(users.len() + 1);
        for u in users {
            let uuid = u.uuid.as_str();
            if !inbound_uuids.contains(&uuid) {
                inbound_uuids.push(uuid);
            }
        }
        if let Some(lb) = loopback_uuid.map(String::as_str) {
            if !inbound_uuids.contains(&lb) {
                inbound_uuids.push(lb);
            }
        }
        // An inbound with zero users is a misconfiguration — sing-box would
        // accept VLESS handshakes it can never authenticate, and there is
        // nothing to hand any client. Fail closed rather than ship a dead
        // inbound. (The historical guard required `loopback_uuid`; now
        // EITHER a granted user OR the fallback secret satisfies it.)
        if inbound_uuids.is_empty() {
            return Err(CoreError::Render(
                "dns-tunnel kernel: the loopback VLESS inbound has no users — \
                 grant the dns-tunnel protocol to at least one user (their \
                 per-user UUID is reused, same as VLESS-REALITY), or set the \
                 `dns-tunnel:loopback_uuid` fallback secret via \
                 /admin/servers/<id>"
                    .into(),
            ));
        }

        // Listen port — operator-overridable, validated as u16 at render
        // time so a typo surfaces as a clear CoreError::Render rather
        // than an 8-second is-active poll timeout.
        let listen_port: u16 = match ctx.secrets.get("dns-tunnel:listen_port") {
            None => DEFAULT_LISTEN_PORT,
            Some(s) => {
                let port = s.parse::<u16>().map_err(|_| {
                    CoreError::Render(format!(
                        "dns-tunnel kernel: invalid `dns-tunnel:listen_port` value {s:?} — \
                         must be an integer in 1..=65535"
                    ))
                })?;
                if port == 0 {
                    // Port 0 is OS-ephemeral — unreachable for the :53
                    // delegation the relay fronts. Reject like a parse error.
                    return Err(CoreError::Render(format!(
                        "dns-tunnel kernel: invalid `dns-tunnel:listen_port` value {s:?} — \
                         must be an integer in 1..=65535"
                    )));
                }
                port
            }
        };

        // Idle-timeout (seconds) — operator-overridable, validated as a
        // non-zero u16 at render time (mirrors the listen_port guard so a
        // typo surfaces as a clear CoreError::Render, not an is-active
        // poll timeout). Default 180 (a deliberate bump from upstream's
        // 60s so the QUIC connection survives a short НСДИ-resolver stall
        // and recovers without a full re-handshake — see
        // plans/dns-tunnel-server-side-2026-06-11.md).
        let idle_timeout_seconds: u16 = match ctx.secrets.get("dns-tunnel:idle_timeout_seconds") {
            None => DEFAULT_IDLE_TIMEOUT_SECONDS,
            Some(s) => {
                let secs = s.parse::<u16>().map_err(|_| {
                    CoreError::Render(format!(
                        "dns-tunnel kernel: invalid `dns-tunnel:idle_timeout_seconds` value \
                         {s:?} — must be an integer in 1..=65535 seconds"
                    ))
                })?;
                if secs == 0 {
                    // 0 disables the idle timeout in slipstream — never what
                    // an operator wants here (a dead path would linger
                    // forever). Reject like a parse error.
                    return Err(CoreError::Render(format!(
                        "dns-tunnel kernel: invalid `dns-tunnel:idle_timeout_seconds` value \
                         {s:?} — must be an integer in 1..=65535 seconds"
                    )));
                }
                secs
            }
        };

        // Forward-target — operator-overridable, but REJECTED if it
        // isn't a loopback address (a public forward-target exposes the
        // TLS-less VLESS inbound to the internet).
        let forward_target = ctx
            .secrets
            .get("dns-tunnel:forward_target")
            .map(String::as_str)
            .unwrap_or(DEFAULT_FORWARD_TARGET);
        if !is_loopback_forward_target(forward_target) {
            return Err(CoreError::Render(format!(
                "dns-tunnel kernel: `dns-tunnel:forward_target` {forward_target:?} is not a \
                 loopback address — the wrapped VLESS inbound is TLS-less and MUST stay on \
                 127.0.0.0/8 (or [::1]); a public forward-target would expose it to the \
                 internet"
            )));
        }
        // The sing-box inbound binds the forward-target's host+port. Split
        // it so the inbound's `listen` / `listen_port` match the relay's
        // `-a` flag byte-for-byte (the single coupling between the units).
        let (fwd_host, fwd_port) = split_host_port(forward_target).ok_or_else(|| {
            CoreError::Render(format!(
                "dns-tunnel kernel: `dns-tunnel:forward_target` {forward_target:?} is not a \
                 valid host:port"
            ))
        })?;

        // ── 1. Render the slipstream relay env file. ──────────────────
        // The unit's ExecStart reads these via EnvironmentFile so no
        // secret (the domain) lands in `systemctl cat` output.
        let mut env_file = String::with_capacity(256);
        env_file.push_str("# Rendered by vpnctl. Do not hand-edit — your changes\n");
        env_file.push_str("# will be overwritten on next `vpnctl deploy`.\n");
        env_file.push_str("#\n");
        env_file.push_str("# slipstream-server flags for dns-tunnel.service. The ECDSA-P256\n");
        env_file.push_str("# leaf cert is auto-generated on first run; capture its SHA-256\n");
        env_file.push_str("# fingerprint into the `dns-tunnel:fingerprint` secret for the\n");
        env_file.push_str("# client share-link pin.\n");
        env_file.push_str(&format!("SLIPSTREAM_LISTEN_PORT={listen_port}\n"));
        env_file.push_str(&format!("SLIPSTREAM_FORWARD_TARGET={forward_target}\n"));
        env_file.push_str(&format!("SLIPSTREAM_DOMAIN={domain}\n"));
        env_file.push_str(&format!(
            "SLIPSTREAM_IDLE_TIMEOUT_SECONDS={idle_timeout_seconds}\n"
        ));

        // ── 2. Render the loopback-only TLS-less VLESS sing-box config. ─
        // Shape = configs/tunnel-singbox-server.json.tpl. Built as a
        // serde_json::Value then pretty-printed for byte-stability
        // (BTreeMap key order is deterministic; serde_json emits LF-only).
        // PLAIN VLESS entries — only `uuid`, no `flow`/reality (the entry
        // shape vless_reality.rs uses for a vision user minus the
        // xtls-rprx-vision flow, which is loopback-inappropriate here).
        let users_json: Vec<serde_json::Value> = inbound_uuids
            .iter()
            .map(|uuid| serde_json::json!({ "uuid": uuid }))
            .collect();
        let sb_config = serde_json::json!({
            "log": {"level": "warn"},
            "inbounds": [
                {
                    "type": "vless",
                    "tag": "tunnel-in",
                    "listen": fwd_host,
                    "listen_port": fwd_port,
                    "users": users_json
                }
            ],
            "outbounds": [
                {"type": "direct", "tag": "direct"}
            ]
        });
        let sb_json = serde_json::to_string_pretty(&sb_config)
            .map_err(|e| CoreError::Render(format!("dns-tunnel sing-box config marshal: {e}")))?;

        // ── 3. Assemble the multi-file bundle. ────────
        let mut bundle = String::with_capacity(env_file.len() + sb_json.len() + 256);
        bundle.push_str(BUNDLE_DELIMITER);
        bundle.push_str(SLIPSTREAM_CONFIG_PATH);
        bundle.push_str(BUNDLE_DELIMITER_END);
        bundle.push('\n');
        bundle.push_str(&env_file);
        if !env_file.ends_with('\n') {
            bundle.push('\n');
        }
        bundle.push_str(BUNDLE_DELIMITER);
        bundle.push_str(SINGBOX_CONFIG_PATH);
        bundle.push_str(BUNDLE_DELIMITER_END);
        bundle.push('\n');
        bundle.push_str(&sb_json);
        if !sb_json.ends_with('\n') {
            bundle.push('\n');
        }
        Ok(bundle.into_bytes())
    }

    async fn apply_config(&self, ssh: &dyn SshTransport, config: &[u8]) -> Result<()> {
        // Upload the bundle as a single staging file; the unpacker
        // parses + writes each member then restarts both units.
        ssh.upload("/etc/dns-tunnel/.deploy-bundle.new", config)
            .await?;
        ssh.exec(&dns_tunnel_apply_script()).await?;
        Ok(())
    }

    async fn restart(&self, ssh: &dyn SshTransport) -> Result<()> {
        // Restart BOTH units — relay depends on the backend being up.
        ssh.exec(&format!("systemctl restart {BACKEND_UNIT} {RELAY_UNIT}"))
            .await?;
        Ok(())
    }

    async fn status(&self, ssh: &dyn SshTransport) -> Result<KernelStatus> {
        // Active iff BOTH units are active. The slipstream relay opens a
        // UDP :53 socket even if its loopback forward-target is down (it
        // can't tell from a UDP socket whether anyone's listening), so
        // the combined check is the honest one.
        let relay = ssh
            .exec(&format!(
                "systemctl is-active {RELAY_UNIT} 2>/dev/null || true"
            ))
            .await?
            .trim()
            .eq("active");
        let backend = ssh
            .exec(&format!(
                "systemctl is-active {BACKEND_UNIT} 2>/dev/null || true"
            ))
            .await?
            .trim()
            .eq("active");
        let active = relay && backend;
        let version = ssh
            .exec("slipstream-server --version 2>/dev/null | awk '{print $NF; exit}'")
            .await
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        Ok(KernelStatus {
            active,
            version,
            uptime_seconds: None,
        })
    }
}

/// Split a `host:port` (bare IPv4 / bracketed IPv6) into its host string
/// and numeric port. Returns `None` on a malformed value or a port that
/// isn't a u16. Used to keep the sing-box inbound's `listen` and
/// `listen_port` in lockstep with the slipstream `-a` flag.
fn split_host_port(target: &str) -> Option<(String, u16)> {
    if let Some(rest) = target.strip_prefix('[') {
        // `[::1]:9001`
        let (host, after) = rest.split_once(']')?;
        let port = after.strip_prefix(':')?;
        Some((host.to_string(), port.parse().ok()?))
    } else {
        let (host, port) = target.rsplit_once(':')?;
        Some((host.to_string(), port.parse().ok()?))
    }
}

/// The bundle-unpack + atomic-swap + verify + ROLLBACK script run after the
/// dns-tunnel deploy bundle has been uploaded to `…/.deploy-bundle.new`.
///
/// dns-tunnel is a TWO-unit kernel: the sing-box loopback BACKEND
/// (`SINGBOX_CONFIG_PATH`) and the slipstream RELAY (`SLIPSTREAM_CONFIG_PATH`).
/// The backend is (re)started before the relay because the relay's
/// forward-target must be reachable when it comes up.
///
/// Neither `mv` nor `systemctl restart` validates RUNTIME conditions, so a
/// bundle that unpacks cleanly can still crash-loop either unit (a port a
/// co-tenant bound; a cert path the user can't read).
/// This script snapshots BOTH live configs to `<live>.bak` BEFORE their swaps
/// (each guarded on the live file existing — first deploy has none). Snapshot
/// failures on existing configs must abort immediately under `set -e` before
/// any swap (no `|| true`).
///
/// Pre-deploy enabled and active states for both units are recorded before any mutations.
/// Explicit `|| recover <unit-or-empty>` guards route any post-swap intermediate failures
/// (`mv`, `chown`, `chmod`, `chown -R`, `enable`, `restart`, or poll settlement failure)
/// through the recovery state machine (`recover()`). `recover()` restores each prior config
/// independently and restores exact prior enablement/active states; first-deploy cleanup
/// remains disabled/stopped. No recursion.
fn dns_tunnel_apply_script() -> String {
    format!(
        r#"
            set -eu

            BUNDLE=/etc/dns-tunnel/.deploy-bundle.new
            test -f "$BUNDLE"

            # Unpack the bundle. Format documented in
            # `crates/kernels/src/dns_tunnel.rs::BUNDLE_DELIMITER`.
            # Small awk splits on the marker line and writes
            # each member into its declared path (atomic via mv).
            awk '
                BEGIN {{ path = ""; outfile = ""; }}
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

            install -d -m 0750 {run_dir}

            # Snapshot BOTH live configs so a runtime-failed restart can roll
            # back. Each guarded on the live file existing (first deploy has
            # none); -a preserves owner/mode.
            # Snapshot cp failures must abort immediately under set -e before
            # the swap (no || true / error swallowing on existing configs).
            HAD_RELAY_PREV=0
            if [ -f {slipstream_env} ]; then
                cp -a {slipstream_env} {slipstream_env}.bak
                HAD_RELAY_PREV=1
            fi
            HAD_BACKEND_PREV=0
            if [ -f {sb_config} ]; then
                cp -a {sb_config} {sb_config}.bak
                HAD_BACKEND_PREV=1
            fi

            # Record pre-deploy enablement and active states before mutations.
            HAD_BACKEND_ENABLED=0
            if systemctl is-enabled --quiet {backend} 2>/dev/null; then
                HAD_BACKEND_ENABLED=1
            fi
            HAD_BACKEND_ACTIVE=0
            if systemctl is-active --quiet {backend} 2>/dev/null; then
                HAD_BACKEND_ACTIVE=1
            fi

            HAD_RELAY_ENABLED=0
            if systemctl is-enabled --quiet {relay} 2>/dev/null; then
                HAD_RELAY_ENABLED=1
            fi
            HAD_RELAY_ACTIVE=0
            if systemctl is-active --quiet {relay} 2>/dev/null; then
                HAD_RELAY_ACTIVE=1
            fi

            # Common recovery state machine for post-swap intermediate failures,
            # synchronous restart failures, and poll settlement failures.
            # Restores exact prior config, enablement, and active states for units
            # with predecessors, while cleaning up first-deploy units (disabled/stopped).
            _in_recover=0
            recover() {{
                set +e
                [ "$_in_recover" = 1 ] && return 1
                _in_recover=1
                _failed="${{1:-}}"
                if [ -n "$_failed" ]; then
                    echo "$_failed did not become active. Last 20 log lines:" >&2
                    journalctl -u "$_failed" --no-pager -n 20 >&2 || true
                fi
                if [ "$HAD_BACKEND_PREV" = 1 ] && [ -f {sb_config}.bak ]; then
                    echo "rolling back {backend} to previous config" >&2
                    mv {sb_config}.bak {sb_config} || true
                    if [ "$HAD_BACKEND_ENABLED" = 1 ]; then
                        systemctl enable {backend} >/dev/null 2>&1 || true
                    else
                        systemctl disable {backend} >/dev/null 2>&1 || true
                    fi
                    if [ "$HAD_BACKEND_ACTIVE" = 1 ]; then
                        systemctl restart {backend} || true
                    else
                        systemctl stop {backend} || true
                    fi
                else
                    echo "no previous config for {backend} — removing failed deploy" >&2
                    systemctl stop {backend} || true
                    systemctl disable {backend} || true
                    rm -f {sb_config}
                fi
                if [ "$HAD_RELAY_PREV" = 1 ] && [ -f {slipstream_env}.bak ]; then
                    echo "rolling back {relay} to previous config" >&2
                    mv {slipstream_env}.bak {slipstream_env} || true
                    if [ "$HAD_RELAY_ENABLED" = 1 ]; then
                        systemctl enable {relay} >/dev/null 2>&1 || true
                    else
                        systemctl disable {relay} >/dev/null 2>&1 || true
                    fi
                    if [ "$HAD_RELAY_ACTIVE" = 1 ]; then
                        systemctl restart {relay} || true
                    else
                        systemctl stop {relay} || true
                    fi
                else
                    echo "no previous config for {relay} — removing failed deploy" >&2
                    systemctl stop {relay} || true
                    systemctl disable {relay} || true
                    rm -f {slipstream_env}
                fi
                exit 1
            }}

            # Move each ".new" sibling into place atomically. Files we
            # know about: the slipstream env file + the sing-box JSON.
            # Explicit guards route any mutation failure to recover().
            mv {slipstream_env}.new {slipstream_env} || recover ""
            chown dns-tunnel:dns-tunnel {slipstream_env} || recover ""
            chmod 0640 {slipstream_env} || recover ""
            mv {sb_config}.new {sb_config} || recover ""
            chown root:root {sb_config} || recover ""
            chmod 0644 {sb_config} || recover ""
            # Make the run dir + auto-generated cert/key reachable by the
            # unprivileged relay user (cert/key may not exist yet — the
            # binary generates them on first run, inheriting this owner).
            chown -R dns-tunnel:dns-tunnel {run_dir} || recover ""
            rm -f "$BUNDLE" || recover ""

            # Restart the BACKEND (sing-box loopback inbound) FIRST so the
            # relay's forward-target is reachable when it starts.
            # Captured with `|| recover` so synchronous restart failure routes
            # through rollback instead of escaping set -e.
            systemctl enable {backend} >/dev/null 2>&1 || recover "{backend}"
            systemctl restart {backend} || recover "{backend}"

            # Then the relay itself.
            systemctl enable {relay} >/dev/null 2>&1 || recover "{relay}"
            systemctl restart {relay} || recover "{relay}"

            # 8-second wait for BOTH units to settle. On ANY unit failing,
            # route through the common recovery state machine.
            for s in {backend} {relay}; do
                ok=0
                for i in 1 2 3 4 5 6 7 8; do
                    state=$(systemctl is-active "$s" 2>/dev/null || true)
                    if [ "$state" = "active" ]; then
                        ok=1
                        break
                    fi
                    sleep 1
                done
                if [ "$ok" != "1" ]; then
                    recover "$s"
                fi
            done

            # Both units up — drop the transient snapshots (best-effort/non-fatal,
            # new configs/units are already proven healthy).
            rm -f {slipstream_env}.bak {sb_config}.bak || true
        "#,
        run_dir = NODE_RUN_DIR,
        slipstream_env = SLIPSTREAM_CONFIG_PATH,
        sb_config = SINGBOX_CONFIG_PATH,
        backend = BACKEND_UNIT,
        relay = RELAY_UNIT,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Drop `#`-comment lines from a rendered shell script so a doc/inline
    /// comment that mentions a command token (e.g. "exit 1") can't be
    /// mistaken for the actual command when the apply-script tests grep
    /// for command ordering.
    fn strip_comment_lines(script: &str) -> String {
        script
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn id_returns_dns_tunnel() {
        assert_eq!(DnsTunnel::new().id(), KernelId("dns-tunnel".into()));
    }

    #[test]
    fn supported_protocols_is_singleton_dns_tunnel() {
        let protos = DnsTunnel::new().supported_protocols();
        assert_eq!(protos.len(), 1);
        assert_eq!(protos[0], ProtocolId("dns-tunnel".into()));
    }

    #[test]
    fn default_cache_path_embeds_version_and_arch() {
        let s = default_slipstream_cache_path()
            .to_string_lossy()
            .into_owned();
        assert!(s.contains(SLIPSTREAM_VERSION), "missing version: {s}");
        assert!(s.ends_with("-amd64"), "must be arch-stamped: {s}");
    }

    #[test]
    fn slipstream_reinstall_is_content_aware_not_presence() {
        let cache = "a".repeat(64);
        // Absent on the node (empty `sha256sum … | cut` output) → reinstall.
        assert!(slipstream_needs_reinstall(&cache, ""));
        assert!(slipstream_needs_reinstall(&cache, "\n"));
        assert!(slipstream_needs_reinstall(&cache, "   "));
        // Present but DIFFERENT bytes (operator refreshed the cache) →
        // reinstall. This is the bug being fixed: a bare presence check
        // would skip here.
        assert!(slipstream_needs_reinstall(&cache, &"b".repeat(64)));
        // Present AND identical sha (trailing newline from the node) →
        // skip — idempotent no-op.
        assert!(!slipstream_needs_reinstall(&cache, &cache));
        assert!(!slipstream_needs_reinstall(&cache, &format!("{cache}\n")));
        assert!(!slipstream_needs_reinstall(&cache, &format!("  {cache}  ")));
    }

    #[test]
    fn engine_parse_defaults_and_rejects_unknown() {
        assert_eq!(Engine::parse("slipstream").unwrap(), Engine::Slipstream);
        assert_eq!(Engine::parse(" slipstream ").unwrap(), Engine::Slipstream);
        assert_eq!(Engine::parse("dnstt").unwrap(), Engine::Dnstt);
        let err = Engine::parse("wireguard").unwrap_err();
        assert!(format!("{err}").contains("unknown engine"));
    }

    #[test]
    fn loopback_forward_target_classifier() {
        assert!(is_loopback_forward_target("127.0.0.1:9001"));
        assert!(is_loopback_forward_target("127.5.6.7:9001"));
        assert!(is_loopback_forward_target("[::1]:9001"));
        assert!(!is_loopback_forward_target("0.0.0.0:9001"));
        assert!(!is_loopback_forward_target("203.0.113.1:9001"));
        assert!(!is_loopback_forward_target("example.com:9001"));
    }

    #[test]
    fn split_host_port_handles_ipv4_and_ipv6() {
        assert_eq!(
            split_host_port("127.0.0.1:9001"),
            Some(("127.0.0.1".to_string(), 9001))
        );
        assert_eq!(
            split_host_port("[::1]:9001"),
            Some(("::1".to_string(), 9001))
        );
        assert_eq!(split_host_port("127.0.0.1"), None);
        assert_eq!(split_host_port("127.0.0.1:70000"), None);
    }

    #[test]
    fn apply_script_snapshots_both_configs_before_swap() {
        // Two-unit kernel: BOTH the slipstream env AND the sing-box JSON
        // must be `cp -a`'d to `.bak` BEFORE their respective `mv .new →
        // live` swaps, so a runtime-failed restart can roll either back.
        let s = dns_tunnel_apply_script();
        for live in [SLIPSTREAM_CONFIG_PATH, SINGBOX_CONFIG_PATH] {
            let cp = s
                .find(&format!("cp -a {live} {live}.bak"))
                .unwrap_or_else(|| panic!("snapshot cp -a to .bak missing for {live}"));
            let mv = s
                .find(&format!("mv {live}.new {live}"))
                .unwrap_or_else(|| panic!("atomic swap mv missing for {live}"));
            assert!(cp < mv, "snapshot for {live} must precede its swap");
        }
    }

    #[test]
    fn apply_script_restores_both_configs_on_failure() {
        // On ANY unit failing to become active, BOTH configs roll back and
        // BOTH units restart (backend-first) before `exit 1`.
        // Strip `#` comment lines first so a doc-comment mentioning
        // "exit 1" can't be mistaken for the actual command.
        let s = strip_comment_lines(&dns_tunnel_apply_script());
        let restore_env = s
            .find(&format!(
                "mv {SLIPSTREAM_CONFIG_PATH}.bak {SLIPSTREAM_CONFIG_PATH}"
            ))
            .expect("slipstream restore mv missing");
        let restore_sb = s
            .find(&format!(
                "mv {SINGBOX_CONFIG_PATH}.bak {SINGBOX_CONFIG_PATH}"
            ))
            .expect("sing-box restore mv missing");
        let exit1 = s.find("exit 1").expect("failure exit missing");
        assert!(restore_env < exit1 && restore_sb < exit1);
        // Both units restarted back to good after the restore.
        let tail = &s[restore_env.min(restore_sb)..exit1];
        assert!(
            tail.contains(&format!("systemctl restart {BACKEND_UNIT}")),
            "backend must restart on the rollback branch"
        );
        assert!(
            tail.contains(&format!("systemctl restart {RELAY_UNIT}")),
            "relay must restart on the rollback branch"
        );
        // Restore steps `|| true`-guarded so the branch always hits exit 1.
        assert!(tail.contains("|| true"));
    }

    #[test]
    fn apply_script_cleans_up_baks_on_success() {
        let s = dns_tunnel_apply_script();
        assert!(
            s.contains(&format!(
                "rm -f {SLIPSTREAM_CONFIG_PATH}.bak {SINGBOX_CONFIG_PATH}.bak || true"
            )),
            "success path must remove both transient .bak snapshots with non-fatal || true: {s}"
        );
    }

    #[test]
    fn apply_script_first_deploy_failure_stops_disables_and_removes_configs() {
        // When no backup exists (first deploy failure), both units must be
        // stopped and disabled, and failed configs removed before `exit 1`
        // so `Restart=on-failure` units do not crash-loop.
        let s = strip_comment_lines(&dns_tunnel_apply_script());
        let stop_relay = s
            .find(&format!("systemctl stop {RELAY_UNIT} || true"))
            .expect("relay stop missing on first-deploy failure branch");
        let disable_relay = s
            .find(&format!("systemctl disable {RELAY_UNIT} || true"))
            .expect("relay disable missing on first-deploy failure branch");
        let stop_backend = s
            .find(&format!("systemctl stop {BACKEND_UNIT} || true"))
            .expect("backend stop missing on first-deploy failure branch");
        let disable_backend = s
            .find(&format!("systemctl disable {BACKEND_UNIT} || true"))
            .expect("backend disable missing on first-deploy failure branch");
        let rm_relay = s
            .find(&format!("rm -f {SLIPSTREAM_CONFIG_PATH}"))
            .expect("relay config cleanup missing on first-deploy failure branch");
        let rm_backend = s
            .find(&format!("rm -f {SINGBOX_CONFIG_PATH}"))
            .expect("backend config cleanup missing on first-deploy failure branch");
        let exit1 = s.find("exit 1").expect("failure exit missing");

        assert!(stop_relay < exit1, "stop relay must precede exit 1");
        assert!(disable_relay < exit1, "disable relay must precede exit 1");
        assert!(stop_backend < exit1, "stop backend must precede exit 1");
        assert!(
            disable_backend < exit1,
            "disable backend must precede exit 1"
        );
        assert!(rm_relay < exit1, "rm relay config must precede exit 1");
        assert!(rm_backend < exit1, "rm backend config must precede exit 1");

        assert!(
            s.contains("no previous config for dns-tunnel-singbox — removing failed deploy"),
            "first deploy backend failure message missing: {s}"
        );
        assert!(
            s.contains("no previous config for dns-tunnel — removing failed deploy"),
            "first deploy relay failure message missing: {s}"
        );
    }

    #[test]
    fn apply_script_mixed_backup_states_and_branch_placement() {
        let s = strip_comment_lines(&dns_tunnel_apply_script());

        // Independent predecessor tracking flags and enablement/active probes must be initialized before swaps.
        let init_relay_prev = s
            .find("HAD_RELAY_PREV=0")
            .expect("HAD_RELAY_PREV=0 initialization missing");
        let init_backend_prev = s
            .find("HAD_BACKEND_PREV=0")
            .expect("HAD_BACKEND_PREV=0 initialization missing");
        let init_be_enabled = s
            .find("HAD_BACKEND_ENABLED=0")
            .expect("HAD_BACKEND_ENABLED=0 initialization missing");
        let init_be_active = s
            .find("HAD_BACKEND_ACTIVE=0")
            .expect("HAD_BACKEND_ACTIVE=0 initialization missing");
        let init_re_enabled = s
            .find("HAD_RELAY_ENABLED=0")
            .expect("HAD_RELAY_ENABLED=0 initialization missing");
        let init_re_active = s
            .find("HAD_RELAY_ACTIVE=0")
            .expect("HAD_RELAY_ACTIVE=0 initialization missing");

        let swap_relay = s
            .find(&format!(
                "mv {SLIPSTREAM_CONFIG_PATH}.new {SLIPSTREAM_CONFIG_PATH} || recover \"\""
            ))
            .expect("swap relay missing");
        assert!(
            init_relay_prev < swap_relay
                && init_backend_prev < swap_relay
                && init_be_enabled < swap_relay
                && init_be_active < swap_relay
                && init_re_enabled < swap_relay
                && init_re_active < swap_relay
        );

        let probe_be_enabled = s
            .find(&format!(
                "systemctl is-enabled --quiet {BACKEND_UNIT} 2>/dev/null"
            ))
            .expect("backend is-enabled probe missing");
        let probe_be_active = s
            .find(&format!(
                "systemctl is-active --quiet {BACKEND_UNIT} 2>/dev/null"
            ))
            .expect("backend is-active probe missing");
        let probe_re_enabled = s
            .find(&format!(
                "systemctl is-enabled --quiet {RELAY_UNIT} 2>/dev/null"
            ))
            .expect("relay is-enabled probe missing");
        let probe_re_active = s
            .find(&format!(
                "systemctl is-active --quiet {RELAY_UNIT} 2>/dev/null"
            ))
            .expect("relay is-active probe missing");

        assert!(
            probe_be_enabled < swap_relay
                && probe_be_active < swap_relay
                && probe_re_enabled < swap_relay
                && probe_re_active < swap_relay,
            "pre-deploy enabled/active state probing must precede swaps"
        );

        let recover_branch = s.find("recover() {").expect("recover function missing");
        let exit1 = s[recover_branch..]
            .find("exit 1")
            .expect("failure exit missing")
            + recover_branch;
        let fail_block = &s[recover_branch..exit1];

        // 1. Backend branch checks HAD_BACKEND_PREV and handles backup vs first-deploy.
        assert!(
            fail_block.contains(&format!(
                "if [ \"$HAD_BACKEND_PREV\" = 1 ] && [ -f {SINGBOX_CONFIG_PATH}.bak ]; then"
            )),
            "backend backup check missing in failure block"
        );
        assert!(
            fail_block.contains(&format!(
                "mv {SINGBOX_CONFIG_PATH}.bak {SINGBOX_CONFIG_PATH} || true"
            )),
            "backend config restore missing in backup branch"
        );
        assert!(
            fail_block.contains(&format!(
                "if [ \"$HAD_BACKEND_ENABLED\" = 1 ]; then\n                        systemctl enable {BACKEND_UNIT} >/dev/null 2>&1 || true\n                    else\n                        systemctl disable {BACKEND_UNIT} >/dev/null 2>&1 || true\n                    fi"
            )),
            "backend enablement restoration branch missing in backup block"
        );
        assert!(
            fail_block.contains(&format!(
                "if [ \"$HAD_BACKEND_ACTIVE\" = 1 ]; then\n                        systemctl restart {BACKEND_UNIT} || true\n                    else\n                        systemctl stop {BACKEND_UNIT} || true\n                    fi"
            )),
            "backend active restoration branch missing in backup block"
        );
        assert!(
            fail_block.contains(&format!("systemctl stop {BACKEND_UNIT} || true")),
            "backend stop missing in no-backup branch"
        );
        assert!(
            fail_block.contains(&format!("systemctl disable {BACKEND_UNIT} || true")),
            "backend disable missing in no-backup branch"
        );
        assert!(
            fail_block.contains(&format!("rm -f {SINGBOX_CONFIG_PATH}")),
            "backend config remove missing in no-backup branch"
        );

        // 2. Relay branch checks HAD_RELAY_PREV and handles backup vs first-deploy.
        assert!(
            fail_block.contains(&format!(
                "if [ \"$HAD_RELAY_PREV\" = 1 ] && [ -f {SLIPSTREAM_CONFIG_PATH}.bak ]; then"
            )),
            "relay backup check missing in failure block"
        );
        assert!(
            fail_block.contains(&format!(
                "mv {SLIPSTREAM_CONFIG_PATH}.bak {SLIPSTREAM_CONFIG_PATH} || true"
            )),
            "relay config restore missing in backup branch"
        );
        assert!(
            fail_block.contains(&format!(
                "if [ \"$HAD_RELAY_ENABLED\" = 1 ]; then\n                        systemctl enable {RELAY_UNIT} >/dev/null 2>&1 || true\n                    else\n                        systemctl disable {RELAY_UNIT} >/dev/null 2>&1 || true\n                    fi"
            )),
            "relay enablement restoration branch missing in backup block"
        );
        assert!(
            fail_block.contains(&format!(
                "if [ \"$HAD_RELAY_ACTIVE\" = 1 ]; then\n                        systemctl restart {RELAY_UNIT} || true\n                    else\n                        systemctl stop {RELAY_UNIT} || true\n                    fi"
            )),
            "relay active restoration branch missing in backup block"
        );
        assert!(
            fail_block.contains(&format!("systemctl stop {RELAY_UNIT} || true")),
            "relay stop missing in no-backup branch"
        );
        assert!(
            fail_block.contains(&format!("systemctl disable {RELAY_UNIT} || true")),
            "relay disable missing in no-backup branch"
        );
        assert!(
            fail_block.contains(&format!("rm -f {SLIPSTREAM_CONFIG_PATH}")),
            "relay config remove missing in no-backup branch"
        );

        // 3. Ordering: Backend recovery logic is placed before Relay recovery logic.
        let backend_pos = fail_block
            .find("$HAD_BACKEND_PREV")
            .expect("HAD_BACKEND_PREV in fail block");
        let relay_pos = fail_block
            .find("$HAD_RELAY_PREV")
            .expect("HAD_RELAY_PREV in fail block");
        assert!(
            backend_pos < relay_pos,
            "backend recovery must precede relay recovery"
        );
    }

    #[test]
    fn apply_script_snapshot_cp_failures_abort_before_swap() {
        // Snapshot operations on existing configs must run directly without error
        // swallowing (no || true, no 2>/dev/null in an if-guard) so any snapshot
        // failure trips `set -e` and aborts BEFORE any swap (.new -> live) occurs.
        let s = strip_comment_lines(&dns_tunnel_apply_script());

        let relay_snap = format!("cp -a {SLIPSTREAM_CONFIG_PATH} {SLIPSTREAM_CONFIG_PATH}.bak");
        let backend_snap = format!("cp -a {SINGBOX_CONFIG_PATH} {SINGBOX_CONFIG_PATH}.bak");

        assert!(s.contains(&relay_snap), "relay snapshot command missing");
        assert!(
            backend_snap_command_exists(&s, &backend_snap),
            "backend snapshot command missing"
        );

        // Ensure no `|| true` on snapshot lines.
        for line in s.lines() {
            if line.contains(&relay_snap) || line.contains(&backend_snap) {
                assert!(
                    !line.contains("|| true") && !line.contains("2>/dev/null"),
                    "snapshot cp must not swallow errors or ignore exit code: {line}"
                );
            }
        }
    }

    fn backend_snap_command_exists(script: &str, expected: &str) -> bool {
        script.contains(expected)
    }

    #[test]
    fn apply_script_restart_commands_route_to_recovery_machine() {
        // Synchronous `systemctl restart` failures must not escape unhandled under `set -e`.
        // They must capture the failure and route immediately to the recovery state machine.
        let s = strip_comment_lines(&dns_tunnel_apply_script());

        let expected_backend_enable = format!(
            "systemctl enable {BACKEND_UNIT} >/dev/null 2>&1 || recover \"{BACKEND_UNIT}\""
        );
        let expected_relay_enable =
            format!("systemctl enable {RELAY_UNIT} >/dev/null 2>&1 || recover \"{RELAY_UNIT}\"");
        let expected_backend_restart =
            format!("systemctl restart {BACKEND_UNIT} || recover \"{BACKEND_UNIT}\"");
        let expected_relay_restart =
            format!("systemctl restart {RELAY_UNIT} || recover \"{RELAY_UNIT}\"");

        assert!(
            s.contains(&expected_backend_enable),
            "backend enable must route failure to recover(): {s}"
        );
        assert!(
            s.contains(&expected_relay_enable),
            "relay enable must route failure to recover(): {s}"
        );
        assert!(
            s.contains(&expected_backend_restart),
            "backend restart must route failure to recover(): {s}"
        );
        assert!(
            s.contains(&expected_relay_restart),
            "relay restart must route failure to recover(): {s}"
        );
    }

    #[test]
    fn apply_script_poll_failure_routes_to_recovery_machine() {
        // If settlement polling times out without both units becoming active,
        // the failure must route to the common recovery state machine.
        let s = strip_comment_lines(&dns_tunnel_apply_script());

        let poll_block = s.find("for s in").expect("poll loop missing");
        let poll_tail = &s[poll_block..];

        assert!(
            poll_tail.contains("recover \"$s\""),
            "poll timeout must invoke recover(): {poll_tail}"
        );
    }

    #[test]
    fn runtime_provision_script_resolves_singbox_executable_path() {
        let script = runtime_provision_script();
        assert!(
            script.contains("SB_BIN=$(command -v sing-box 2>/dev/null || echo /usr/bin/sing-box)"),
            "runtime provision script must dynamically resolve sing-box binary via command -v: {script}"
        );
        assert!(
            script.contains("ExecStart=$SB_BIN run -c /etc/dns-tunnel/tunnel-sb.json"),
            "backend unit must use the resolved $SB_BIN in ExecStart: {script}"
        );
    }

    #[test]
    fn runtime_provision_script_handles_usr_local_bin_only_and_exact_exec_start() {
        let script = runtime_provision_script();
        assert!(
            script.contains("SB_BIN=$(command -v sing-box 2>/dev/null || echo /usr/bin/sing-box)"),
            "runtime_provision_script must resolve sing-box path: {script}"
        );

        let run_snippet = |mock_singbox_path: Option<&str>| -> String {
            let command_mock = match mock_singbox_path {
                Some(p) => format!(
                    r#"command() {{ if [ "$1" = "-v" ] && [ "$2" = "sing-box" ]; then echo "{p}"; return 0; fi; return 1; }}"#
                ),
                None => r#"command() { return 1; }"#.to_string(),
            };
            let test_script = format!(
                r#"
                set -eu
                TMP_UNIT=$(mktemp)
                trap 'rm -f "$TMP_UNIT"' EXIT
                {command_mock}
                SB_BIN=$(command -v sing-box 2>/dev/null || echo /usr/bin/sing-box)
                cat > "$TMP_UNIT" <<BACKEND_UNIT_EOF
[Unit]
Description=sing-box VLESS inbound for DNS tunnel (loopback :9001) — vpnctl-managed
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$SB_BIN run -c /etc/dns-tunnel/tunnel-sb.json
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
BACKEND_UNIT_EOF
                cat "$TMP_UNIT"
                "#
            );
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(&test_script)
                .output()
                .expect("failed to run test script");
            assert!(out.status.success(), "shell execution failed: {:?}", out);
            String::from_utf8_lossy(&out.stdout).to_string()
        };

        // 1. /usr/local/bin-only scenario: sing-box resolved to /usr/local/bin/sing-box
        let unit_usr_local = run_snippet(Some("/usr/local/bin/sing-box"));
        assert!(
            unit_usr_local.contains(
                "ExecStart=/usr/local/bin/sing-box run -c /etc/dns-tunnel/tunnel-sb.json"
            ),
            "ExecStart must use /usr/local/bin/sing-box when sing-box is only in /usr/local/bin:\n{unit_usr_local}"
        );

        // 2. Canonical /usr/bin scenario: sing-box resolved to /usr/bin/sing-box
        let unit_usr = run_snippet(Some("/usr/bin/sing-box"));
        assert!(
            unit_usr.contains("ExecStart=/usr/bin/sing-box run -c /etc/dns-tunnel/tunnel-sb.json"),
            "ExecStart must use /usr/bin/sing-box when sing-box is in /usr/bin:\n{unit_usr}"
        );

        // 3. Fallback scenario (sing-box not found via command -v)
        let unit_fallback = run_snippet(None);
        assert!(
            unit_fallback
                .contains("ExecStart=/usr/bin/sing-box run -c /etc/dns-tunnel/tunnel-sb.json"),
            "ExecStart must fall back to /usr/bin/sing-box:\n{unit_fallback}"
        );
    }

    #[test]
    fn runtime_provision_script_usr_local_bin_only_end_to_end() {
        let script = runtime_provision_script();
        let test_script = format!(
            r#"
            set -eu
            TMP_DIR=$(mktemp -d)
            trap 'rm -rf "$TMP_DIR"' EXIT
            mkdir -p "$TMP_DIR/systemd" "$TMP_DIR/run"

            # Mock external commands to isolate filesystem writes
            install() {{ :; }}
            id() {{ return 0; }}
            useradd() {{ :; }}
            systemctl() {{ :; }}
            command() {{
                if [ "$1" = "-v" ]; then
                    if [ "$2" = "sing-box" ]; then
                        echo "/usr/local/bin/sing-box"
                        return 0
                    elif [ "$2" = "/usr/local/bin/slipstream-server" ]; then
                        return 0
                    fi
                fi
                return 1
            }}

            # Run modified script redirecting /etc/systemd/system to TMP_DIR/systemd
            EVAL_SCRIPT=$(cat <<'EOF'
{script}
EOF
)
            EVAL_SCRIPT=$(echo "$EVAL_SCRIPT" | sed "s|/etc/systemd/system/|$TMP_DIR/systemd/|g")
            eval "$EVAL_SCRIPT"

            cat "$TMP_DIR/systemd/dns-tunnel-singbox.service"
            "#
        );
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&test_script)
            .output()
            .expect("failed to execute test script for runtime_provision_script");
        assert!(out.status.success(), "script failed: {:?}", out);
        let generated_unit = String::from_utf8_lossy(&out.stdout);
        assert!(
            generated_unit.contains(
                "ExecStart=/usr/local/bin/sing-box run -c /etc/dns-tunnel/tunnel-sb.json"
            ),
            "dns-tunnel-singbox.service ExecStart must resolve to /usr/local/bin/sing-box when sing-box is only in /usr/local/bin:\n{generated_unit}"
        );
    }

    #[test]
    fn apply_script_uses_explicit_guards_and_no_err_trap() {
        let s = strip_comment_lines(&dns_tunnel_apply_script());

        // Asserts NO ERR trap is armed or disarmed anywhere in the POSIX sh script.
        assert!(
            !s.contains("trap") || !s.contains("ERR"),
            "apply script must not use unsupported trap ERR in POSIX sh: {s}"
        );
        assert!(!s.contains("trap 'recover' ERR"));
        assert!(!s.contains("trap - ERR"));

        // Asserts every post-swap mutation command that can fail uses explicit `|| recover ""`
        let expected_relay_mv =
            format!("mv {SLIPSTREAM_CONFIG_PATH}.new {SLIPSTREAM_CONFIG_PATH} || recover \"\"");
        let expected_relay_chown =
            format!("chown dns-tunnel:dns-tunnel {SLIPSTREAM_CONFIG_PATH} || recover \"\"");
        let expected_relay_chmod = format!("chmod 0640 {SLIPSTREAM_CONFIG_PATH} || recover \"\"");
        let expected_backend_mv =
            format!("mv {SINGBOX_CONFIG_PATH}.new {SINGBOX_CONFIG_PATH} || recover \"\"");
        let expected_backend_chown =
            format!("chown root:root {SINGBOX_CONFIG_PATH} || recover \"\"");
        let expected_backend_chmod = format!("chmod 0644 {SINGBOX_CONFIG_PATH} || recover \"\"");
        let expected_rundir_chown =
            format!("chown -R dns-tunnel:dns-tunnel {NODE_RUN_DIR} || recover \"\"");
        let expected_bundle_rm = "rm -f \"$BUNDLE\" || recover \"\"";

        assert!(
            s.contains(&expected_relay_mv),
            "relay swap mv must use explicit || recover \"\""
        );
        assert!(
            s.contains(&expected_relay_chown),
            "relay chown must use explicit || recover \"\""
        );
        assert!(
            s.contains(&expected_relay_chmod),
            "relay chmod must use explicit || recover \"\""
        );
        assert!(
            s.contains(&expected_backend_mv),
            "backend swap mv must use explicit || recover \"\""
        );
        assert!(
            s.contains(&expected_backend_chown),
            "backend chown must use explicit || recover \"\""
        );
        assert!(
            s.contains(&expected_backend_chmod),
            "backend chmod must use explicit || recover \"\""
        );
        assert!(
            s.contains(&expected_rundir_chown),
            "rundir chown -R must use explicit || recover \"\""
        );
        assert!(
            s.contains(expected_bundle_rm),
            "bundle rm must use explicit || recover \"\""
        );

        // Asserts recover() disables -e to prevent aborts during rollback and protects against recursion
        let recover_pos = s.find("recover() {").expect("recover function missing");
        let exit1_pos = s[recover_pos..].find("exit 1").expect("exit 1 missing") + recover_pos;
        let recover_body = &s[recover_pos..exit1_pos];

        assert!(
            recover_body.contains("set +e"),
            "recover() must disable -e to prevent aborts during rollback"
        );
        assert!(
            s.contains("_in_recover=0")
                && recover_body.contains("[ \"$_in_recover\" = 1 ] && return 1"),
            "recover() must guard against recursion"
        );
    }

    #[test]
    fn apply_script_preswap_snapshot_failure_does_not_invoke_recover_e2e() {
        let script = dns_tunnel_apply_script();
        let test_script = format!(
            r#"
            set -eu
            TMP_DIR=$(mktemp -d)
            trap 'rm -rf "$TMP_DIR"' EXIT
            mkdir -p "$TMP_DIR/etc/dns-tunnel"

            # Create existing live configs
            echo "LIVE_RELAY_CONTENT" > "$TMP_DIR/etc/dns-tunnel/slipstream.env"
            echo "LIVE_BACKEND_CONTENT" > "$TMP_DIR/etc/dns-tunnel/tunnel-sb.json"

            # Create deploy bundle with remapped paths
            cat > "$TMP_DIR/etc/dns-tunnel/.deploy-bundle.new" <<BUNDLE_EOF
====FILE: $TMP_DIR/etc/dns-tunnel/slipstream.env====
NEW_RELAY_CONTENT
====FILE: $TMP_DIR/etc/dns-tunnel/tunnel-sb.json====
NEW_BACKEND_CONTENT
BUNDLE_EOF

            # Mock external commands to isolate test
            install() {{ :; }}
            chown() {{ :; }}
            chmod() {{ :; }}
            systemctl() {{ :; }}
            journalctl() {{ :; }}
            # Mock cp to fail on snapshot (-a)
            cp() {{
                if [ "${{1:-}}" = "-a" ]; then
                    return 1
                fi
                command cp "$@"
            }}

            EVAL_SCRIPT=$(cat <<'EOF'
{script}
EOF
)
            # Remap /etc/dns-tunnel to TMP_DIR/etc/dns-tunnel
            EVAL_SCRIPT=$(echo "$EVAL_SCRIPT" | sed "s|/etc/dns-tunnel|$TMP_DIR/etc/dns-tunnel|g")

            set +e
            OUTPUT=$(eval "$EVAL_SCRIPT" 2>&1)
            STATUS=$?
            set -e

            if [ "$STATUS" -eq 0 ]; then
                echo "FAIL: expected non-zero exit on snapshot failure, got 0" >&2
                exit 1
            fi

            # Ensure recover was NOT invoked
            if echo "$OUTPUT" | grep -q "rolling back"; then
                echo "FAIL: recover was invoked on pre-swap snapshot failure: $OUTPUT" >&2
                exit 1
            fi
            if echo "$OUTPUT" | grep -q "did not become active"; then
                echo "FAIL: recover logged unit failure: $OUTPUT" >&2
                exit 1
            fi

            # Live configs must remain intact and unchanged
            RELAY_CONTENT=$(cat "$TMP_DIR/etc/dns-tunnel/slipstream.env")
            BACKEND_CONTENT=$(cat "$TMP_DIR/etc/dns-tunnel/tunnel-sb.json")
            if [ "$RELAY_CONTENT" != "LIVE_RELAY_CONTENT" ]; then
                echo "FAIL: relay live content changed: $RELAY_CONTENT" >&2
                exit 1
            fi
            if [ "$BACKEND_CONTENT" != "LIVE_BACKEND_CONTENT" ]; then
                echo "FAIL: backend live content changed: $BACKEND_CONTENT" >&2
                exit 1
            fi
            "#
        );

        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(&test_script)
            .output()
            .expect("failed to run preswap snapshot failure e2e test");
        assert!(
            out.status.success(),
            "preswap snapshot test failed: stdout={}, stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn apply_script_postswap_chown_failure_invokes_recover_e2e() {
        let script = dns_tunnel_apply_script();
        let test_script = format!(
            r#"
            set -eu
            TMP_DIR=$(mktemp -d)
            trap 'rm -rf "$TMP_DIR"' EXIT
            mkdir -p "$TMP_DIR/etc/dns-tunnel"

            # Create existing live configs
            echo "LIVE_RELAY_PREV" > "$TMP_DIR/etc/dns-tunnel/slipstream.env"
            echo "LIVE_BACKEND_PREV" > "$TMP_DIR/etc/dns-tunnel/tunnel-sb.json"

            # Create deploy bundle with remapped paths
            cat > "$TMP_DIR/etc/dns-tunnel/.deploy-bundle.new" <<BUNDLE_EOF
====FILE: $TMP_DIR/etc/dns-tunnel/slipstream.env====
NEW_RELAY_CONTENT
====FILE: $TMP_DIR/etc/dns-tunnel/tunnel-sb.json====
NEW_BACKEND_CONTENT
BUNDLE_EOF

            # Mock chown to fail (simulating post-swap intermediate failure)
            chown() {{
                return 1
            }}
            chmod() {{ :; }}
            install() {{ :; }}
            systemctl() {{ :; }}
            journalctl() {{ :; }}

            EVAL_SCRIPT=$(cat <<'EOF'
{script}
EOF
)
            # Remap /etc/dns-tunnel to TMP_DIR/etc/dns-tunnel
            EVAL_SCRIPT=$(echo "$EVAL_SCRIPT" | sed "s|/etc/dns-tunnel|$TMP_DIR/etc/dns-tunnel|g")

            set +e
            OUTPUT=$(eval "$EVAL_SCRIPT" 2>&1)
            STATUS=$?
            set -e

            if [ "$STATUS" -ne 1 ]; then
                echo "FAIL: expected exit 1 from recover, got $STATUS; output: $OUTPUT" >&2
                exit 1
            fi

            # Ensure recover was invoked and rolled back
            if ! echo "$OUTPUT" | grep -q "rolling back dns-tunnel-singbox to previous config"; then
                echo "FAIL: backend rollback missing in output: $OUTPUT" >&2
                exit 1
            fi
            if ! echo "$OUTPUT" | grep -q "rolling back dns-tunnel to previous config"; then
                echo "FAIL: relay rollback missing in output: $OUTPUT" >&2
                exit 1
            fi

            # Live configs must be restored to previous state
            RELAY_CONTENT=$(cat "$TMP_DIR/etc/dns-tunnel/slipstream.env")
            BACKEND_CONTENT=$(cat "$TMP_DIR/etc/dns-tunnel/tunnel-sb.json")
            if [ "$RELAY_CONTENT" != "LIVE_RELAY_PREV" ]; then
                echo "FAIL: relay live content not restored: $RELAY_CONTENT" >&2
                exit 1
            fi
            if [ "$BACKEND_CONTENT" != "LIVE_BACKEND_PREV" ]; then
                echo "FAIL: backend live content not restored: $BACKEND_CONTENT" >&2
                exit 1
            fi
            "#
        );

        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(&test_script)
            .output()
            .expect("failed to run postswap chown failure e2e test");
        assert!(
            out.status.success(),
            "postswap chown test failed: stdout={}, stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn apply_script_postswap_singbox_mv_failure_invokes_recover_e2e() {
        let script = dns_tunnel_apply_script();
        let test_script = format!(
            r#"
            set -eu
            TMP_DIR=$(mktemp -d)
            trap 'rm -rf "$TMP_DIR"' EXIT
            mkdir -p "$TMP_DIR/etc/dns-tunnel"

            # Create existing live configs
            echo "LIVE_RELAY_PREV" > "$TMP_DIR/etc/dns-tunnel/slipstream.env"
            echo "LIVE_BACKEND_PREV" > "$TMP_DIR/etc/dns-tunnel/tunnel-sb.json"

            # Create deploy bundle with remapped paths
            cat > "$TMP_DIR/etc/dns-tunnel/.deploy-bundle.new" <<BUNDLE_EOF
====FILE: $TMP_DIR/etc/dns-tunnel/slipstream.env====
NEW_RELAY_CONTENT
====FILE: $TMP_DIR/etc/dns-tunnel/tunnel-sb.json====
NEW_BACKEND_CONTENT
BUNDLE_EOF

            # Mock mv so first mv (slipstream) succeeds but second mv (tunnel-sb.json.new) fails
            mv() {{
                for arg in "$@"; do
                    if [ "$arg" = "$TMP_DIR/etc/dns-tunnel/tunnel-sb.json.new" ]; then
                        return 1
                    fi
                done
                command mv "$@"
            }}
            chown() {{ :; }}
            chmod() {{ :; }}
            install() {{ :; }}
            systemctl() {{ :; }}
            journalctl() {{ :; }}

            EVAL_SCRIPT=$(cat <<'EOF'
{script}
EOF
)
            # Remap /etc/dns-tunnel to TMP_DIR/etc/dns-tunnel
            EVAL_SCRIPT=$(echo "$EVAL_SCRIPT" | sed "s|/etc/dns-tunnel|$TMP_DIR/etc/dns-tunnel|g")

            set +e
            OUTPUT=$(eval "$EVAL_SCRIPT" 2>&1)
            STATUS=$?
            set -e

            if [ "$STATUS" -ne 1 ]; then
                echo "FAIL: expected exit 1 from recover, got $STATUS; output: $OUTPUT" >&2
                exit 1
            fi

            # Ensure recover was invoked and rolled back
            if ! echo "$OUTPUT" | grep -q "rolling back dns-tunnel to previous config"; then
                echo "FAIL: relay rollback missing in output: $OUTPUT" >&2
                exit 1
            fi

            # Live configs must be restored to previous state
            RELAY_CONTENT=$(cat "$TMP_DIR/etc/dns-tunnel/slipstream.env")
            BACKEND_CONTENT=$(cat "$TMP_DIR/etc/dns-tunnel/tunnel-sb.json")
            if [ "$RELAY_CONTENT" != "LIVE_RELAY_PREV" ]; then
                echo "FAIL: relay live content not restored: $RELAY_CONTENT" >&2
                exit 1
            fi
            if [ "$BACKEND_CONTENT" != "LIVE_BACKEND_PREV" ]; then
                echo "FAIL: backend live content not restored: $BACKEND_CONTENT" >&2
                exit 1
            fi
            "#
        );

        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(&test_script)
            .output()
            .expect("failed to run postswap second mv failure e2e test");
        assert!(
            out.status.success(),
            "postswap mv test failed: stdout={}, stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn apply_script_first_deploy_postswap_chown_failure_cleans_up_e2e() {
        let script = dns_tunnel_apply_script();
        let test_script = format!(
            r#"
            set -eu
            TMP_DIR=$(mktemp -d)
            trap 'rm -rf "$TMP_DIR"' EXIT
            mkdir -p "$TMP_DIR/etc/dns-tunnel"

            # First deploy: no existing live configs

            # Create deploy bundle with remapped paths
            cat > "$TMP_DIR/etc/dns-tunnel/.deploy-bundle.new" <<BUNDLE_EOF
====FILE: $TMP_DIR/etc/dns-tunnel/slipstream.env====
NEW_RELAY_CONTENT
====FILE: $TMP_DIR/etc/dns-tunnel/tunnel-sb.json====
NEW_BACKEND_CONTENT
BUNDLE_EOF

            # Mock chown to fail
            chown() {{
                return 1
            }}
            chmod() {{ :; }}
            install() {{ :; }}
            systemctl() {{ :; }}
            journalctl() {{ :; }}

            EVAL_SCRIPT=$(cat <<'EOF'
{script}
EOF
)
            # Remap /etc/dns-tunnel to TMP_DIR/etc/dns-tunnel
            EVAL_SCRIPT=$(echo "$EVAL_SCRIPT" | sed "s|/etc/dns-tunnel|$TMP_DIR/etc/dns-tunnel|g")

            set +e
            OUTPUT=$(eval "$EVAL_SCRIPT" 2>&1)
            STATUS=$?
            set -e

            if [ "$STATUS" -ne 1 ]; then
                echo "FAIL: expected exit 1 from recover, got $STATUS; output: $OUTPUT" >&2
                exit 1
            fi

            # Ensure cleanup messages logged
            if ! echo "$OUTPUT" | grep -q "no previous config for dns-tunnel-singbox — removing failed deploy"; then
                echo "FAIL: backend cleanup missing in output: $OUTPUT" >&2
                exit 1
            fi
            if ! echo "$OUTPUT" | grep -q "no previous config for dns-tunnel — removing failed deploy"; then
                echo "FAIL: relay cleanup missing in output: $OUTPUT" >&2
                exit 1
            fi

            # Failed configs must be removed
            if [ -f "$TMP_DIR/etc/dns-tunnel/slipstream.env" ]; then
                echo "FAIL: failed relay config was not removed" >&2
                exit 1
            fi
            if [ -f "$TMP_DIR/etc/dns-tunnel/tunnel-sb.json" ]; then
                echo "FAIL: failed backend config was not removed" >&2
                exit 1
            fi
            "#
        );

        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(&test_script)
            .output()
            .expect("failed to run first deploy chown failure e2e test");
        assert!(
            out.status.success(),
            "first deploy postswap chown test failed: stdout={}, stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn apply_script_mixed_prior_enablement_and_active_restoration_e2e() {
        let script = dns_tunnel_apply_script();
        let test_script = format!(
            r#"
            set -eu
            TMP_DIR=$(mktemp -d)
            trap 'rm -rf "$TMP_DIR"' EXIT
            mkdir -p "$TMP_DIR/etc/dns-tunnel"

            # Create existing live configs for both units
            echo "LIVE_RELAY_PREV" > "$TMP_DIR/etc/dns-tunnel/slipstream.env"
            echo "LIVE_BACKEND_PREV" > "$TMP_DIR/etc/dns-tunnel/tunnel-sb.json"

            # Create deploy bundle with remapped paths
            cat > "$TMP_DIR/etc/dns-tunnel/.deploy-bundle.new" <<BUNDLE_EOF
====FILE: $TMP_DIR/etc/dns-tunnel/slipstream.env====
NEW_RELAY_CONTENT
====FILE: $TMP_DIR/etc/dns-tunnel/tunnel-sb.json====
NEW_BACKEND_CONTENT
BUNDLE_EOF

            # Mock systemctl to simulate mixed initial states:
            # Backend: was enabled and active
            # Relay: was disabled and inactive
            # Also records all mutating commands (enable, disable, restart, stop) into a log file.
            CMD_LOG="$TMP_DIR/systemctl_actions.log"
            touch "$CMD_LOG"

            systemctl() {{
                action="$1"
                shift
                case "$action" in
                    is-enabled)
                        unit="${{2:-$1}}"
                        if [ "$unit" = "dns-tunnel-singbox" ]; then
                            return 0
                        else
                            return 1
                        fi
                        ;;
                    is-active)
                        unit="${{2:-$1}}"
                        if [ "$unit" = "dns-tunnel-singbox" ]; then
                            echo "active"
                            return 0
                        else
                            echo "inactive"
                            return 3
                        fi
                        ;;
                    enable|disable|restart|stop)
                        echo "$action $*" >> "$CMD_LOG"
                        return 0
                        ;;
                    *)
                        return 0
                        ;;
                esac
            }}

            # Mock chmod to fail on post-swap slipstream chmod (simulating post-swap failure)
            chmod() {{
                for arg in "$@"; do
                    if [ "$arg" = "$TMP_DIR/etc/dns-tunnel/slipstream.env" ]; then
                        return 1
                    fi
                done
                command chmod "$@"
            }}
            chown() {{ :; }}
            install() {{ :; }}
            journalctl() {{ :; }}

            EVAL_SCRIPT=$(cat <<'EOF'
{script}
EOF
)
            # Remap /etc/dns-tunnel to TMP_DIR/etc/dns-tunnel
            EVAL_SCRIPT=$(echo "$EVAL_SCRIPT" | sed "s|/etc/dns-tunnel|$TMP_DIR/etc/dns-tunnel|g")

            set +e
            OUTPUT=$(eval "$EVAL_SCRIPT" 2>&1)
            STATUS=$?
            set -e

            if [ "$STATUS" -ne 1 ]; then
                echo "FAIL: expected exit 1 from recover, got $STATUS; output: $OUTPUT" >&2
                exit 1
            fi

            # Check logged systemctl actions during recovery:
            # Backend: was enabled+active -> recovered via enable + restart
            # Relay: was disabled+inactive -> recovered via disable + stop
            if ! grep -q "enable dns-tunnel-singbox" "$CMD_LOG"; then
                echo "FAIL: backend enable missing in recovery: $(cat "$CMD_LOG")" >&2
                exit 1
            fi
            if ! grep -q "restart dns-tunnel-singbox" "$CMD_LOG"; then
                echo "FAIL: backend restart missing in recovery: $(cat "$CMD_LOG")" >&2
                exit 1
            fi
            if ! grep -q "disable dns-tunnel" "$CMD_LOG"; then
                echo "FAIL: relay disable missing in recovery: $(cat "$CMD_LOG")" >&2
                exit 1
            fi
            if ! grep -q "stop dns-tunnel" "$CMD_LOG"; then
                echo "FAIL: relay stop missing in recovery: $(cat "$CMD_LOG")" >&2
                exit 1
            fi

            # Live configs must be restored to previous state
            RELAY_CONTENT=$(cat "$TMP_DIR/etc/dns-tunnel/slipstream.env")
            BACKEND_CONTENT=$(cat "$TMP_DIR/etc/dns-tunnel/tunnel-sb.json")
            if [ "$RELAY_CONTENT" != "LIVE_RELAY_PREV" ]; then
                echo "FAIL: relay live content not restored: $RELAY_CONTENT" >&2
                exit 1
            fi
            if [ "$BACKEND_CONTENT" != "LIVE_BACKEND_PREV" ]; then
                echo "FAIL: backend live content not restored: $BACKEND_CONTENT" >&2
                exit 1
            fi
            "#
        );

        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&test_script)
            .output()
            .expect("failed to run mixed prior state restoration e2e test");
        assert!(
            out.status.success(),
            "mixed prior state restoration test failed: stdout={}, stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn apply_script_mixed_first_deploy_and_upgrade_recovery_e2e() {
        let script = dns_tunnel_apply_script();
        let test_script = format!(
            r#"
            set -eu
            TMP_DIR=$(mktemp -d)
            trap 'rm -rf "$TMP_DIR"' EXIT
            mkdir -p "$TMP_DIR/etc/dns-tunnel"

            # Mixed state: Relay has existing config, Backend is first-deploy (no existing config)
            echo "LIVE_RELAY_PREV" > "$TMP_DIR/etc/dns-tunnel/slipstream.env"

            # Create deploy bundle with remapped paths
            cat > "$TMP_DIR/etc/dns-tunnel/.deploy-bundle.new" <<BUNDLE_EOF
====FILE: $TMP_DIR/etc/dns-tunnel/slipstream.env====
NEW_RELAY_CONTENT
====FILE: $TMP_DIR/etc/dns-tunnel/tunnel-sb.json====
NEW_BACKEND_CONTENT
BUNDLE_EOF

            CMD_LOG="$TMP_DIR/systemctl_actions.log"
            touch "$CMD_LOG"

            systemctl() {{
                action="$1"
                shift
                case "$action" in
                    is-enabled)
                        unit="${{2:-$1}}"
                        if [ "$unit" = "dns-tunnel" ]; then
                            return 0
                        else
                            return 1
                        fi
                        ;;
                    is-active)
                        unit="${{2:-$1}}"
                        if [ "$unit" = "dns-tunnel" ]; then
                            echo "active"
                            return 0
                        else
                            echo "inactive"
                            return 3
                        fi
                        ;;
                    enable)
                        unit="${{1:-}}"
                        # Simulate backend enable failure
                        if [ "$unit" = "dns-tunnel-singbox" ]; then
                            echo "enable dns-tunnel-singbox FAILED" >> "$CMD_LOG"
                            return 1
                        fi
                        echo "$action $*" >> "$CMD_LOG"
                        return 0
                        ;;
                    disable|restart|stop)
                        echo "$action $*" >> "$CMD_LOG"
                        return 0
                        ;;
                    *)
                        return 0
                        ;;
                esac
            }}

            chmod() {{ :; }}
            chown() {{ :; }}
            install() {{ :; }}
            journalctl() {{ :; }}

            EVAL_SCRIPT=$(cat <<'EOF'
{script}
EOF
)
            # Remap /etc/dns-tunnel to TMP_DIR/etc/dns-tunnel
            EVAL_SCRIPT=$(echo "$EVAL_SCRIPT" | sed "s|/etc/dns-tunnel|$TMP_DIR/etc/dns-tunnel|g")

            set +e
            OUTPUT=$(eval "$EVAL_SCRIPT" 2>&1)
            STATUS=$?
            set -e

            if [ "$STATUS" -ne 1 ]; then
                echo "FAIL: expected exit 1 from recover, got $STATUS; output: $OUTPUT" >&2
                exit 1
            fi

            # Check logged systemctl actions during recovery:
            # Backend: first deploy -> stopped and disabled
            # Relay: was enabled+active -> enabled and restarted
            if ! grep -q "stop dns-tunnel-singbox" "$CMD_LOG"; then
                echo "FAIL: backend stop missing in recovery: $(cat "$CMD_LOG")" >&2
                exit 1
            fi
            if ! grep -q "disable dns-tunnel-singbox" "$CMD_LOG"; then
                echo "FAIL: backend disable missing in recovery: $(cat "$CMD_LOG")" >&2
                exit 1
            fi
            if ! grep -q "enable dns-tunnel" "$CMD_LOG"; then
                echo "FAIL: relay enable missing in recovery: $(cat "$CMD_LOG")" >&2
                exit 1
            fi
            if ! grep -q "restart dns-tunnel" "$CMD_LOG"; then
                echo "FAIL: relay restart missing in recovery: $(cat "$CMD_LOG")" >&2
                exit 1
            fi

            # Backend failed config must be deleted
            if [ -f "$TMP_DIR/etc/dns-tunnel/tunnel-sb.json" ]; then
                echo "FAIL: backend first-deploy config was not removed" >&2
                exit 1
            fi
            # Relay live config must be restored
            RELAY_CONTENT=$(cat "$TMP_DIR/etc/dns-tunnel/slipstream.env")
            if [ "$RELAY_CONTENT" != "LIVE_RELAY_PREV" ]; then
                echo "FAIL: relay live content not restored: $RELAY_CONTENT" >&2
                exit 1
            fi
            "#
        );

        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&test_script)
            .output()
            .expect("failed to run mixed first-deploy / upgrade recovery e2e test");
        assert!(
            out.status.success(),
            "mixed first-deploy / upgrade recovery test failed: stdout={}, stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn apply_script_successful_deploy_bak_cleanup_failure_does_not_invoke_recover_e2e() {
        let script = dns_tunnel_apply_script();
        let test_script = format!(
            r#"
            set -eu
            TMP_DIR=$(mktemp -d)
            trap 'rm -rf "$TMP_DIR"' EXIT
            mkdir -p "$TMP_DIR/etc/dns-tunnel"

            # Create existing live configs
            echo "LIVE_RELAY_PREV" > "$TMP_DIR/etc/dns-tunnel/slipstream.env"
            echo "LIVE_BACKEND_PREV" > "$TMP_DIR/etc/dns-tunnel/tunnel-sb.json"

            # Create deploy bundle with remapped paths
            cat > "$TMP_DIR/etc/dns-tunnel/.deploy-bundle.new" <<BUNDLE_EOF
====FILE: $TMP_DIR/etc/dns-tunnel/slipstream.env====
NEW_RELAY_CONTENT
====FILE: $TMP_DIR/etc/dns-tunnel/tunnel-sb.json====
NEW_BACKEND_CONTENT
BUNDLE_EOF

            # Mock systemctl so services report active
            systemctl() {{
                action="$1"
                shift
                case "$action" in
                    is-enabled)
                        return 0
                        ;;
                    is-active)
                        echo "active"
                        return 0
                        ;;
                    enable|restart)
                        return 0
                        ;;
                    *)
                        return 0
                        ;;
                esac
            }}

            # Mock rm so removing .bak files fails, but removing bundle succeeds
            rm() {{
                for arg in "$@"; do
                    case "$arg" in
                        *.bak)
                            return 1
                            ;;
                    esac
                done
                command rm "$@"
            }}

            install() {{ :; }}
            chown() {{ :; }}
            chmod() {{ :; }}
            journalctl() {{ :; }}

            EVAL_SCRIPT=$(cat <<'EOF'
{script}
EOF
)
            # Remap /etc/dns-tunnel to TMP_DIR/etc/dns-tunnel
            EVAL_SCRIPT=$(echo "$EVAL_SCRIPT" | sed "s|/etc/dns-tunnel|$TMP_DIR/etc/dns-tunnel|g")

            set +e
            OUTPUT=$(eval "$EVAL_SCRIPT" 2>&1)
            STATUS=$?
            set -e

            if [ "$STATUS" -ne 0 ]; then
                echo "FAIL: expected exit 0 on .bak cleanup failure, got $STATUS; output: $OUTPUT" >&2
                exit 1
            fi

            # Ensure recover was NOT invoked
            if echo "$OUTPUT" | grep -q "rolling back"; then
                echo "FAIL: recover was invoked on post-success .bak cleanup failure: $OUTPUT" >&2
                exit 1
            fi
            if echo "$OUTPUT" | grep -q "removing failed deploy"; then
                echo "FAIL: recover cleanup was invoked on post-success .bak cleanup failure: $OUTPUT" >&2
                exit 1
            fi
            if echo "$OUTPUT" | grep -q "did not become active"; then
                echo "FAIL: recover logged unit failure: $OUTPUT" >&2
                exit 1
            fi

            # New configs must remain active in place
            RELAY_CONTENT=$(cat "$TMP_DIR/etc/dns-tunnel/slipstream.env")
            BACKEND_CONTENT=$(cat "$TMP_DIR/etc/dns-tunnel/tunnel-sb.json")
            if [ "$RELAY_CONTENT" != "NEW_RELAY_CONTENT" ]; then
                echo "FAIL: relay new content not preserved: $RELAY_CONTENT" >&2
                exit 1
            fi
            if [ "$BACKEND_CONTENT" != "NEW_BACKEND_CONTENT" ]; then
                echo "FAIL: backend new content not preserved: $BACKEND_CONTENT" >&2
                exit 1
            fi
            "#
        );

        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&test_script)
            .output()
            .expect("failed to run successful deploy bak cleanup failure e2e test");
        assert!(
            out.status.success(),
            "cleanup failure test failed: stdout={}, stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
