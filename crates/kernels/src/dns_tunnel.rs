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
//! ## Architecture — TWO systemd units (mirrors wgturn relay+backend)
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
//! This kernel OWNS BOTH units (exactly like wgturn owns its relay +
//! `wg-quick@wgturn-be` backend). The composition with sing-box is
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
//! (the slipstream server config + the sing-box JSON), so we reuse
//! wgturn's delimited multi-file bundle (`BUNDLE_DELIMITER`). See
//! `apply_config` for the unpack-then-restart orchestration.
//!
//! ## Binary provisioning — prebuilt cache + SHA256 verify (NOT on-node)
//!
//! slipstream-rust needs ≥2 GB RAM to build (Rust LTO + picoquic/C) and
//! the target box has 960 MB — an on-node build (the wgturn / on-node-Go
//! pattern) is IMPOSSIBLE. So provisioning copies the
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
//! No edits to `core`, `ssh`, `crypto`, `inventory`, `hosters`, or
//! `cli/src/cmd/*` per CLAUDE.md's Kernel × Protocol invariant.

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use vpnctl_core::{
    CoreError, Kernel, KernelId, KernelStatus, Protocol, ProtocolId, RenderCtx, Result,
    SshTransport, User,
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
/// it starts (mirrors wgturn restarting `wg-quick@wgturn-be` before the
/// relay).
const RELAY_UNIT: &str = "dns-tunnel";
const BACKEND_UNIT: &str = "dns-tunnel-singbox";

/// Multi-file bundle delimiter — identical format to
/// `crates/kernels/src/wgturn.rs::BUNDLE_DELIMITER`. `render_config`
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

/// `true` only when the node probe printed exactly `present` — i.e.
/// BOTH the slipstream binary is executable AND sing-box is on PATH
/// (the backend daemon). Pure (testable) so an inverted branch can't
/// slip past CI. Mirrors `caddy::caddy_present`.
fn slipstream_present(probe_stdout: &str) -> bool {
    probe_stdout.trim() == "present"
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
ExecStart={binary} -l ${{SLIPSTREAM_LISTEN_PORT}} -a ${{SLIPSTREAM_FORWARD_TARGET}} -d ${{SLIPSTREAM_DOMAIN}} -c {cert} -k {key} --reset-seed {reset}
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
        # is reachable on boot. Uses the box's existing sing-box binary.
        cat > /etc/systemd/system/{backend}.service <<'BACKEND_UNIT_EOF'
[Unit]
Description=sing-box VLESS inbound for DNS tunnel (loopback :9001) — vpnctl-managed
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/sing-box run -c {sb_config}
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

    async fn ensure_installed(&self, ssh: &dyn SshTransport) -> Result<()> {
        // Idempotency probe: a node that already has the slipstream
        // binary AND sing-box skips straight to runtime provisioning.
        let present = ssh
            .exec(
                "command -v /usr/local/bin/slipstream-server >/dev/null 2>&1 \
                 && command -v sing-box >/dev/null 2>&1 \
                 && echo present || echo absent",
            )
            .await?;

        if !slipstream_present(&present) {
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

            // ── Prebuilt-cache install (NO on-node build fallback). ───
            // slipstream-rust needs ≥2 GB RAM to build (Rust LTO +
            // picoquic/C); the target box has 960 MB. So unlike caddy
            // (which falls back to an on-node xcaddy build on cache-miss)
            // there is NOTHING to fall back to here — a cache-miss is a
            // HARD, LOUD failure pointing the operator at the docker
            // build that populates the cache.
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

            // Integrity-verify on the node before installing it as a
            // root systemd service: SHA256 the bytes we read, upload to
            // .new, `sha256sum -c` there, then atomic mv. `set -eu`
            // aborts the deploy on a corrupted/truncated upload. Same
            // shape as caddy's cache-install path.
            let digest = format!("{:x}", Sha256::digest(&bytes));
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
        // wgturn / caddy).
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
        // than an 8-second is-active poll timeout (mirrors wgturn's
        // listen_port pre-validation).
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

        // ── 3. Assemble the multi-file bundle (wgturn format). ────────
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
        // parses + writes each member then restarts both units. Atomic-
        // rename + 8s is-active poll + journalctl-on-fail mirrors
        // wgturn's apply_config.
        ssh.upload("/etc/dns-tunnel/.deploy-bundle.new", config)
            .await?;
        let cmd = format!(
            r#"
            set -eu

            BUNDLE=/etc/dns-tunnel/.deploy-bundle.new
            test -f "$BUNDLE"

            # Unpack the bundle. Format documented in
            # `crates/kernels/src/dns_tunnel.rs::BUNDLE_DELIMITER` (same
            # as wgturn). Small awk splits on the marker line and writes
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

            # Move each ".new" sibling into place atomically. Files we
            # know about: the slipstream env file + the sing-box JSON.
            mv {slipstream_env}.new {slipstream_env}
            chown dns-tunnel:dns-tunnel {slipstream_env}
            chmod 0640 {slipstream_env}
            mv {sb_config}.new {sb_config}
            chown root:root {sb_config}
            chmod 0644 {sb_config}
            # Make the run dir + auto-generated cert/key reachable by the
            # unprivileged relay user (cert/key may not exist yet — the
            # binary generates them on first run, inheriting this owner).
            chown -R dns-tunnel:dns-tunnel {run_dir}
            rm -f "$BUNDLE"

            # Restart the BACKEND (sing-box loopback inbound) FIRST so the
            # relay's forward-target is reachable when it starts.
            systemctl enable {backend} >/dev/null 2>&1 || true
            systemctl restart {backend}

            # Then the relay itself.
            systemctl enable {relay} >/dev/null 2>&1 || true
            systemctl restart {relay}

            # 8-second wait for BOTH units to settle.
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
                    echo "$s did not become active. Last 20 log lines:" >&2
                    journalctl -u "$s" --no-pager -n 20 >&2 || true
                    exit 1
                fi
            done
        "#,
            run_dir = NODE_RUN_DIR,
            slipstream_env = SLIPSTREAM_CONFIG_PATH,
            sb_config = SINGBOX_CONFIG_PATH,
            backend = BACKEND_UNIT,
            relay = RELAY_UNIT,
        );
        ssh.exec(&cmd).await?;
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
        // the combined check is the honest one — same as wgturn.
        let relay = ssh
            .exec(&format!("systemctl is-active {RELAY_UNIT}"))
            .await?
            .trim()
            .eq("active");
        let backend = ssh
            .exec(&format!("systemctl is-active {BACKEND_UNIT}"))
            .await?
            .trim()
            .eq("active");
        let active = relay && backend;
        let version = ssh
            .exec("slipstream-server --version 2>/dev/null | head -1")
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

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
    fn slipstream_present_only_on_exact_token() {
        assert!(slipstream_present("present"));
        assert!(slipstream_present("present\n"));
        assert!(slipstream_present("  present  "));
        assert!(!slipstream_present("absent"));
        assert!(!slipstream_present(""));
        assert!(!slipstream_present("present extra"));
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
}
