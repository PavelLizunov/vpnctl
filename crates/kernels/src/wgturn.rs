//! wgturn-core — VK-TURN-relayed WireGuard «emergency channel» kernel.
//!
//! `wgturn` is an Apache-2.0 Go library + CLI from
//! github.com/PavelLizunov/wgturn-core (v0.1.0, May 2026). The
//! server-side daemon (`wgturn-cli serve`) listens on a UDP port and
//! terminates DTLS sessions arriving over VK-TURN, then forwards the
//! inner WireGuard payload to a **separate local WireGuard daemon**
//! on loopback. Clients run `wgturn-cli connect-url '<wgturn://...>'
//! --vk-link '<https://vk.com/call/join/...>'` and traffic is relayed
//! through VK Calls' anonymous TURN servers.
//!
//! ## Why this kernel exists
//!
//! Standard VPN protocols (OpenVPN, WireGuard direct, Shadowsocks,
//! xray/REALITY) are all blocked under РФ «white-list» mode. VK is
//! government-mandated and stays reachable; its anonymous-TURN
//! infrastructure becomes a free always-available relay. wgturn-core
//! piggybacks on that with DTLS 1.2 obfuscation + STUN ChannelData.
//!
//! ## Bandwidth ceiling — IMPORTANT operator UX
//!
//! **~200 KB/s (~1.6 Mbps) per device, hard empirical limit.** VK
//! rate-limits anonymous-token requests per source IP. Adding more
//! streams / call links / wgturn-server instances does NOT raise it.
//! Suitable for SSH, IM, web browsing, audio streaming, RSS. NOT
//! suitable for video, file transfer, torrents, video calls.
//!
//! Position as an **emergency channel** beside an xray/REALITY +
//! WireGuard daily-driver — when those get blocked, fall to this.
//!
//! ## Architecture (post-2026-05-19 rewrite)
//!
//! `wgturn-cli serve` is a **thin DTLS relay** — NOT a complete
//! VPN server. It needs a separate WireGuard daemon listening on a
//! loopback port to terminate the inner WG handshake. Architecture:
//!
//! ```text
//! Internet (UDP 56000)
//!     │
//!     ▼  DTLS+STUN over VK-TURN
//! wgturn-cli serve  ── forwards inner WG payload via UDP ──▶ wg-quick@wgturn-be
//!                                                            (127.0.0.1:51821,
//!                                                             interface wgturn-be,
//!                                                             [Peer] per user)
//! ```
//!
//! We therefore deploy + manage TWO systemd units per server:
//!   * `wgturn.service` — wgturn-cli serve, public UDP 56000
//!   * `wg-quick@wgturn-be.service` — backend WG, loopback UDP 51821,
//!     authenticates clients via their `[Peer]` pubkey
//!
//! The previously-tried TOML schema was a guess; upstream actually
//! parses **wg-quick INI with `#@wgt:` metadata comments** via
//! `pkg/wgconf`. Three keys are required for `serve`:
//!   * `#@wgt:EnableServer = true`
//!   * `#@wgt:Listen = 0.0.0.0:<port>`
//!   * `#@wgt:Backend = udp:127.0.0.1:51821`
//!
//! ## Versions tested
//!
//! - `wgturn-core` v0.1.0 (Apache-2.0)
//! - Go 1.25+ required (apt-installs `golang-go` on bookworm — system
//!   ships 1.22; pin via /usr/local/go if newer is needed).
//! - Debian 12 bookworm (the only deploy target today).
//! - wireguard-tools (apt-installable on bookworm) for the wg-quick
//!   backend.
//!
//! ## Multi-file deploy bundle
//!
//! Unlike sing-box / amneziawg (one config file each), wgturn needs
//! TWO files on every deploy:
//!   1. `/etc/wgturn/server.conf` — wgturn-cli serve config (INI)
//!   2. `/etc/wireguard/wgturn-be.conf` — backend WG-quick config (INI)
//!
//! The `Kernel::render_config` trait returns `Vec<u8>` (one blob).
//! We use a delimited multi-file format below; `apply_config` parses
//! the delimiter, writes each file separately, then orchestrates both
//! `systemctl restart` calls. See `BUNDLE_DELIMITER` for the format.
//!
//! ## Kernel orthogonality
//!
//! Adding this kernel touches ONLY:
//!   * `crates/kernels/src/wgturn.rs` (this file)
//!   * `crates/kernels/src/lib.rs` (`mod` + `pub use`)
//!   * `crates/protocols/src/wgturn.rs` (companion stub protocol)
//!   * `crates/protocols/src/lib.rs` (`mod` + `pub use`)
//!   * `cli/src/registry.rs` + `daemon/src/app.rs::build_registry`
//!     — one `register_*` line each
//!   * `daemon/src/wizard_bootstrap.rs::bootstrap_server_secrets` —
//!     mints `wgturn:server_wg_{private,public}` keypair
//!
//! No edits to `core`, `ssh`, `crypto`, `inventory`, `hosters`, or
//! `cli/src/cmd/*` per CLAUDE.md's Kernel × Protocol invariant.

use async_trait::async_trait;
use vpnctl_core::{
    CoreError, Kernel, KernelId, KernelStatus, Protocol, ProtocolId, RenderCtx, Result,
    SshTransport, User,
};

/// Default public UDP port `wgturn-cli serve` listens on for the
/// DTLS+STUN VK-TURN relay traffic. Matches upstream's documented
/// default + the operator-pasted port hint in
/// `cmd/wgturn-cli/main.go` server mode.
const DEFAULT_LISTEN_PORT: u16 = 56000;

/// Loopback UDP port the backend `wg-quick@wgturn-be` daemon listens
/// on. `wgturn-cli serve` forwards inner WG payload here via
/// `#@wgt:Backend = udp:127.0.0.1:<this>`.
///
/// Chosen distinct from AmneziaWG's typical 51820 so a single VPS
/// hosting BOTH kernels doesn't collide. Loopback-only — never
/// exposed publicly.
const DEFAULT_BACKEND_PORT: u16 = 51821;

/// Per-user `/32` octet base: each granted user gets `10.7.0.<2 +
/// index>/24`. Mirrors the share-link encoder in
/// `crates/protocols/src/wgturn.rs` so the [Peer] AllowedIPs we
/// write into wgturn-be.conf match the client's tunnel address from
/// its `wgturn://` URL. Octet >254 (i.e. 254-peer cap) fails the
/// render with a clear error.
const BACKEND_BASE_OCTET: u16 = 2;

/// CIDR + interface name for the backend WG. `/24` matches the
/// share-link encoder. Interface name is what `wg-quick@<NAME>`
/// systemd template resolves to.
const BACKEND_INTERFACE_NAME: &str = "wgturn-be";
const BACKEND_SERVER_CIDR: &str = "10.7.0.1/24";

/// Pinned upstream commit hash for `wgturn-core`. Required to prevent
/// any future compromise of github.com/PavelLizunov/wgturn-core from
/// pushing arbitrary code to every VPN node on the next deploy
/// (review-agent finding 2 — critical, supply-chain).
///
/// This is the SHA of the `v0.1.0` tag (May 2026). Bumping requires
/// **deliberate operator action**: edit this constant, re-deploy, and
/// `ensure_installed` will fast-forward each node to the new pin.
/// Tracking `main` was the prior behaviour and is explicitly NOT
/// safe — sing_box / amnezia_wg get their hardening from signed apt
/// packages; this kernel can't rely on that.
const WGTURN_CORE_PINNED_SHA: &str = "af0f209f99f8381356fbae82d9b0f64d4af4bdcf";

/// Multi-file bundle delimiter. `render_config` emits text in this
/// format; `apply_config` parses it. Format:
///
/// ```text
/// ====FILE: <absolute path>====
/// <file bytes>
/// ====FILE: <another absolute path>====
/// <file bytes>
/// ```
///
/// Each path line MUST start at column 0 with `====FILE: ` and end
/// `====`. File body is everything between two such markers (or
/// between the last marker and end-of-buffer). We do NOT escape `==`
/// runs in file bodies because wg-quick INI files don't legally
/// contain them (they're either `Key = Value` or `#` comments).
const BUNDLE_DELIMITER: &str = "====FILE: ";
const BUNDLE_DELIMITER_END: &str = "====";

/// Compute the per-user backend host octet — same arithmetic as
/// `crates/protocols/src/wgturn.rs::host_octet_for` so the server's
/// [Peer] AllowedIPs match the client's tunnel address from its
/// share-link.
fn backend_octet_for(idx: usize, user_id: &str) -> Result<u16> {
    let octet = BACKEND_BASE_OCTET.saturating_add(u16::try_from(idx).unwrap_or(u16::MAX));
    if octet > 254 {
        return Err(CoreError::Render(format!(
            "wgturn /24 has only 253 peer slots; user '{user_id}' index {idx} would overflow"
        )));
    }
    Ok(octet)
}

#[derive(Debug, Default)]
pub struct WgTurn;

impl WgTurn {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Kernel for WgTurn {
    fn id(&self) -> KernelId {
        KernelId("wgturn".to_string())
    }

    fn supported_protocols(&self) -> Vec<ProtocolId> {
        // The wire format is «WG-inside-TURN»; there's exactly one
        // protocol shape this kernel hosts. Plain WireGuard belongs
        // to AmneziaWg / a future WireGuardKernel.
        vec![ProtocolId("wgturn".to_string())]
    }

    async fn ensure_installed(&self, ssh: &dyn SshTransport) -> Result<()> {
        // ensure_installed sets up THREE things on the server:
        //   1. wgturn-cli binary (build from pinned wgturn-core source)
        //   2. wireguard-tools (apt — for the backend wg-quick daemon)
        //   3. systemd unit for `wgturn.service` (the DTLS relay)
        //
        // The backend `wg-quick@wgturn-be.service` is enabled by
        // apply_config, not here — that's because the .conf file the
        // template references doesn't exist until render_config has
        // run. ensure_installed is meant to be «config-independent
        // setup»; apply_config is «config-dependent setup + reload».
        //
        // Supply-chain pin: `git checkout WGTURN_CORE_PINNED_SHA` +
        // post-checkout HEAD verification (rejects a hijacked git
        // client / proxy that substitutes another SHA).
        //
        // Idempotency:
        //   * The apt + git + go-build block is GUARDED by an
        //     installed-SHA marker file; re-deploy with same pin is
        //     a no-op.
        //   * `useradd` is wrapped in `id -u wgturn` so it's
        //     idempotent for free.
        //   * Systemd unit is rewritten unconditionally — cheap, lets
        //     us push hardening updates without operator action.
        let pinned_sha = WGTURN_CORE_PINNED_SHA;
        let script = format!(
            r#"
            set -eu

            PINNED_SHA="{pinned_sha}"
            REPO_DIR=/opt/wgturn-core
            BINARY=/usr/local/bin/wgturn-cli

            # ── 1. apt prerequisites (toolchain + wg-tools).
            #    Always run apt-get install -y (idempotent, fast on
            #    already-installed packages). `wireguard-tools` is for
            #    the backend `wg-quick@wgturn-be` daemon.
            apt-get update -qq
            apt-get install -y wireguard-tools

            # ── 2. wgturn-cli build (skip if binary already at the
            #    pinned SHA).
            INSTALLED_SHA_FILE=/etc/wgturn/.installed-sha
            need_rebuild=1
            if [ -x "$BINARY" ] && [ -f "$INSTALLED_SHA_FILE" ] \
                && [ "$(cat "$INSTALLED_SHA_FILE" 2>/dev/null)" = "$PINNED_SHA" ]; then
                need_rebuild=0
            fi

            if [ "$need_rebuild" = "1" ]; then
                apt-get install -y git ca-certificates curl

                # Install Go 1.24+ via official tarball. Bookworm's
                # apt-package `golang-go` ships 1.19 which is too old
                # for wgturn-core's deps (crypto/ecdh ≥1.20,
                # crypto/hkdf ≥1.24, crypto/mlkem ≥1.24, math/rand/v2
                # ≥1.22, slices ≥1.21). Live deploy 2026-05-19 caught
                # this. Tarball install is idempotent — re-run with the
                # same pinned version is a no-op via the version probe.
                GO_PINNED_VERSION="go1.24.4"
                GO_TARBALL="${{GO_PINNED_VERSION}}.linux-amd64.tar.gz"
                if ! /usr/local/go/bin/go version 2>/dev/null | grep -q "${{GO_PINNED_VERSION}}"; then
                    cd /tmp
                    curl -fsSL -o "$GO_TARBALL" "https://go.dev/dl/$GO_TARBALL"
                    rm -rf /usr/local/go
                    tar -C /usr/local -xzf "$GO_TARBALL"
                    rm -f "$GO_TARBALL"
                fi
                export PATH=/usr/local/go/bin:$PATH

                if [ -d "$REPO_DIR/.git" ]; then
                    git -C "$REPO_DIR" fetch --quiet origin
                    git -C "$REPO_DIR" checkout --quiet "$PINNED_SHA"
                else
                    git clone --quiet \
                        https://github.com/PavelLizunov/wgturn-core.git \
                        "$REPO_DIR"
                    git -C "$REPO_DIR" checkout --quiet "$PINNED_SHA"
                fi

                ACTUAL_SHA=$(git -C "$REPO_DIR" rev-parse HEAD)
                if [ "$ACTUAL_SHA" != "$PINNED_SHA" ]; then
                    echo "wgturn-core HEAD is $ACTUAL_SHA, expected $PINNED_SHA — aborting" >&2
                    exit 1
                fi

                cd "$REPO_DIR"
                GOFLAGS=-trimpath GOCACHE=/tmp/wgturn-gocache \
                    /usr/local/go/bin/go build -o "$BINARY" ./cmd/wgturn-cli

                install -d -m 0755 /etc/wgturn
                echo "$PINNED_SHA" > "$INSTALLED_SHA_FILE"
                chmod 0644 "$INSTALLED_SHA_FILE"
            fi

            # ── 3. system user. wgturn-cli serve runs as `wgturn`
            #    (no privileges needed: high UDP port + no kernel
            #    interface).
            id -u wgturn >/dev/null 2>&1 \
                || useradd -r -s /usr/sbin/nologin -d /var/lib/wgturn -m wgturn

            install -d -m 0755 /etc/wgturn
            install -d -m 0755 -o wgturn -g wgturn /var/lib/wgturn

            # ── 4. systemd unit for wgturn-cli serve (the DTLS relay).
            #    Hardened mirroring vpnctld's 2026-05-18 audit pattern
            #    minus MemoryDenyWriteExecute (Go runtime needs W+X
            #    pages on some arches — directive crashes the binary).
            cat > /etc/systemd/system/wgturn.service <<'UNIT'
[Unit]
Description=wgturn-core relay (VK-TURN-relayed WireGuard)
Documentation=https://github.com/PavelLizunov/wgturn-core
After=network-online.target wg-quick@{iface}.service
Wants=network-online.target

[Service]
Type=simple
User=wgturn
Group=wgturn
WorkingDirectory=/var/lib/wgturn
ExecStart=/usr/local/bin/wgturn-cli serve /etc/wgturn/server.conf
Restart=on-failure
RestartSec=5

NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/wgturn
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectClock=true
ProtectControlGroups=true
ProtectHostname=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @obsolete @raw-io @reboot @swap @debug @cpu-emulation @mount
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT
            systemctl daemon-reload

            # Final assertion — fail loud if any step above silently
            # produced an empty binary or PATH inversion.
            command -v wgturn-cli
            test -x /usr/local/bin/wgturn-cli
            command -v wg-quick
        "#,
            iface = BACKEND_INTERFACE_NAME,
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
        // Defense-in-depth: Registry::validate_server should reject
        // a `kernels=[wgturn]` + `enabled_protocols=[...not-wgturn]`
        // combination earlier, but the kernel still verifies its
        // own contract.
        let _wgturn_proto = protocols
            .iter()
            .find(|p| p.id() == ProtocolId("wgturn".to_string()))
            .ok_or_else(|| {
                CoreError::Render(
                    "wgturn kernel requires the wgturn protocol in `protocols`".into(),
                )
            })?;

        // Per-server secret minted at add-server-wizard time:
        //   * `wgturn:server_wg_private` — Curve25519 private key for
        //     the BACKEND wg-quick@wgturn-be daemon. Public half is
        //     stored separately as `wgturn:server_wg_public` and is
        //     what the per-user share-link's `sp` field carries.
        //
        // VK link is INTENTIONALLY ABSENT (Pavel 2026-05-19 + upstream
        // `pkg/wgshare/doc.go` confirm: client-side, supplied at
        // connect time).
        let server_wg_private = ctx.secrets.get("wgturn:server_wg_private").ok_or_else(|| {
            CoreError::Render(
                "wgturn kernel: missing secret `wgturn:server_wg_private` — \
                 mint via the add-server wizard, or set via /admin/servers/<id>"
                    .into(),
            )
        })?;

        // Validate listen_port as u16 at render time so a typo
        // surfaces as a clear CoreError::Render rather than an 8-
        // second is-active poll timeout (review-agent finding 5 —
        // important).
        let listen_port: u16 = match ctx.secrets.get("wgturn:listen_port") {
            None => DEFAULT_LISTEN_PORT,
            Some(s) => s.parse().map_err(|_| {
                CoreError::Render(format!(
                    "wgturn kernel: invalid `wgturn:listen_port` value {s:?} — \
                     must be an integer in 0..=65535"
                ))
            })?,
        };

        // ── 1. Render /etc/wgturn/server.conf — the wgturn-cli serve
        //    config (wg-quick INI + `#@wgt:` metadata).
        //    Required keys per upstream `pkg/wgconf/parse.go`:
        //      #@wgt:EnableServer = true
        //      #@wgt:Listen = 0.0.0.0:<port>
        //      #@wgt:Backend = udp:127.0.0.1:<backend port>
        //    Anything else in this file is silently ignored.
        let mut server_conf = String::with_capacity(512);
        server_conf.push_str("# Rendered by vpnctl. Do not hand-edit — your changes\n");
        server_conf.push_str("# will be overwritten on next `vpnctl deploy`.\n");
        server_conf.push_str("#\n");
        server_conf.push_str("# This is `wgturn-cli serve` config: a thin DTLS relay that\n");
        server_conf.push_str("# forwards inner WG payload to the backend `wg-quick@");
        server_conf.push_str(BACKEND_INTERFACE_NAME);
        server_conf.push_str("`\n# daemon on loopback (rendered separately below).\n");
        server_conf.push_str("# Note: VK Calls invite link is supplied by the END USER at\n");
        server_conf.push_str("# connect time (`wgturn-cli connect-url ... --vk-link <url>`),\n");
        server_conf.push_str("# NOT embedded here.\n\n");
        server_conf.push_str("#@wgt:EnableServer = true\n");
        server_conf.push_str(&format!("#@wgt:Listen = 0.0.0.0:{listen_port}\n"));
        server_conf.push_str(&format!(
            "#@wgt:Backend = udp:127.0.0.1:{DEFAULT_BACKEND_PORT}\n"
        ));

        // ── 2. Render /etc/wireguard/wgturn-be.conf — the BACKEND
        //    wg-quick config. Real WireGuard daemon listening on
        //    127.0.0.1:51821, with [Interface] holding our keypair
        //    + [Peer] section per granted user.
        //
        //    The user's wireguard_pubkey is the `[Peer] PublicKey =`
        //    that authenticates them. AllowedIPs is the /32 derived
        //    from their index in the granted-users list (same arith-
        //    metic as `crates/protocols/src/wgturn.rs::host_octet_for`).
        //
        //    Users with no wireguard_pubkey are silently skipped (same
        //    convention as wireguard.rs::server_inbound). Malformed
        //    pubkey is a hard error.
        let mut be_conf = String::with_capacity(1024);
        be_conf.push_str("# Rendered by vpnctl. Do not hand-edit — your changes\n");
        be_conf.push_str("# will be overwritten on next `vpnctl deploy`.\n");
        be_conf.push_str("#\n");
        be_conf.push_str("# Loopback-only WireGuard daemon. `wgturn-cli serve` forwards\n");
        be_conf.push_str("# DTLS-decapsulated payload here via `udp:127.0.0.1:");
        be_conf.push_str(&DEFAULT_BACKEND_PORT.to_string());
        be_conf.push_str("`.\n");
        be_conf.push_str("# Never bind to a public interface.\n\n");
        be_conf.push_str("[Interface]\n");
        be_conf.push_str(&format!("PrivateKey = {server_wg_private}\n"));
        be_conf.push_str(&format!("Address = {BACKEND_SERVER_CIDR}\n"));
        be_conf.push_str(&format!("ListenPort = {DEFAULT_BACKEND_PORT}\n"));
        be_conf.push_str("# Bind to loopback only via wg-quick PreUp/PostUp:\n");
        be_conf.push_str("# the [Interface] doesn't have a native «bind only to lo» knob,\n");
        be_conf.push_str("# but the port is firewalled to 127.0.0.1 by iptables below.\n");
        be_conf.push_str("PreUp = iptables -I INPUT 1 -p udp --dport ");
        be_conf.push_str(&DEFAULT_BACKEND_PORT.to_string());
        be_conf.push_str(" ! -i lo -j DROP\n");
        be_conf.push_str("PostDown = iptables -D INPUT -p udp --dport ");
        be_conf.push_str(&DEFAULT_BACKEND_PORT.to_string());
        be_conf.push_str(" ! -i lo -j DROP || true\n");
        be_conf.push('\n');

        let mut peer_count = 0;
        for (idx, u) in users.iter().enumerate() {
            let Some(pubkey) = u.wireguard_pubkey.as_deref() else {
                continue;
            };
            // Shape gate — matches wireguard.rs::is_valid_wg_pubkey.
            if pubkey.len() != 44 || !pubkey.ends_with('=') {
                return Err(CoreError::Render(format!(
                    "user '{}' has malformed wireguard pubkey (must be 44 base64 chars ending '='): {pubkey:?}",
                    u.id.0
                )));
            }
            let octet = backend_octet_for(idx, &u.id.0)?;
            be_conf.push_str(&format!("# Peer: {}\n", u.id.0));
            be_conf.push_str("[Peer]\n");
            be_conf.push_str(&format!("PublicKey = {pubkey}\n"));
            be_conf.push_str(&format!("AllowedIPs = 10.7.0.{octet}/32\n"));
            be_conf.push('\n');
            peer_count += 1;
        }
        let _ = peer_count; // informational only

        // ── 3. Assemble the multi-file bundle.
        let mut bundle = String::with_capacity(server_conf.len() + be_conf.len() + 256);
        bundle.push_str(BUNDLE_DELIMITER);
        bundle.push_str("/etc/wgturn/server.conf");
        bundle.push_str(BUNDLE_DELIMITER_END);
        bundle.push('\n');
        bundle.push_str(&server_conf);
        if !server_conf.ends_with('\n') {
            bundle.push('\n');
        }
        bundle.push_str(BUNDLE_DELIMITER);
        bundle.push_str("/etc/wireguard/");
        bundle.push_str(BACKEND_INTERFACE_NAME);
        bundle.push_str(".conf");
        bundle.push_str(BUNDLE_DELIMITER_END);
        bundle.push('\n');
        bundle.push_str(&be_conf);
        if !be_conf.ends_with('\n') {
            bundle.push('\n');
        }
        Ok(bundle.into_bytes())
    }

    async fn apply_config(&self, ssh: &dyn SshTransport, config: &[u8]) -> Result<()> {
        // Upload the bundle as a single staging file; the unpacker
        // script below parses + writes each member file then restarts
        // both systemd units. Atomic-rename + 8s is-active poll +
        // journalctl-on-fail pattern mirrors sing_box / amnezia_wg.
        ssh.upload("/etc/wgturn/.deploy-bundle.new", config).await?;
        let iface = BACKEND_INTERFACE_NAME;
        let cmd = format!(
            r#"
            set -eu

            BUNDLE=/etc/wgturn/.deploy-bundle.new
            test -f "$BUNDLE"

            # Unpack the bundle. Format documented in
            # `crates/kernels/src/wgturn.rs::BUNDLE_DELIMITER`. Parser
            # is a small awk that splits on the marker line and writes
            # each member into its declared path (atomic via mv).
            awk '
                BEGIN {{ path = ""; outfile = ""; }}
                /^====FILE: .*====$/ {{
                    # Flush previous file if any.
                    if (outfile != "") {{ close(outfile); }}
                    # Extract path between "====FILE: " and "===="
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

            # Move each ".new" sibling into place atomically. Files we
            # know about: /etc/wgturn/server.conf and
            # /etc/wireguard/{iface}.conf.
            install -d -m 0755 /etc/wireguard
            install -d -m 0755 /etc/wgturn
            mv /etc/wgturn/server.conf.new /etc/wgturn/server.conf
            chown wgturn:wgturn /etc/wgturn/server.conf
            chmod 0640 /etc/wgturn/server.conf
            mv /etc/wireguard/{iface}.conf.new /etc/wireguard/{iface}.conf
            chown root:root /etc/wireguard/{iface}.conf
            chmod 0600 /etc/wireguard/{iface}.conf
            rm -f "$BUNDLE"

            # Enable + restart the backend WG first (wgturn relay
            # depends on it being reachable on 127.0.0.1:51821).
            systemctl enable wg-quick@{iface} >/dev/null 2>&1 || true
            systemctl restart wg-quick@{iface}

            # Then the relay itself.
            systemctl enable wgturn >/dev/null 2>&1 || true
            systemctl restart wgturn

            # 8-second wait for BOTH services to settle.
            for s in wg-quick@{iface} wgturn; do
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
            iface = iface,
        );
        ssh.exec(&cmd).await?;
        Ok(())
    }

    async fn restart(&self, ssh: &dyn SshTransport) -> Result<()> {
        // Restart BOTH services — relay depends on backend.
        ssh.exec(&format!(
            "systemctl restart wg-quick@{iface} wgturn",
            iface = BACKEND_INTERFACE_NAME,
        ))
        .await?;
        Ok(())
    }

    async fn status(&self, ssh: &dyn SshTransport) -> Result<KernelStatus> {
        // Active iff BOTH services are active. wgturn-cli serve will
        // start even if the backend is down (it can't tell from a
        // UDP socket whether anyone's listening), so the combined
        // check is the honest one.
        let relay = ssh
            .exec("systemctl is-active wgturn")
            .await?
            .trim()
            .eq("active");
        let backend = ssh
            .exec(&format!(
                "systemctl is-active wg-quick@{iface}",
                iface = BACKEND_INTERFACE_NAME,
            ))
            .await?
            .trim()
            .eq("active");
        let active = relay && backend;
        let version = ssh
            .exec("wgturn-cli version 2>/dev/null | head -1")
            .await
            .ok()
            .map(|s| s.trim().to_string());
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

    fn dummy_server() -> Server {
        Server {
            id: ServerId("wgturn-node".into()),
            address: "203.0.113.42".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("wgturn".into())],
            enabled_protocols: vec![ProtocolId("wgturn".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    fn complete_secrets() -> HashMap<String, String> {
        let mut s = HashMap::new();
        s.insert(
            "wgturn:server_wg_private".into(),
            "AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNNn=".into(),
        );
        s
    }

    fn dummy_user_with_pubkey(name: &str) -> User {
        User {
            id: UserId(name.into()),
            uuid: format!("{name}-uuid"),
            tuic_password: None,
            wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
            wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        }
    }

    #[test]
    fn id_returns_wgturn() {
        assert_eq!(WgTurn::new().id(), KernelId("wgturn".into()));
    }

    #[test]
    fn supported_protocols_is_singleton_wgturn() {
        let protos = WgTurn::new().supported_protocols();
        assert_eq!(protos.len(), 1);
        assert_eq!(protos[0], ProtocolId("wgturn".into()));
    }

    #[test]
    fn render_config_requires_server_wg_private_secret() {
        let mut secrets = complete_secrets();
        secrets.remove("wgturn:server_wg_private");
        let server = dummy_server();
        let ctx = RenderCtx::new(&server, &secrets);
        let protos: Vec<&dyn Protocol> = vec![&vpnctl_protocols::WgTurn];
        let err = WgTurn::new().render_config(&ctx, &[], &protos).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("wgturn:server_wg_private"));
    }

    #[test]
    fn render_config_rejects_missing_wgturn_protocol() {
        let server = dummy_server();
        let secrets = complete_secrets();
        let ctx = RenderCtx::new(&server, &secrets);
        let protos: Vec<&dyn Protocol> = vec![];
        let err = WgTurn::new().render_config(&ctx, &[], &protos).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("wgturn protocol"));
    }

    #[test]
    fn render_config_emits_multi_file_bundle() {
        // Pavel 2026-05-19 + upstream `pkg/wgconf/parse.go`: wgturn-cli
        // serve parses wg-quick INI with `#@wgt:` metadata, NOT TOML.
        // The kernel emits a TWO-file bundle: server.conf for the
        // relay + backend.conf for the loopback wg-quick daemon.
        let server = dummy_server();
        let secrets = complete_secrets();
        let ctx = RenderCtx::new(&server, &secrets);
        let protos: Vec<&dyn Protocol> = vec![&vpnctl_protocols::WgTurn];
        let bytes = WgTurn::new().render_config(&ctx, &[], &protos).unwrap();
        let body = String::from_utf8(bytes).unwrap();

        // Bundle structure — both file markers present.
        assert!(
            body.contains("====FILE: /etc/wgturn/server.conf===="),
            "server.conf marker missing: {body}"
        );
        assert!(
            body.contains("====FILE: /etc/wireguard/wgturn-be.conf===="),
            "backend conf marker missing: {body}"
        );

        // server.conf required keys (per upstream wgconf parser).
        assert!(
            body.contains("#@wgt:EnableServer = true"),
            "EnableServer key missing: {body}"
        );
        assert!(
            body.contains("#@wgt:Listen = 0.0.0.0:56000"),
            "Listen key missing or wrong port: {body}"
        );
        assert!(
            body.contains("#@wgt:Backend = udp:127.0.0.1:51821"),
            "Backend key missing or wrong loopback port: {body}"
        );

        // backend.conf required structure.
        assert!(
            body.contains("[Interface]"),
            "backend [Interface] section missing: {body}"
        );
        assert!(
            body.contains("PrivateKey = AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNNn="),
            "backend private key not embedded: {body}"
        );
        assert!(
            body.contains("ListenPort = 51821"),
            "backend ListenPort wrong: {body}"
        );
        assert!(
            body.contains("Address = 10.7.0.1/24"),
            "backend Address wrong: {body}"
        );
    }

    #[test]
    fn render_config_emits_peer_per_user_with_pubkey() {
        let server = dummy_server();
        let secrets = complete_secrets();
        let ctx = RenderCtx::new(&server, &secrets);
        let protos: Vec<&dyn Protocol> = vec![&vpnctl_protocols::WgTurn];
        let users = vec![
            dummy_user_with_pubkey("alice"),
            dummy_user_with_pubkey("bob"),
        ];
        let bytes = WgTurn::new().render_config(&ctx, &users, &protos).unwrap();
        let body = String::from_utf8(bytes).unwrap();

        // Two [Peer] blocks, each with the same pubkey + a distinct
        // /32 AllowedIPs (octet 2 for alice, octet 3 for bob).
        let peer_count = body.matches("[Peer]").count();
        assert_eq!(peer_count, 2, "expected 2 [Peer] blocks: {body}");
        assert!(body.contains("# Peer: alice"), "alice peer comment missing");
        assert!(body.contains("# Peer: bob"), "bob peer comment missing");
        assert!(
            body.contains("AllowedIPs = 10.7.0.2/32"),
            "alice /32 missing: {body}"
        );
        assert!(
            body.contains("AllowedIPs = 10.7.0.3/32"),
            "bob /32 missing: {body}"
        );
    }

    #[test]
    fn render_config_skips_users_without_pubkey() {
        let server = dummy_server();
        let secrets = complete_secrets();
        let ctx = RenderCtx::new(&server, &secrets);
        let protos: Vec<&dyn Protocol> = vec![&vpnctl_protocols::WgTurn];
        let mut no_key = dummy_user_with_pubkey("charlie");
        no_key.wireguard_pubkey = None;
        let users = vec![dummy_user_with_pubkey("alice"), no_key];
        let bytes = WgTurn::new().render_config(&ctx, &users, &protos).unwrap();
        let body = String::from_utf8(bytes).unwrap();
        let peer_count = body.matches("[Peer]").count();
        assert_eq!(peer_count, 1, "only alice should have a peer block");
        assert!(!body.contains("# Peer: charlie"));
    }

    #[test]
    fn render_config_rejects_malformed_pubkey() {
        let server = dummy_server();
        let secrets = complete_secrets();
        let ctx = RenderCtx::new(&server, &secrets);
        let protos: Vec<&dyn Protocol> = vec![&vpnctl_protocols::WgTurn];
        let mut bad = dummy_user_with_pubkey("eve");
        bad.wireguard_pubkey = Some("not-a-valid-wg-key".into());
        let err = WgTurn::new()
            .render_config(&ctx, &[bad], &protos)
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("malformed wireguard pubkey"));
    }

    #[test]
    fn render_config_honours_listen_port_override() {
        let mut secrets = complete_secrets();
        secrets.insert("wgturn:listen_port".into(), "56777".into());
        let server = dummy_server();
        let ctx = RenderCtx::new(&server, &secrets);
        let protos: Vec<&dyn Protocol> = vec![&vpnctl_protocols::WgTurn];
        let bytes = WgTurn::new().render_config(&ctx, &[], &protos).unwrap();
        let body = String::from_utf8(bytes).unwrap();
        assert!(
            body.contains("#@wgt:Listen = 0.0.0.0:56777"),
            "operator-set listen port wins: {body}"
        );
    }

    #[test]
    fn render_config_rejects_non_numeric_listen_port() {
        let mut secrets = complete_secrets();
        secrets.insert("wgturn:listen_port".into(), "not-a-number".into());
        let server = dummy_server();
        let ctx = RenderCtx::new(&server, &secrets);
        let protos: Vec<&dyn Protocol> = vec![&vpnctl_protocols::WgTurn];
        let err = WgTurn::new().render_config(&ctx, &[], &protos).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("wgturn:listen_port"));
        assert!(msg.contains("not-a-number"));
    }

    #[test]
    fn render_config_does_not_emit_vk_link() {
        // VK link is client-side per upstream `pkg/wgshare/doc.go`;
        // even if a stale secret lingers in the table, the renderer
        // must not echo it.
        let server = dummy_server();
        let mut secrets = complete_secrets();
        secrets.insert(
            "wgturn:vk_link".into(),
            "https://vk.com/call/join/stale-row".into(),
        );
        let ctx = RenderCtx::new(&server, &secrets);
        let protos: Vec<&dyn Protocol> = vec![&vpnctl_protocols::WgTurn];
        let bytes = WgTurn::new().render_config(&ctx, &[], &protos).unwrap();
        let body = String::from_utf8(bytes).unwrap();
        assert!(!body.contains("vk_link"), "vk_link leaked: {body}");
        assert!(!body.contains("stale-row"), "stale value leaked: {body}");
    }

    #[test]
    fn ensure_installed_script_pins_to_known_sha() {
        assert_eq!(
            WGTURN_CORE_PINNED_SHA.len(),
            40,
            "pin must be a full 40-char SHA"
        );
        assert!(
            WGTURN_CORE_PINNED_SHA
                .chars()
                .all(|c| c.is_ascii_hexdigit()),
            "pin must be all hex: {WGTURN_CORE_PINNED_SHA}"
        );
    }
}
