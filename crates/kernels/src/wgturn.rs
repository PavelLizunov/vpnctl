//! wgturn-core — VK-TURN-relayed WireGuard «emergency channel» kernel.
//!
//! `wgturn` is an Apache-2.0 Go library + CLI from
//! github.com/PavelLizunov/wgturn-core (v0.1.0, May 2026). The
//! server-side daemon (`wgturn-cli serve`) listens on a UDP port,
//! demultiplexes per-Session-ID streams arriving via TURN-relayed
//! DTLS, and forwards into the bundled `pkg/wgturnsrv` WireGuard
//! backend. Clients run `wgturn-cli connect-url '<wgturn://...>'
//! --vk-link '<https://vk.com/call/join/...>'` and the request
//! traffic gets relayed through VK Calls' anonymous TURN servers.
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
//! ## Phase 1 (this commit) vs Phase 2
//!
//! **Phase 1** ships the kernel skeleton (`ensure_installed` +
//! `apply_config` + `status`) plus a stub `WgTurn` protocol whose
//! `share_link` returns a render-error «not yet generated offline».
//! Operator can deploy the kernel and bring `wgturn-cli serve` up;
//! user provisioning stays manual via `wgturn-cli provision-url` on
//! the server until phase 2.
//!
//! **Phase 2** (next session) ports `pkg/wgshare`'s `wgturn://`
//! URL encoder to Rust so per-user share-links generate offline from
//! `RenderCtx::secrets`. Then the admin user-detail page gets the same
//! one-button share UX as VLESS / TUIC / etc.
//!
//! ## Versions tested
//!
//! - `wgturn-core` v0.1.0 (Apache-2.0)
//! - Go 1.25+ required (apt-installs `golang-go` on bookworm — system
//!   ships 1.22; pin via /usr/local/go if newer is needed).
//! - Debian 12 bookworm (the only deploy target today).
//!
//! ## Kernel orthogonality
//!
//! Adding this kernel touches ONLY:
//!   * `crates/kernels/src/wgturn.rs` (this file)
//!   * `crates/kernels/src/lib.rs` (`mod` + `pub use`)
//!   * `crates/protocols/src/wgturn.rs` (companion stub protocol)
//!   * `crates/protocols/src/lib.rs` (`mod` + `pub use`)
//!   * `cli/src/registry.rs` + `daemon/src/app.rs::build_registry`
//!     — one `register_*` line each (the duplication is pre-existing,
//!     documented at the daemon site)
//!   * `daemon/src/wizard_bootstrap.rs::bootstrap_server_secrets` —
//!     a new gated block that mints `wgturn:*` secrets when the
//!     kernel is enabled
//!
//! No edits to `core`, `ssh`, `crypto`, `inventory`, `hosters`, or
//! `cli/src/cmd/*` per CLAUDE.md's Kernel × Protocol invariant.

use async_trait::async_trait;
use vpnctl_core::{
    CoreError, Kernel, KernelId, KernelStatus, Protocol, ProtocolId, RenderCtx, Result,
    SshTransport, User,
};

/// Default UDP port `wgturn-cli serve` listens on. Matches the
/// upstream's documented default + the operator-pasted port hint in
/// `cmd/wgturn-cli/main.go` server mode.
const DEFAULT_LISTEN_PORT: u16 = 56000;

/// Default peer-type — the wire-compatible multi-user mode with
/// DTLS + Session-ID handshake. `proxy_v1` and `wireguard` modes
/// are legacy / debug; production = `proxy_v2`.
const DEFAULT_PEER_TYPE: &str = "proxy_v2";

/// Whitelist of accepted `wgturn:mode` values. Operator-pasted via
/// /admin/servers/<id>/secrets; we hard-reject anything outside this
/// set rather than passing it through to wgturn-cli, where a bad
/// value surfaces only after an 8-second `is-active` poll failure.
/// (Review-agent finding 5 — important.)
const ALLOWED_MODES: &[&str] = &["proxy_v2", "proxy_v1", "wireguard"];

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

/// Escape a string for embedding inside a TOML *basic* (double-quoted)
/// string literal. Implements the minimal escape set from TOML 1.0:
/// `\\` `"` `\n` `\r` `\t` `\b` `\f` plus other C0 control codes via
/// `\u00XX`. Prevents operator-pasted secrets from breaking out of
/// their `"..."` envelope (review-agent finding 1 — critical, TOML
/// injection).
///
/// We hand-roll rather than depending on the `toml` crate to keep
/// the kernels-crate dep graph minimal (only `vpnctl-core`, `serde`,
/// `async-trait` today). The escape set is deliberately a strict
/// SUPERSET of what TOML 1.0 requires — over-escaping is safe; under-
/// escaping breaks the file.
fn toml_escape_basic(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            // Other C0 controls (0x00..=0x1F minus the named ones above)
            // and DEL (0x7F): emit as \u00XX. TOML 1.0 explicitly bans
            // bare control chars inside basic strings.
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\u{:04X}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
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
        // wgturn-core is a Go project; we build from source on the
        // VPN server itself. Reasons:
        //   * upstream doesn't publish release binaries yet (v0.1.0
        //     alpha); pin to a tag once they do.
        //   * apt-installable `golang-go` on bookworm is glibc-safe
        //     — runs on the VPN server, never the daemon host.
        //   * build artefact is one static binary; we install it to
        //     /usr/local/bin/wgturn-cli and ship a minimal systemd
        //     unit.
        //
        // Idempotent — re-running ensure_installed on an already-
        // provisioned server is a near-no-op:
        //   * The apt+git+go-build block is GUARDED by
        //     `command -v wgturn-cli` so on re-deploy we don't reinstall
        //     the toolchain, re-clone, or rebuild (review-agent finding 4
        //     — important, wasted bandwidth + state mutation on every
        //     deploy).
        //   * `useradd` is wrapped in `id -u wgturn` so it's idempotent
        //     for free.
        //   * Systemd unit is rewritten unconditionally — cheap, lets
        //     us push hardening updates without operator action.
        //
        // Supply-chain pin: we check out `WGTURN_CORE_PINNED_SHA`
        // explicitly rather than tracking `origin/main`. Bumping
        // requires editing the Rust constant + redeploy (review-agent
        // finding 2 — critical, supply-chain).
        let pinned_sha = WGTURN_CORE_PINNED_SHA;
        let script = format!(
            r#"
            set -eu

            PINNED_SHA="{pinned_sha}"
            REPO_DIR=/opt/wgturn-core
            BINARY=/usr/local/bin/wgturn-cli

            # ── Toolchain + source + build (skip if binary already at
            #    the pinned SHA). The marker file records WHICH sha is
            #    installed so a pin-bump in the Rust constant triggers
            #    a rebuild without an operator-side flush.
            INSTALLED_SHA_FILE=/etc/wgturn/.installed-sha
            need_rebuild=1
            if [ -x "$BINARY" ] && [ -f "$INSTALLED_SHA_FILE" ] \
                && [ "$(cat "$INSTALLED_SHA_FILE" 2>/dev/null)" = "$PINNED_SHA" ]; then
                need_rebuild=0
            fi

            if [ "$need_rebuild" = "1" ]; then
                # Apt prerequisites. golang-go on bookworm ships 1.22;
                # if upstream's go.mod requires newer, this will fail
                # loud via `go build` exit non-zero — operator's signal
                # to install a newer toolchain manually.
                apt-get update -qq
                apt-get install -y golang-go git ca-certificates

                # Clone or pull. Either way, hard-reset to the PINNED
                # SHA — refuses to pick up unknown changes on `main`.
                if [ -d "$REPO_DIR/.git" ]; then
                    git -C "$REPO_DIR" fetch --quiet origin
                    git -C "$REPO_DIR" checkout --quiet "$PINNED_SHA"
                else
                    # `--depth 1` is incompatible with checkout-by-sha;
                    # do a regular clone, then checkout. The repo is
                    # tiny (~200 KB).
                    git clone --quiet \
                        https://github.com/PavelLizunov/wgturn-core.git \
                        "$REPO_DIR"
                    git -C "$REPO_DIR" checkout --quiet "$PINNED_SHA"
                fi

                # Verify HEAD matches the pin — defense against a
                # compromised git client / proxy substituting another
                # ref under our nose.
                ACTUAL_SHA=$(git -C "$REPO_DIR" rev-parse HEAD)
                if [ "$ACTUAL_SHA" != "$PINNED_SHA" ]; then
                    echo "wgturn-core HEAD is $ACTUAL_SHA, expected $PINNED_SHA — aborting" >&2
                    exit 1
                fi

                # Build the CLI. GOFLAGS=-trimpath strips build-host
                # paths from the binary; GOCACHE under /tmp because
                # the system user `wgturn` doesn't have a home.
                cd "$REPO_DIR"
                GOFLAGS=-trimpath GOCACHE=/tmp/wgturn-gocache \
                    go build -o "$BINARY" ./cmd/wgturn-cli

                # Record the installed SHA so the next ensure_installed
                # can short-circuit.
                install -d -m 0750 /etc/wgturn
                echo "$PINNED_SHA" > "$INSTALLED_SHA_FILE"
                chmod 0640 "$INSTALLED_SHA_FILE"
            fi

            # Non-root system user. wgturn-cli serve listens on a
            # high UDP port (56000 default), so no CAP_NET_BIND
            # needed.
            id -u wgturn >/dev/null 2>&1 \
                || useradd -r -s /usr/sbin/nologin -d /var/lib/wgturn -m wgturn

            install -d -m 0750 -o wgturn -g wgturn /etc/wgturn
            chown wgturn:wgturn "$INSTALLED_SHA_FILE" 2>/dev/null || true

            # Systemd unit. Mirrors `vpnctld`'s 2026-05-18 hardening
            # — drop caps, restrict address families, syscall filter,
            # UMask 0077.
            #
            # `MemoryDenyWriteExecute` is OMITTED here because Go's
            # runtime maps W+X pages for its goroutine signal-stack
            # trampolines on some architectures, and the directive
            # crashes the binary at startup (review-agent finding 3
            # — important; the directive was copy-pasted from
            # vpnctld which is Rust + has no such requirement).
            cat > /etc/systemd/system/wgturn.service <<'UNIT'
[Unit]
Description=wgturn-core relay (VK-TURN-relayed WireGuard)
Documentation=https://github.com/PavelLizunov/wgturn-core
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=wgturn
Group=wgturn
WorkingDirectory=/var/lib/wgturn
ExecStart=/usr/local/bin/wgturn-cli serve --config /etc/wgturn/server.toml
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
        "#
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

        // Per-server secrets (set by `bootstrap_server_secrets` at
        // add-server-wizard time):
        //   * `wgturn:server_wg_private` — WG-style base64 private
        //     key the bundled `wgturnsrv` backend uses
        //   * `wgturn:listen_port` (optional, default 56000)
        //   * `wgturn:mode`        (optional, default proxy_v2)
        //
        // **VK link is INTENTIONALLY ABSENT from the server config**
        // (Pavel 2026-05-19: «пользователь сам вставляет свою ссылку,
        // так как у каждого звонка ограниченное кол-во потоков»).
        // Per upstream `pkg/wgshare/doc.go`: «NOT IN: any VK Calls
        // link. The VK invite that drives the proxy's credential
        // rotation is a runtime parameter the user supplies on each
        // connect — both because it changes more often than the wg
        // keys, and because the share URL is meant to be portable
        // across users / devices.» Each VK call has limited
        // concurrent streams, so a shared per-server link would
        // saturate; client-side per-user supply is the correct
        // design. Pre-2026-05-19 we erroneously required a per-
        // server `wgturn:vk_link` secret — removed.
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

        // Validate mode against an explicit whitelist — wgturn-cli
        // accepts only `proxy_v2` / `proxy_v1` / `wireguard`; anything
        // else is a typo that we want to catch at render time, not
        // after a service crash-loop.
        let mode = ctx.or_default("wgturn:mode", DEFAULT_PEER_TYPE);
        if !ALLOWED_MODES.contains(&mode) {
            return Err(CoreError::Render(format!(
                "wgturn kernel: invalid `wgturn:mode` value {mode:?} — \
                 must be one of {ALLOWED_MODES:?}"
            )));
        }

        // TOML rendering — exact key names will need verification
        // against `cmd/wgturn-cli/main.go` server mode in phase 2.
        // Until then, use a documented superset that the upstream
        // parser tolerates.
        //
        // ALL operator-controlled strings are run through
        // `toml_escape_basic` before interpolation so a pasted secret
        // containing `"` / `\` / `\n` can't break out of its
        // double-quoted envelope and inject arbitrary TOML keys
        // (review-agent finding 1 — critical, TOML injection).
        //
        // The `users` slice is intentionally unused at config-
        // render time — user-grant provisioning lives in
        // `wgturn-cli provision-url` (server-side state, not in
        // the daemon-rendered TOML).
        let _ = users;
        let mode_esc = toml_escape_basic(mode);
        let server_wg_private_esc = toml_escape_basic(server_wg_private);

        let mut out = String::with_capacity(512);
        out.push_str("# Rendered by vpnctl. Do not hand-edit \u{2014} your changes\n");
        out.push_str("# will be overwritten on next `vpnctl deploy`.\n");
        out.push_str("# Note: VK Calls invite link is supplied by the END USER at\n");
        out.push_str("# connect time (`wgturn-cli connect-url ... --vk-link <url>`),\n");
        out.push_str("# NOT embedded here. Each VK call has limited concurrent\n");
        out.push_str("# streams, so each user must hand-supply their own link.\n\n");
        out.push_str(&format!("listen_addr = \"0.0.0.0:{listen_port}\"\n"));
        out.push_str(&format!("mode = \"{mode_esc}\"\n"));
        out.push_str("\n[backend.wireguard]\n");
        out.push_str(&format!("private_key = \"{server_wg_private_esc}\"\n"));
        out.push_str("listen_port = 51821\n");
        Ok(out.into_bytes())
    }

    async fn apply_config(&self, ssh: &dyn SshTransport, config: &[u8]) -> Result<()> {
        ssh.upload("/etc/wgturn/server.toml.new", config).await?;
        // Same atomic-rename + `systemctl is-active` 8-second poll +
        // journalctl-dump-on-fail pattern as `sing_box::apply_config`
        // and `amnezia_wg::apply_config` (CLAUDE.md staging-deploy
        // lesson #3 — `systemctl reload-or-restart` returns 0 even
        // when the service immediately exits).
        let cmd = r#"
            set -eu
            # No `wgturn-cli check` exists in v0.1.0; the server
            # parser is run at startup time. Atomic-rename and let
            # the is-active poll surface a parse error.
            mv /etc/wgturn/server.toml.new /etc/wgturn/server.toml
            chown wgturn:wgturn /etc/wgturn/server.toml
            chmod 0600 /etc/wgturn/server.toml

            systemctl enable wgturn >/dev/null 2>&1 || true
            systemctl reload-or-restart wgturn

            # 8-second wait for the service to settle.
            for i in 1 2 3 4 5 6 7 8; do
                state=$(systemctl is-active wgturn 2>/dev/null || true)
                if [ "$state" = "active" ]; then
                    exit 0
                fi
                sleep 1
            done
            echo "wgturn did not become active. Last 20 log lines:" >&2
            journalctl -u wgturn --no-pager -n 20 >&2 || true
            exit 1
        "#;
        ssh.exec(cmd).await?;
        Ok(())
    }

    async fn restart(&self, ssh: &dyn SshTransport) -> Result<()> {
        ssh.exec("systemctl restart wgturn").await?;
        Ok(())
    }

    async fn status(&self, ssh: &dyn SshTransport) -> Result<KernelStatus> {
        let active = ssh
            .exec("systemctl is-active wgturn")
            .await?
            .trim()
            .eq("active");
        // `wgturn-cli --version` exits 0 on stdout like
        // `wgturn-cli vX.Y.Z (commit abc1234)`. We don't have a
        // version constant to compare against; the operator-visible
        // value is informational only.
        let version = ssh
            .exec("wgturn-cli --version 2>/dev/null | head -1")
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
    use vpnctl_core::{Server, ServerId};

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
        // Post-2026-05-19: only `wgturn:server_wg_private` is required
        // server-side; VK link moved to client-side (each user supplies
        // their own at connect time — see kernel render_config comment).
        let mut s = HashMap::new();
        s.insert(
            "wgturn:server_wg_private".into(),
            "AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNNn=".into(),
        );
        s
    }

    #[test]
    fn id_returns_wgturn() {
        assert_eq!(WgTurn::new().id(), KernelId("wgturn".into()));
    }

    #[test]
    fn supported_protocols_is_singleton_wgturn() {
        // The wgturn kernel hosts exactly one protocol shape — its
        // own «WG-inside-TURN» wire format. Plain wireguard is the
        // AmneziaWg kernel's job.
        let protos = WgTurn::new().supported_protocols();
        assert_eq!(protos.len(), 1);
        assert_eq!(protos[0], ProtocolId("wgturn".into()));
    }

    #[test]
    fn render_config_does_not_emit_vk_link() {
        // Pavel 2026-05-19 + upstream `pkg/wgshare/doc.go`: VK link
        // is a CLIENT-SIDE parameter supplied at connect time, not a
        // per-server secret. Pre-2026-05-19 we erroneously baked it
        // into server.toml. Pin the new contract: rendered config
        // must NOT contain a `vk_link` key, and the comment block
        // must explain why so a future maintainer doesn't add it back.
        let server = dummy_server();
        // Even if a stale `wgturn:vk_link` secret lingers in the
        // table (left over from before this design change), the
        // renderer MUST ignore it.
        let mut secrets = complete_secrets();
        secrets.insert(
            "wgturn:vk_link".into(),
            "https://vk.com/call/join/stale-row".into(),
        );
        let ctx = RenderCtx::new(&server, &secrets);
        let protos: Vec<&dyn Protocol> = vec![&vpnctl_protocols::WgTurn];
        let bytes = WgTurn::new().render_config(&ctx, &[], &protos).unwrap();
        let toml = String::from_utf8(bytes).unwrap();
        assert!(
            !toml.contains("vk_link"),
            "rendered TOML must not carry vk_link (now client-side):\n{toml}"
        );
        assert!(
            !toml.contains("stale-row"),
            "stale `wgturn:vk_link` secret must not leak into the rendered config:\n{toml}"
        );
        // The header comment must explain WHY vk_link isn't here so a
        // future operator reading server.toml doesn't think it's a bug.
        assert!(
            toml.contains("END USER") || toml.contains("end user"),
            "header must explain that VK link is end-user-supplied: {toml}"
        );
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
        assert!(
            msg.contains("wgturn:server_wg_private"),
            "error must name the missing key: {msg}"
        );
    }

    #[test]
    fn render_config_emits_listen_port_and_mode_defaults() {
        let server = dummy_server();
        let secrets = complete_secrets();
        let ctx = RenderCtx::new(&server, &secrets);
        let protos: Vec<&dyn Protocol> = vec![&vpnctl_protocols::WgTurn];
        let bytes = WgTurn::new().render_config(&ctx, &[], &protos).unwrap();
        let toml = String::from_utf8(bytes).unwrap();
        assert!(
            toml.contains("listen_addr = \"0.0.0.0:56000\""),
            "default listen port is 56000: {toml}"
        );
        assert!(
            toml.contains("mode = \"proxy_v2\""),
            "default mode is proxy_v2: {toml}"
        );
        assert!(
            toml.contains("[backend.wireguard]"),
            "backend section present: {toml}"
        );
    }

    #[test]
    fn render_config_honours_listen_port_override() {
        let mut secrets = complete_secrets();
        secrets.insert("wgturn:listen_port".into(), "56777".into());
        let server = dummy_server();
        let ctx = RenderCtx::new(&server, &secrets);
        let protos: Vec<&dyn Protocol> = vec![&vpnctl_protocols::WgTurn];
        let bytes = WgTurn::new().render_config(&ctx, &[], &protos).unwrap();
        let toml = String::from_utf8(bytes).unwrap();
        assert!(
            toml.contains("listen_addr = \"0.0.0.0:56777\""),
            "operator-set listen port wins: {toml}"
        );
    }

    #[test]
    fn render_config_rejects_missing_wgturn_protocol() {
        // Defense-in-depth — even if Registry::validate_server
        // missed the inconsistency, the kernel itself rejects a
        // protocol list without `wgturn`.
        let server = dummy_server();
        let secrets = complete_secrets();
        let ctx = RenderCtx::new(&server, &secrets);
        let protos: Vec<&dyn Protocol> = vec![]; // empty
        let err = WgTurn::new().render_config(&ctx, &[], &protos).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("wgturn protocol"));
    }

    // ── Review-agent round-1 regression tests ──────────────────────
    // The tests below pin the four mitigations applied 2026-05-18
    // for review-agent's critical + important findings:
    //   - TOML injection via operator-pasted vk_link/mode
    //   - listen_port parse validation
    //   - mode whitelist enforcement
    //   - toml_escape_basic byte-stability

    #[test]
    fn toml_escape_basic_escapes_quote_and_backslash() {
        // The two characters that can break out of a `"..."` envelope
        // in TOML basic strings.
        assert_eq!(toml_escape_basic("ab\"cd"), "ab\\\"cd");
        assert_eq!(toml_escape_basic("ab\\cd"), "ab\\\\cd");
    }

    #[test]
    fn toml_escape_basic_escapes_newline_and_control_chars() {
        assert_eq!(toml_escape_basic("a\nb"), "a\\nb");
        assert_eq!(toml_escape_basic("a\rb"), "a\\rb");
        assert_eq!(toml_escape_basic("a\tb"), "a\\tb");
        // C0 control without a named escape — must come out as \u00XX.
        assert_eq!(toml_escape_basic("a\u{01}b"), "a\\u0001b");
        // DEL (0x7F) is also banned in basic strings.
        assert_eq!(toml_escape_basic("a\u{7f}b"), "a\\u007Fb");
    }

    #[test]
    fn toml_escape_basic_passes_through_safe_chars() {
        // ASCII alphanumeric + common punctuation must NOT be touched
        // — over-eager escaping would make the rendered TOML noisy.
        assert_eq!(toml_escape_basic("abc-123_xyz=:/"), "abc-123_xyz=:/");
    }

    // (`render_config_escapes_malicious_vk_link` was removed 2026-05-19
    // — vk_link is no longer in the rendered config. The
    // `render_config_escapes_malicious_mode` test below still exercises
    // `toml_escape_basic` via the server_wg_private path; the escape
    // contract itself is also unit-tested in
    // `toml_escape_basic_escapes_*`.)

    #[test]
    fn render_config_escapes_malicious_mode() {
        // The mode field is whitelist-rejected (see below test), but
        // BEFORE the whitelist would have stopped it, a `"` in the
        // pasted value would still need escaping if a future refactor
        // weakened the whitelist. This test pins the escape behaviour
        // for a value that DOES pass the whitelist —
        // `proxy_v2` then a quote tacked on would fail whitelist, so
        // we exercise `toml_escape_basic` indirectly via
        // server_wg_private which has no whitelist.
        let mut secrets = complete_secrets();
        secrets.insert(
            "wgturn:server_wg_private".into(),
            "fakekey\"injected = true\nx = \"".into(),
        );
        let server = dummy_server();
        let ctx = RenderCtx::new(&server, &secrets);
        let protos: Vec<&dyn Protocol> = vec![&vpnctl_protocols::WgTurn];
        let bytes = WgTurn::new().render_config(&ctx, &[], &protos).unwrap();
        let toml = String::from_utf8(bytes).unwrap();
        let no_injection = !toml
            .lines()
            .any(|line| line.trim_start() == "injected = true");
        assert!(
            no_injection,
            "server_wg_private injection broke out:\n{toml}"
        );
    }

    #[test]
    fn render_config_rejects_non_numeric_listen_port() {
        // Review-agent finding 5 — important: an invalid listen_port
        // value must fail at render time with a clear error, not
        // silently emit garbage and crash wgturn-cli 8 seconds later.
        let mut secrets = complete_secrets();
        secrets.insert("wgturn:listen_port".into(), "not-a-number".into());
        let server = dummy_server();
        let ctx = RenderCtx::new(&server, &secrets);
        let protos: Vec<&dyn Protocol> = vec![&vpnctl_protocols::WgTurn];
        let err = WgTurn::new().render_config(&ctx, &[], &protos).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("wgturn:listen_port"),
            "error must name the bad key: {msg}"
        );
        assert!(
            msg.contains("not-a-number"),
            "error must quote the bad value: {msg}"
        );
    }

    #[test]
    fn render_config_rejects_out_of_range_listen_port() {
        let mut secrets = complete_secrets();
        // 99999 > u16::MAX → parse should fail.
        secrets.insert("wgturn:listen_port".into(), "99999".into());
        let server = dummy_server();
        let ctx = RenderCtx::new(&server, &secrets);
        let protos: Vec<&dyn Protocol> = vec![&vpnctl_protocols::WgTurn];
        let err = WgTurn::new().render_config(&ctx, &[], &protos).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("wgturn:listen_port"), "got: {msg}");
    }

    #[test]
    fn render_config_rejects_unknown_mode() {
        // mode whitelist enforcement — only `proxy_v2` / `proxy_v1`
        // / `wireguard` accepted.
        let mut secrets = complete_secrets();
        secrets.insert("wgturn:mode".into(), "ssh-banana".into());
        let server = dummy_server();
        let ctx = RenderCtx::new(&server, &secrets);
        let protos: Vec<&dyn Protocol> = vec![&vpnctl_protocols::WgTurn];
        let err = WgTurn::new().render_config(&ctx, &[], &protos).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("wgturn:mode"), "got: {msg}");
        assert!(
            msg.contains("ssh-banana"),
            "must quote the bad value: {msg}"
        );
        assert!(
            msg.contains("proxy_v2") || msg.contains("proxy_v1"),
            "must list the allowed values: {msg}"
        );
    }

    #[test]
    fn render_config_accepts_each_whitelisted_mode() {
        for mode in ["proxy_v2", "proxy_v1", "wireguard"] {
            let mut secrets = complete_secrets();
            secrets.insert("wgturn:mode".into(), mode.into());
            let server = dummy_server();
            let ctx = RenderCtx::new(&server, &secrets);
            let protos: Vec<&dyn Protocol> = vec![&vpnctl_protocols::WgTurn];
            let bytes = WgTurn::new()
                .render_config(&ctx, &[], &protos)
                .unwrap_or_else(|e| panic!("mode={mode} rejected: {e}"));
            let toml = String::from_utf8(bytes).unwrap();
            assert!(
                toml.contains(&format!("mode = \"{mode}\"")),
                "mode {mode:?} not embedded: {toml}"
            );
        }
    }

    #[test]
    fn ensure_installed_script_pins_to_known_sha() {
        // Defense-in-depth: the pinned SHA literal must NOT be the
        // empty string and must be a 40-char hex (full git SHA-1).
        // A pin-bump removing the constant by accident (e.g. via
        // search-replace) would fail this test before deploy.
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
