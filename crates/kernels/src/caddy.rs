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

mod builder;
mod render;
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use vpnctl_core::{
    CoreError, Kernel, KernelId, KernelStatus, KernelVersionPolicy, KernelVersionRequirement,
    Protocol, ProtocolId, RenderCtx, Result, SshTransport, User,
};

use self::builder::{
    CADDY_RESTART_IF_ACTIVE, CADDY_VERSION, caddy_build_script, caddy_cache_path,
    caddy_needs_reinstall, caddy_present, caddy_runtime_provision_script,
};
use self::render::{
    BUNDLE_DELIMITER, naive_apply_script, render_naive_config, render_vlessws_bundle,
    vlessws_apply_script,
};

#[derive(Debug, Default)]
pub struct Caddy;

impl Caddy {
    pub fn new() -> Self {
        Self
    }
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

    fn version_requirement(&self) -> Option<KernelVersionRequirement> {
        Some(KernelVersionRequirement {
            policy: KernelVersionPolicy::Pin,
            value: CADDY_VERSION,
        })
    }

    async fn ensure_installed(&self, ssh: &dyn SshTransport) -> Result<()> {
        // FAST PATH: a prebuilt static (CGO-free) amd64 caddy cached on
        // the CONTROL node — upload it (seconds; no Go/swap/RAM pressure
        // on the target). The same binary runs on any amd64 node.
        // SLOW FALLBACK: build on the node via xcaddy (~10 min) when no
        // cache is present (e.g. a CLI deploy from a host without it).
        let cache = caddy_cache_path();
        let binary_changed = match std::fs::read(&cache) {
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
                let needs_reinstall = caddy_needs_reinstall(&digest, &node_sha);
                if needs_reinstall {
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
                needs_reinstall
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
                let needs_reinstall = !caddy_present(&present);
                if needs_reinstall {
                    ssh.exec(&caddy_build_script()).await?;
                }
                needs_reinstall
            }
            Err(e) => return Err(CoreError::Io(e)),
        };

        // Provision the runtime (user, masquerade site, systemd unit,
        // firewall) regardless of how the binary arrived. Idempotent.
        ssh.exec(&caddy_runtime_provision_script()).await?;
        if binary_changed {
            ssh.exec(CADDY_RESTART_IF_ACTIVE).await?;
        }
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

        render_naive_config(ctx, users, *naive)
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
        ssh.exec(naive_apply_script()).await?;
        Ok(())
    }

    async fn restart(&self, ssh: &dyn SshTransport) -> Result<()> {
        ssh.exec("systemctl restart caddy").await?;
        Ok(())
    }

    async fn status(&self, ssh: &dyn SshTransport) -> Result<KernelStatus> {
        let active = ssh
            .exec("systemctl is-active caddy 2>/dev/null || true")
            .await?
            .trim()
            .eq("active");
        let version = ssh
            .exec("/usr/local/bin/caddy version 2>/dev/null | awk '{print $1; exit}'")
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
