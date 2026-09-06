mod arch;
mod guards;
mod scripts;
#[cfg(test)]
mod tests;

pub(crate) use arch::resolve_sing_box_artifact_path;
pub use guards::{live_config_user_uuids, validate_config_excludes_ports};
pub use scripts::{
    SING_BOX_AMD64_SHA256, SING_BOX_ARM64_SHA256, SING_BOX_ARMV7_SHA256, SING_BOX_MIN_VERSION,
    SING_BOX_VPNCTL_VERSION,
};

use async_trait::async_trait;
use guards::user_uuid_diff;
use scripts::{
    DEFAULT_STATS_HELPER_ARTIFACT, SING_BOX_SETUP_SCRIPT, cleanup_remote_artifacts_script,
    firewall_open_script, install_managed_artifacts_script, remote_artifact_paths,
    sing_box_apply_script,
};
use serde_json::json;
use vpnctl_core::{
    CoreError, Kernel, KernelId, KernelStatus, KernelVersionPolicy, KernelVersionRequirement,
    Protocol, ProtocolId, RenderCtx, Result, SshTransport, User,
};

/// sing-box 1.13.x из официального APT-репо SagerNet.
///
/// **Optional features that need a newer sing-box than what's in the
/// SagerNet stable APT channel:**
///
/// | Feature | Required | Activation |
/// |---|---|---|
/// | `experimental.clash_api` block | sing-box ≥ 1.10 | always rendered for live metadata |
/// | `experimental.v2ray_api` block | build tag `with_v2ray_api` | always rendered for cumulative accounting |
/// | Hysteria2 `realm` (NAT-traversal via rendezvous + STUN) | sing-box ≥ 1.14 | only when `hysteria2.realm.server_url` is set in `RenderCtx::secrets` |
///
/// On a stale node (1.13.x without the rendered key support), the
/// `sing-box check -c …` step in `apply_config` rejects the config
/// before `mv` swaps it in — so the deploy fails loud rather than
/// silently dropping the directive. To unlock 1.14+, switch the APT
/// repo from `*/*` to a channel that ships 1.14, or pull a release
/// `.deb` from sing-box GitHub releases.
#[derive(Debug, Default)]
pub struct SingBox;

impl SingBox {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Kernel for SingBox {
    fn id(&self) -> KernelId {
        KernelId("sing-box".to_string())
    }

    fn supported_protocols(&self) -> Vec<ProtocolId> {
        vec![
            ProtocolId("vless+reality".to_string()),
            ProtocolId("tuic-v5".to_string()),
            ProtocolId("hysteria2".to_string()),
            ProtocolId("shadowsocks-2022".to_string()),
            // AnyTLS — sing-box ≥ 1.12. ensure_installed pulls the
            // SagerNet stable channel which currently ships 1.13.x;
            // on a stale-version node `sing-box check` would reject
            // an `anytls` inbound and apply_config fails loud.
            ProtocolId("anytls".to_string()),
            // Trojan — in sing-box since v0.1, no version concern.
            ProtocolId("trojan".to_string()),
            ProtocolId("amneziawg2".to_string()),
            ProtocolId("amneziawg3".to_string()),
        ]
    }

    fn version_requirement(&self) -> Option<KernelVersionRequirement> {
        Some(KernelVersionRequirement {
            policy: KernelVersionPolicy::Floor,
            value: SING_BOX_MIN_VERSION,
        })
    }

    async fn ensure_installed(&self, ssh: &dyn SshTransport) -> Result<()> {
        let arch = ssh
            .exec("uname -m 2>/dev/null || echo x86_64")
            .await?
            .trim()
            .to_string();
        let sing_box_path = resolve_sing_box_artifact_path(&arch);
        let helper_path = std::env::var_os("VPNCTL_STATS_HELPER_ARTIFACT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(DEFAULT_STATS_HELPER_ARTIFACT));
        // Validate both local artifacts before changing the node. Packaging
        // installs these atomically from the same vpnctl revision.
        let (sing_box, stats_helper) = tokio::task::spawn_blocking(move || {
            let sb = std::fs::read(&sing_box_path)?;
            let sh = std::fs::read(&helper_path)?;
            Ok::<_, std::io::Error>((sb, sh))
        })
        .await
        .map_err(|e| CoreError::Transport(format!("spawn_blocking failed: {e}")))?
        .map_err(CoreError::Io)?;

        // Idempotent base setup keeps the official package as the rollback
        // source; the managed binary then adds with_v2ray_api and the helper.
        ssh.exec(SING_BOX_SETUP_SCRIPT.as_str()).await?;
        let (remote_sing_box, remote_stats_helper) = remote_artifact_paths();
        let cleanup_script =
            cleanup_remote_artifacts_script(&remote_sing_box, &remote_stats_helper);
        let install_script =
            install_managed_artifacts_script(&remote_sing_box, &remote_stats_helper);
        ssh.exec(&cleanup_script).await?;
        let install_result: Result<()> = async {
            ssh.upload(&remote_sing_box, &sing_box).await?;
            ssh.upload(&remote_stats_helper, &stats_helper).await?;
            ssh.exec(&install_script).await?;
            Ok(())
        }
        .await;
        if install_result.is_err() {
            // The installer cleans its own paths once its shell starts. Cover
            // partial uploads and transport failures before that point too.
            let _ = ssh.exec(&cleanup_script).await;
        }
        install_result
    }

    fn render_config(
        &self,
        ctx: &RenderCtx<'_>,
        users: &[User],
        protocols: &[&dyn Protocol],
    ) -> Result<Vec<u8>> {
        let mut inbounds = Vec::with_capacity(protocols.len());
        let mut endpoints = Vec::new();
        for p in protocols {
            let fragment = p.server_inbound(ctx, users)?;
            // WireGuard is a bidirectional endpoint in native sing-box JSON,
            // not an inbound. Dispatch by wire schema, not protocol identity.
            if fragment.get("type").and_then(serde_json::Value::as_str) == Some("wireguard") {
                endpoints.push(fragment);
            } else {
                inbounds.push(fragment);
            }
        }
        let stats_users: Vec<&str> = users.iter().map(|user| user.id.0.as_str()).collect();
        let stats_inbounds: Vec<String> = inbounds
            .iter()
            .map(|inbound| {
                inbound
                    .get("tag")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| CoreError::Render("sing-box inbound is missing its tag".into()))
            })
            .collect::<Result<_>>()?;
        let mut cfg = json!({
            "log": { "level": "info", "output": "/var/log/sing-box.log", "timestamp": true },
            "inbounds": inbounds,
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "block", "tag": "block" }
            ],
            // Phase Track-3 prep: clash-api on loopback so the daemon
            // can poll active connections + traffic counters in a
            // future iteration. Bound to 127.0.0.1 (no external
            // exposure); no secret needed because nothing on the node
            // is allowed to bind 9090 except sing-box itself.
            //
            // No `external_ui` set — we don't need a clash dashboard.
            // The future poller talks the JSON API directly.
            //
            // sing-box ≥ 1.10 accepts this top-level key; on older
            // builds the `sing-box check` step would reject the
            // config, so the deploy fails loudly on a stale node.
            "experimental": {
                "clash_api": {
                    "external_controller": "127.0.0.1:9090"
                },
                "v2ray_api": {
                    "listen": "127.0.0.1:10085",
                    "stats": {
                        "enabled": true,
                        "inbounds": stats_inbounds,
                        "users": stats_users
                    }
                }
            }
        });
        // Omit new fields entirely for legacy servers to preserve their bytes.
        if !endpoints.is_empty() {
            let endpoint_tags: Vec<&str> = endpoints
                .iter()
                .map(|endpoint| {
                    endpoint
                        .get("tag")
                        .and_then(serde_json::Value::as_str)
                        .filter(|tag| !tag.is_empty())
                        .ok_or_else(|| {
                            CoreError::Render("sing-box endpoint is missing its tag".into())
                        })
                })
                .collect::<Result<_>>()?;
            // Userspace endpoints can map their tunnel address to host loopback.
            // VPN peers must not reach node-local management or private services.
            let mut rules = vec![json!({
                "inbound": endpoint_tags, "ip_is_private": true, "action": "reject"
            })];
            // A node's own public address is not private, but services bound to
            // it are still node-local. Reject it explicitly for VPN peers.
            if let Ok(address) = ctx.server.address.parse::<std::net::IpAddr>() {
                let prefix = if address.is_ipv4() { 32 } else { 128 };
                rules.push(json!({
                    "inbound": endpoint_tags,
                    "ip_cidr": [format!("{address}/{prefix}")],
                    "action": "reject"
                }));
            } else {
                return Err(CoreError::Render(
                    "AWG server isolation requires a literal server IP; set the server address in the admin UI before deploying".into(),
                ));
            }
            cfg["route"] = json!({ "rules": rules, "final": "direct" });
            cfg["endpoints"] = json!(endpoints);
        }
        serde_json::to_vec_pretty(&cfg).map_err(CoreError::from)
    }

    async fn apply_config(&self, ssh: &dyn SshTransport, config: &[u8]) -> Result<()> {
        // ── PRE-APPLY DIFF GUARD (post-2026-05-19 incident) ───────
        //
        // Compare the LIVE /etc/sing-box/config.json with the new
        // rendered one. If the new config REMOVES any user UUID
        // from inbounds[*].users[*] AND the operator has not
        // explicitly set VPNCTLD_ALLOW_USER_REMOVAL=1, REFUSE the
        // deploy with the lost UUIDs spelled out.
        //
        // Why this exists: 2026-05-18 deploy on vps-de-01 silently
        // dropped UUID `b25684c3-…` (the claude-chat-proxy service
        // user that wasn't in vpnctld's inventory). Result: every
        // outbound HTTPS request from .142 containers — including
        // the entire claude-chat → api.anthropic.com path —
        // started failing tcpdump-silent at Reality handshake.
        // Pavel had to manually patch the live config back.
        //
        // The fix: vpnctld now reads the existing config before
        // rewriting it. If reconciling inventory → live would lose
        // any UUID, the operator sees a precise list with the
        // remediation paths (add to inventory OR override).
        //
        // Guard runs ONLY when the file already exists (fresh-node
        // first deploy has nothing to lose). Parse failures on
        // the OLD config are non-fatal — we log + proceed (the
        // file might be hand-edited into a non-standard shape;
        // refusing forever would itself be a footgun).
        if let Ok(old_bytes) = ssh.read_file("/etc/sing-box/config.json").await {
            match user_uuid_diff(&old_bytes, config) {
                Ok(removed) if !removed.is_empty() => {
                    let allow = std::env::var("VPNCTLD_ALLOW_USER_REMOVAL")
                        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                        .unwrap_or(false);
                    if !allow {
                        let preview: Vec<&String> = removed.iter().take(5).collect();
                        return Err(CoreError::Render(format!(
                            "sing-box apply_config: refusing to deploy a config that would \
                             REMOVE {} user UUID(s) from inbounds[*].users[]: {:?}{}. \
                             These users exist on the LIVE server but are missing from vpnctld's \
                             inventory. Either:\n  \
                             1. Add the missing user(s) to inventory (admin UI → Add user with \
                                the SAME UUID, then grant on this server), OR\n  \
                             2. Set VPNCTLD_ALLOW_USER_REMOVAL=1 in /etc/vpnctl/vpnctld.env and \
                                restart vpnctld to bypass this gate for this deploy cycle.",
                            removed.len(),
                            preview,
                            if removed.len() > preview.len() {
                                format!(" (+{} more)", removed.len() - preview.len())
                            } else {
                                String::new()
                            },
                        )));
                    }
                }
                Ok(_) => { /* no removals, proceed */ }
                Err(e) => {
                    // Defensive — old config is hand-edited / malformed.
                    // We don't fail closed here because that'd brick
                    // deploys forever on any node with a non-standard
                    // /etc/sing-box/config.json. Operator's signal is
                    // this stderr warn that journald captures into
                    // `journalctl -u vpnctld`. (Can't use `tracing!`
                    // — the kernels crate intentionally has zero
                    // logging deps; daemon-side logging happens at
                    // the handler layer.)
                    eprintln!(
                        "WARN vpnctl::kernels::sing_box: pre-apply diff guard could not \
                         parse old /etc/sing-box/config.json ({e}); skipping guard \
                         (deploy proceeds)"
                    );
                }
            }
        }

        ssh.upload("/etc/sing-box/config.json.new", config).await?;
        ssh.exec(sing_box_apply_script()).await?;
        Ok(())
    }

    async fn open_firewall(
        &self,
        ssh: &dyn SshTransport,
        ctx: &RenderCtx<'_>,
        protocols: &[&dyn Protocol],
    ) -> Result<()> {
        // Source of truth = each `Protocol::effective_listen_ports()` (the
        // SAME data the cross-protocol port-conflict guard reads), so the
        // firewall opens EXACTLY what sing-box binds — never a stale
        // hardcoded list, and it grows automatically when a new protocol is
        // enabled. `effective_*` (not the static `listen_ports`) so a
        // per-server port override (e.g. vless.listen_port=8443 on a
        // co-tenant host) opens the REAL port — the static default would
        // open 443 that a co-owned caddy already holds and leave 8443
        // firewalled (cdn incident 2026-08-05).
        let ports: Vec<(&str, u16)> = protocols
            .iter()
            .flat_map(|p| p.effective_listen_ports(ctx.secrets))
            .collect();
        if let Some(script) = firewall_open_script(&ports) {
            ssh.exec(&script).await?;
        }
        Ok(())
    }

    async fn restart(&self, ssh: &dyn SshTransport) -> Result<()> {
        ssh.exec("systemctl restart sing-box").await?;
        Ok(())
    }

    async fn status(&self, ssh: &dyn SshTransport) -> Result<KernelStatus> {
        let active = ssh
            .exec("systemctl is-active sing-box 2>/dev/null || true")
            .await?
            .trim()
            .eq("active");
        let version = ssh
            .exec("/usr/bin/sing-box version 2>/dev/null | awk '/version/{print $3; exit}'")
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
