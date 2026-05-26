use async_trait::async_trait;
use serde_json::json;
use vpnctl_core::{
    CoreError, Kernel, KernelId, KernelStatus, Protocol, ProtocolId, RenderCtx, Result,
    SshTransport, User,
};

/// sing-box 1.13.x из официального APT-репо SagerNet.
///
/// **Optional features that need a newer sing-box than what's in the
/// SagerNet stable APT channel:**
///
/// | Feature | Required | Activation |
/// |---|---|---|
/// | `experimental.clash_api` block | sing-box ≥ 1.10 | always rendered (Track-3 prep) |
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
        ]
    }

    async fn ensure_installed(&self, ssh: &dyn SshTransport) -> Result<()> {
        // Идемпотентно: пакет ставится только если не установлен.
        //
        // Каноничный минимальный Debian (например, новый VDS) НЕ имеет
        // curl/gpg/ca-certificates — поэтому ставим их безусловно перед
        // тем, как тянуть APT-репо SagerNet. Найдено на staging-деплое
        // 84.19.3.104 (Debian 12 minimal): exec exit=127 «curl: команда
        // не найдена».
        //
        // **Logrotate (added 2026-05-16):** without an explicit rotation
        // policy, `/var/log/sing-box.log` grows linearly with traffic
        // (~MB/day on a low-traffic node, GB/day on a busy one). At
        // 20 GB disk staging boxes that's a death spiral within a
        // couple months. Install a logrotate fragment that caps log
        // age at 14 days + size at 100 MB, then `copytruncate` so
        // sing-box doesn't need a SIGHUP/restart to pick up the new
        // file. Idempotent: `cat > .../sing-box` replaces any prior
        // version (including a hand-edited one — operator should know).
        let script = r#"
            set -eu
            export DEBIAN_FRONTEND=noninteractive
            if ! command -v sing-box >/dev/null; then
                apt-get update -qq
                apt-get install -y --no-install-recommends \
                    curl gpg ca-certificates
                install -d -m 0755 /usr/share/keyrings
                curl -fsSL https://sing-box.app/gpg.key \
                    | gpg --dearmor -o /usr/share/keyrings/sagernet.gpg
                echo "deb [signed-by=/usr/share/keyrings/sagernet.gpg] https://deb.sagernet.org/ * *" \
                    > /etc/apt/sources.list.d/sagernet.list
                apt-get update -qq
                apt-get install -y sing-box
            fi
            # Pre-create log file with sing-box ownership. Otherwise the
            # service crash-loops with "open /var/log/sing-box.log:
            # permission denied" — observed live on the staging deploy.
            install -o sing-box -g sing-box -m 0640 /dev/null /var/log/sing-box.log
            chown -R sing-box:sing-box /etc/sing-box
            systemctl enable sing-box >/dev/null
            # logrotate fragment for sing-box's main log file. `daily`
            # check with size-based trigger at 100 MB. `copytruncate`
            # so sing-box's open file descriptor stays valid (no SIGHUP
            # needed). Keep 14 rotations = ~14 days at most under
            # idle load.
            apt-get install -y --no-install-recommends logrotate
            cat > /etc/logrotate.d/sing-box <<'LR'
/var/log/sing-box.log {
    daily
    rotate 14
    size 100M
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    su sing-box sing-box
    create 0640 sing-box sing-box
}
LR
            # Verify the fragment parses — logrotate's parser is strict
            # and a typo would silently disable rotation for ALL fragments.
            logrotate -d /etc/logrotate.d/sing-box >/dev/null 2>&1
            command -v sing-box  # final assertion — fails the exec on regression
            command -v logrotate
        "#;
        ssh.exec(script).await?;
        Ok(())
    }

    fn render_config(
        &self,
        ctx: &RenderCtx<'_>,
        users: &[User],
        protocols: &[&dyn Protocol],
    ) -> Result<Vec<u8>> {
        let mut inbounds = Vec::with_capacity(protocols.len());
        for p in protocols {
            inbounds.push(p.server_inbound(ctx, users)?);
        }
        let cfg = json!({
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
                }
            }
        });
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
        // Атомарная замена + валидация перед перезагрузкой + ВЕРИФИКАЦИЯ
        // что сервис реально поднялся. Без последнего блока deploy'и
        // молча «succeed» когда sing-box crash-loop'ит (живой пример:
        // permission denied на /var/log/sing-box.log на свежей ноде).
        let cmd = r#"
            set -eu
            sing-box check -c /etc/sing-box/config.json.new
            mv /etc/sing-box/config.json.new /etc/sing-box/config.json
            chown sing-box:sing-box /etc/sing-box/config.json
            chmod 0640 /etc/sing-box/config.json
            systemctl reload-or-restart sing-box

            # Wait up to 8 seconds for the service to settle. systemd's
            # auto-restart back-off kicks in every 10s, so 8s is past the
            # first attempt — if we're not "active" by then, we're in a
            # crash loop.
            for i in 1 2 3 4 5 6 7 8; do
                state=$(systemctl is-active sing-box || true)
                [ "$state" = "active" ] && exit 0
                sleep 1
            done

            # Bail with the most diagnostic output possible.
            echo "sing-box did not become active. Last 20 log lines:" >&2
            journalctl -u sing-box --no-pager -n 20 >&2 || true
            exit 1
        "#;
        ssh.exec(cmd).await?;
        Ok(())
    }

    async fn restart(&self, ssh: &dyn SshTransport) -> Result<()> {
        ssh.exec("systemctl restart sing-box").await?;
        Ok(())
    }

    async fn status(&self, ssh: &dyn SshTransport) -> Result<KernelStatus> {
        let active = ssh
            .exec("systemctl is-active sing-box")
            .await?
            .trim()
            .eq("active");
        let version = ssh.exec("sing-box version 2>&1 | head -1").await.ok();
        Ok(KernelStatus {
            active,
            version,
            uptime_seconds: None,
        })
    }
}

/// Extract every `uuid` value found in `inbounds[*].users[*]` of a
/// sing-box JSON config. Tolerant of non-VLESS inbounds (which don't
/// carry a `users` array) and of inbounds whose users use a different
/// auth shape — only entries with a real `"uuid"` string key are
/// returned. Used by the pre-apply diff guard.
fn extract_user_uuids(config_bytes: &[u8]) -> Result<std::collections::HashSet<String>> {
    let v: serde_json::Value = serde_json::from_slice(config_bytes).map_err(CoreError::from)?;
    let mut out = std::collections::HashSet::new();
    let Some(inbounds) = v.get("inbounds").and_then(|x| x.as_array()) else {
        return Ok(out);
    };
    for inbound in inbounds {
        let Some(users) = inbound.get("users").and_then(|x| x.as_array()) else {
            continue;
        };
        for u in users {
            if let Some(uuid) = u.get("uuid").and_then(|x| x.as_str()) {
                out.insert(uuid.to_string());
            }
        }
    }
    Ok(out)
}

/// Compute the set of user UUIDs that are present in the OLD config
/// but absent from the NEW config — i.e. would be REMOVED if we
/// proceeded with the apply. Empty result = safe to proceed.
fn user_uuid_diff(old: &[u8], new: &[u8]) -> Result<std::collections::HashSet<String>> {
    let old_uuids = extract_user_uuids(old)?;
    let new_uuids = extract_user_uuids(new)?;
    Ok(old_uuids.difference(&new_uuids).cloned().collect())
}

/// Reserved-ports pre-apply guard (post-2026-05-26, Pavel:
/// «важно конкретно для этого сервера заблокировать часть
/// функционала, чтоб через админку нельзя было что-то перетереть»).
///
/// Returns `Err` with the offending port(s) if `config_bytes` (a
/// rendered sing-box JSON) declares any `inbounds[].listen_port`
/// that intersects `reserved`. Empty `reserved` is a no-op — most
/// servers in the fleet stay byte-equivalent to pre-0028.
///
/// The fence is **fail-CLOSED**: parse failures of `config_bytes`
/// also return Err. This is the opposite policy from
/// `user_uuid_diff` — there we fail-OPEN because the OLD config
/// might be hand-edited; here the NEW config is what *we* render,
/// so a parse failure means our own renderer produced malformed
/// JSON and the safest move is to refuse to upload it.
///
/// Called from every `apply_config` site (CLI deploy, daemon
/// deploy, wizard bootstrap). The trait signature itself is not
/// changed — the validator is a free function so kernels other
/// than sing-box don't have to opt in.
pub fn validate_config_excludes_ports(config_bytes: &[u8], reserved: &[u16]) -> Result<()> {
    if reserved.is_empty() {
        return Ok(());
    }
    let parsed: serde_json::Value = serde_json::from_slice(config_bytes).map_err(|e| {
        CoreError::Render(format!(
            "sing-box config: reserved-ports guard could not parse rendered JSON ({e}); \
             refusing to apply"
        ))
    })?;
    let Some(inbounds) = parsed.get("inbounds").and_then(|v| v.as_array()) else {
        // No inbounds[] at all — vacuously safe (the renderer may
        // produce a config with only outbounds for some future
        // route-only role). Don't false-flag.
        return Ok(());
    };
    let reserved_set: std::collections::HashSet<u16> = reserved.iter().copied().collect();
    let mut collisions: Vec<u16> = Vec::new();
    for inbound in inbounds {
        let Some(port_value) = inbound.get("listen_port") else {
            continue;
        };
        let Some(port_u64) = port_value.as_u64() else {
            continue;
        };
        let Ok(port) = u16::try_from(port_u64) else {
            continue;
        };
        if reserved_set.contains(&port) {
            collisions.push(port);
        }
    }
    if collisions.is_empty() {
        return Ok(());
    }
    collisions.sort_unstable();
    collisions.dedup();
    Err(CoreError::Render(format!(
        "sing-box config: refusing to apply — rendered inbounds[] bind reserved port(s) {:?} \
         on this server (full reserved list: {:?}). These ports are protected by the operator \
         (typically a co-tenant service like a legacy 3x-ui panel on :443). Reconfigure the \
         offending protocol to a non-reserved port via /admin/servers/<id> → Enabled protocols, \
         or drop the reservation via the Reserved-ports section if you truly want to overwrite \
         the co-tenant.",
        collisions, reserved
    )))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::collections::HashMap;
    use vpnctl_core::{Server, ServerId};

    fn dummy_ctx<'a>(server: &'a Server, secrets: &'a HashMap<String, String>) -> RenderCtx<'a> {
        RenderCtx::new(server, secrets)
    }

    fn dummy_server() -> Server {
        Server {
            id: ServerId("srv".into()),
            address: "10.0.0.1".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    /// Track-3 prep: render_config must include the
    /// `experimental.clash_api.external_controller` block bound to
    /// loopback so a future daemon-side poller can talk to sing-box's
    /// JSON API for active connections + traffic counters.
    #[test]
    fn render_config_includes_clash_api_on_loopback() {
        let s = dummy_server();
        let secrets = HashMap::new();
        let ctx = dummy_ctx(&s, &secrets);
        let bytes = SingBox::new().render_config(&ctx, &[], &[]).unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            v["experimental"]["clash_api"]["external_controller"],
            Value::String("127.0.0.1:9090".into()),
            "clash_api must bind to 127.0.0.1:9090 (loopback only — no external exposure)"
        );
    }

    /// Pre-existing keys (log, inbounds, outbounds) must still render
    /// — adding `experimental` shouldn't accidentally drop them.
    #[test]
    fn render_config_keeps_existing_top_level_keys() {
        let s = dummy_server();
        let secrets = HashMap::new();
        let ctx = dummy_ctx(&s, &secrets);
        let bytes = SingBox::new().render_config(&ctx, &[], &[]).unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v["log"].is_object(), "log block missing");
        assert!(v["inbounds"].is_array(), "inbounds array missing");
        let out = v["outbounds"].as_array().unwrap();
        assert_eq!(out.len(), 2, "outbounds should be [direct, block]");
        assert_eq!(out[0]["type"], "direct");
        assert_eq!(out[1]["type"], "block");
    }

    // ── Pre-apply diff guard (post-2026-05-19 vps-de-01 incident) ──
    //
    // Pavel reported: «Все Anthropic API запросы из claude-chat
    // падали тихо». Root cause: a sing-box deploy on vps-de-01
    // dropped the `claude-chat-proxy` service user UUID
    // (b25684c3-…) from `inbounds[0].users[]` because it wasn't in
    // vpnctld's inventory. The pre-apply diff guard refuses any
    // apply that would REMOVE a live UUID (unless the operator
    // explicitly opts in via VPNCTLD_ALLOW_USER_REMOVAL=1).

    fn make_config(uuids: &[&str]) -> Vec<u8> {
        let users: Vec<Value> = uuids
            .iter()
            .map(|u| {
                serde_json::json!({
                    "name": "u",
                    "uuid": u,
                    "flow": "xtls-rprx-vision",
                })
            })
            .collect();
        let cfg = serde_json::json!({
            "inbounds": [
                { "type": "vless", "users": users }
            ]
        });
        serde_json::to_vec(&cfg).unwrap()
    }

    #[test]
    fn extract_user_uuids_finds_every_uuid_across_inbounds() {
        let cfg = serde_json::json!({
            "inbounds": [
                { "type": "vless", "users": [
                    {"uuid": "aaa", "name": "a"},
                    {"uuid": "bbb", "name": "b"},
                ]},
                { "type": "tuic", "users": [{"uuid": "ccc", "password": "x"}] },
                { "type": "trojan", "users": [{"password": "no-uuid-here"}] },
            ]
        });
        let bytes = serde_json::to_vec(&cfg).unwrap();
        let got = extract_user_uuids(&bytes).unwrap();
        let expected: std::collections::HashSet<String> = ["aaa", "bbb", "ccc"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn extract_user_uuids_returns_empty_on_no_inbounds() {
        let bytes = b"{}".to_vec();
        let got = extract_user_uuids(&bytes).unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn extract_user_uuids_returns_err_on_invalid_json() {
        let bytes = b"not json".to_vec();
        assert!(extract_user_uuids(&bytes).is_err());
    }

    #[test]
    fn user_uuid_diff_empty_when_new_is_superset() {
        let old = make_config(&["a", "b"]);
        let new = make_config(&["a", "b", "c"]);
        assert!(user_uuid_diff(&old, &new).unwrap().is_empty());
    }

    #[test]
    fn user_uuid_diff_lists_only_removed_uuids() {
        let old = make_config(&["a", "b", "c"]);
        let new = make_config(&["a", "c"]);
        let lost = user_uuid_diff(&old, &new).unwrap();
        assert_eq!(lost.len(), 1, "lost: {lost:?}");
        assert!(lost.contains("b"));
    }

    #[test]
    fn user_uuid_diff_lists_the_pavel_2026_05_19_case() {
        // The exact incident: live config has claude-chat-proxy's
        // UUID; new rendered config (built from inventory that didn't
        // include the service user) lacks it.
        let live = make_config(&[
            "af6f36aa-2a51-45c7-82dd-5cd362ed970b",
            "b25684c3-90d6-454a-a911-4e0abba568b0", // claude-chat-proxy
        ]);
        let rendered = make_config(&["af6f36aa-2a51-45c7-82dd-5cd362ed970b"]);
        let lost = user_uuid_diff(&live, &rendered).unwrap();
        assert_eq!(lost.len(), 1);
        assert!(lost.contains("b25684c3-90d6-454a-a911-4e0abba568b0"));
    }

    #[test]
    fn user_uuid_diff_empty_when_old_has_no_users() {
        // Fresh node: no /etc/sing-box/config.json yet → empty old set
        // → cannot lose anyone. (In production this path is the
        // ssh.read_file `Err` branch which skips the guard entirely;
        // this test pins the empty-set semantics.)
        let old = b"{\"inbounds\":[]}".to_vec();
        let new = make_config(&["a", "b"]);
        assert!(user_uuid_diff(&old, &new).unwrap().is_empty());
    }

    // ── reserved-ports guard (migration 0028, 2026-05-26) ───────────

    fn cfg_with_inbound_ports(ports: &[u16]) -> Vec<u8> {
        let inbounds: Vec<serde_json::Value> = ports
            .iter()
            .map(|p| serde_json::json!({"type": "vless", "listen_port": p}))
            .collect();
        serde_json::to_vec(&serde_json::json!({"inbounds": inbounds})).unwrap()
    }

    #[test]
    fn reserved_ports_empty_list_is_noop() {
        // Most servers in the fleet have no reserved ports — the
        // guard must short-circuit, never parse, never allocate.
        let cfg = cfg_with_inbound_ports(&[443, 8443]);
        assert!(validate_config_excludes_ports(&cfg, &[]).is_ok());
    }

    #[test]
    fn reserved_ports_disjoint_passes() {
        // Reserved [443], rendered uses [8443] — no collision.
        let cfg = cfg_with_inbound_ports(&[8443, 2083]);
        assert!(validate_config_excludes_ports(&cfg, &[443]).is_ok());
    }

    #[test]
    fn reserved_ports_intersection_blocks() {
        // The 3x-ui scenario: 443 is reserved, the renderer (mistake
        // or accident) wants to bind 443. Guard must refuse, the
        // error must name the offending port.
        let cfg = cfg_with_inbound_ports(&[443, 8443]);
        let err = validate_config_excludes_ports(&cfg, &[443])
            .expect_err("reserved-port collision must error");
        let msg = err.to_string();
        assert!(msg.contains("443"), "error must mention port 443: {msg}");
    }

    #[test]
    fn reserved_ports_multiple_collisions_listed() {
        // Renderer somehow tries TWO reserved ports — error must list
        // both so operator doesn't have to retry to discover the
        // second one. Order is sorted-ascending; dedup applied.
        let cfg = cfg_with_inbound_ports(&[443, 2053, 2096, 8443]);
        let err = validate_config_excludes_ports(&cfg, &[443, 2053, 2096])
            .expect_err("multi-port collision must error");
        let msg = err.to_string();
        // The error renders the offending list as `{:?}` — sorted +
        // dedup'd by the validator.
        assert!(msg.contains("[443, 2053, 2096]"), "msg = {msg}");
    }

    #[test]
    fn reserved_ports_malformed_config_fails_closed() {
        // FAIL-CLOSED policy: the NEW config is what *we* render, so
        // bad JSON means our renderer is broken; refusing to upload
        // is the safest move. (Contrast with user_uuid_diff which
        // fail-OPENs on the OLD config because that may be hand-
        // edited.)
        let err = validate_config_excludes_ports(b"not-json", &[443])
            .expect_err("malformed config with non-empty reserved list must fail closed");
        let msg = err.to_string();
        assert!(msg.contains("parse"), "msg = {msg}");
    }

    #[test]
    fn reserved_ports_no_inbounds_array_is_safe() {
        // Future renderer might produce a config with only outbounds
        // (some route-only role). Treat as vacuously safe — no
        // listen_port to collide.
        let cfg = serde_json::to_vec(&serde_json::json!({"outbounds": []})).unwrap();
        assert!(validate_config_excludes_ports(&cfg, &[443]).is_ok());
    }

    #[test]
    fn reserved_ports_listen_port_missing_is_safe() {
        // Inbound without listen_port (e.g. a transport-only inbound
        // sharing a parent inbound's port) is skipped — only explicit
        // listen_port matches are checked.
        let cfg = serde_json::to_vec(&serde_json::json!({
            "inbounds": [{"type": "vless"}, {"type": "tuic", "listen_port": 8443}]
        }))
        .unwrap();
        assert!(validate_config_excludes_ports(&cfg, &[443]).is_ok());
    }

    #[test]
    fn reserved_ports_listen_port_non_u16_skipped() {
        // Defensive: a JSON value like `99999` or a float that doesn't
        // fit u16 must NOT crash the guard. Skip silently — the
        // sing-box `check -c` step downstream rejects bad ports anyway.
        let cfg = serde_json::to_vec(&serde_json::json!({
            "inbounds": [{"listen_port": 999_999}, {"listen_port": 443}]
        }))
        .unwrap();
        // 443 still flagged; 999_999 silently skipped.
        let err = validate_config_excludes_ports(&cfg, &[443]).expect_err("443 collides");
        assert!(err.to_string().contains("443"));
    }
}
