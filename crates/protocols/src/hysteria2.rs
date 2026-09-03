use crate::encoding::{FRAGMENT, QUERY, USERINFO};
use percent_encoding::utf8_percent_encode;
use serde_json::json;
use vpnctl_core::url_host::host_for_url;
use vpnctl_core::{CoreError, Protocol, ProtocolId, RenderCtx, Result, User};

/// Hysteria 2 — UDP/QUIC-based proxy. Same TLS material as TUIC by design
/// (we want one cert per node, not one per protocol), so the secrets
/// convention REUSES `tuic.cert_path` / `tuic.key_path`. Per-user auth is
/// the same shared secret as TUIC (`User.tuic_password`) — for v0.4.x
/// we treat "UDP-tunnel password" as a single per-user secret; if a
/// future use case needs split secrets per protocol, we add
/// `hysteria.password` and prefer it when present.
///
/// Listens on UDP:8444 (next to TUIC's UDP:8443).
///
/// # Security trade-off (intentional)
///
/// Sharing `tuic_password` across two protocols means **a leak in either
/// client (logs, screenshots, accidental commit) compromises both**. We
/// accept this in v0.4.x to simplify rotation (one `vpnctl user
/// regen-sub` style command later will rotate everything atomically).
/// Migration path when needed: add a `hysteria.password` field to
/// `User`, prefer it when set, fall back to `tuic_password` for
/// backward compat — pure-additive schema change.
///
/// **Stateless**, like every other Protocol in this crate.
#[derive(Debug, Default)]
pub struct Hysteria2;

impl Hysteria2 {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for Hysteria2 {
    fn id(&self) -> ProtocolId {
        ProtocolId("hysteria2".to_string())
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[("udp", 8444)]
    }

    fn dpi_risk(&self) -> vpnctl_core::DpiRisk {
        // The tier is a property of the WIRE FORMAT across the whole
        // fleet, not a per-server config, so it can't inspect whether
        // THIS server has the Salamander secret.
        //
        // `server_inbound` / `client_config` / `share_link` DO render
        // `obfs.type = salamander` whenever `hysteria2.obfs.password`
        // is present (see `obfs_password` below) — every server that
        // passes through a deploy gets the secret minted
        // (`bootstrap_server_secrets`). But minting is deploy-triggered
        // and idempotent with NO fleet-wide backfill, so a legacy
        // server enabled before the obfs spec existed and never
        // re-deployed still renders bare TLS 1.3 QUIC on UDP/8444.
        // Without Salamander the QUIC version tag + handshake pattern
        // fingerprints Hy2 reliably; TSPU (RU) has actively dropped Hy2
        // since early 2026 (CLAUDE.md NM-11 / NM-12), GFW (CN) the same.
        //
        // Because we can't guarantee every enabled server carries the
        // secret, Weak stays the honest conservative tier. The tooltip
        // (DpiRisk::Weak) spells out the conditional: legacy servers
        // without the secret are the fingerprintable ones; re-deploy
        // mints it.
        vpnctl_core::DpiRisk::Weak
    }

    fn server_secret_specs(&self) -> Vec<vpnctl_core::ServerSecretSpec> {
        // 24-byte Salamander obfs password (→ 32 chars url-safe base64),
        // matching the bash shape. Consumed as an OPAQUE STRING by
        // sing-box (not base64-decoded) → `Password`, not `Base64Key`.
        // The self-signed cert is generated node-side at deploy, not
        // pre-minted.
        vec![vpnctl_core::ServerSecretSpec::Password {
            key: "hysteria2.obfs.password",
            entropy_bytes: 24,
        }]
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<serde_json::Value> {
        // Reuse the TUIC cert paths so we provision ONE self-signed cert
        // per node (the existing deploy command already does that for TUIC).
        let cert_path = ctx.or_default("tuic.cert_path", "/etc/sing-box/cert.pem");
        let key_path = ctx.or_default("tuic.key_path", "/etc/sing-box/key.pem");

        // Per-user record. Sing-box hysteria2 wants `name` + `password`.
        // We reuse the same per-user secret as TUIC.
        let users_json: Vec<_> = users
            .iter()
            .filter_map(|u| {
                u.tuic_password
                    .as_ref()
                    .map(|pw| json!({ "name": u.id.0, "password": pw }))
            })
            .collect();

        let mut inbound = json!({
            "type": "hysteria2",
            "tag": "hy2-in",
            "listen": "::",
            "listen_port": 8444,
            "users": users_json,
            "tls": {
                "enabled": true,
                "alpn": ["h3"],
                "certificate_path": cert_path,
                "key_path": key_path,
            }
        });

        // Hysteria Realm — optional NAT-traversal mode. When the operator
        // configures a rendezvous service, the inbound REGISTERS itself
        // there + uses STUN-discovered public addresses + UDP hole-punching
        // to accept clients that can NOT reach `listen_port` directly
        // (CGNAT, residential ISP, no port-forwarding).
        //
        // Per https://sing-box.sagernet.org/configuration/inbound/hysteria2/
        // (Realm support: sing-box ≥ 1.14.0). On older sing-box this block
        // would be rejected at `sing-box check` time — `apply_config`
        // catches that and refuses to deploy, so a stale node fails loud
        // rather than silently ignoring the directive.
        //
        // Activation rule: emit the `realm` block IFF
        // `hysteria2.realm.server_url` is set in `RenderCtx::secrets`
        // **AND non-empty after trim**. An empty-string secret would
        // otherwise activate the block with `realm.server_url=""`,
        // which sing-box rejects only at deploy-time during
        // `sing-box check` — failing loud is good, but we'd rather
        // catch it at config-render time. (Caught by review-agent on
        // cd61838^..492fdeb burst.)
        //
        // The other realm fields fall back to sensible defaults:
        //   - `hysteria2.realm.realm_id`   → server.id (one node, one realm)
        //   - `hysteria2.realm.token`      → "" (anonymous register; OK
        //     for self-hosted rendezvous services on the LAN)
        //   - `hysteria2.realm.stun_servers` → comma-separated list,
        //     parsed into a JSON array. Empty list lets sing-box fall
        //     back to its default STUN server pool.
        //
        // We KEEP the `listen` / `listen_port` keys even when realm is
        // active — sing-box accepts both transports concurrently, so
        // clients on a flat network can connect directly while clients
        // behind NAT use the realm path. No-op cost on a public-IP node.
        if let Some(server_url) = ctx
            .secrets
            .get("hysteria2.realm.server_url")
            .filter(|s| !s.trim().is_empty())
        {
            let realm_id = ctx
                .secrets
                .get("hysteria2.realm.realm_id")
                .map(String::as_str)
                .unwrap_or(&ctx.server.id.0);
            let token = ctx
                .secrets
                .get("hysteria2.realm.token")
                .map(String::as_str)
                .unwrap_or("");
            let stun_servers: Vec<&str> = ctx
                .secrets
                .get("hysteria2.realm.stun_servers")
                .map(|s| {
                    s.split(',')
                        .map(str::trim)
                        .filter(|piece| !piece.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            // serde_json::Value::Object is mutated via as_object_mut —
            // safe because the literal above always builds an Object.
            if let Some(map) = inbound.as_object_mut() {
                map.insert(
                    "realm".to_string(),
                    json!({
                        "server_url": server_url,
                        "realm_id": realm_id,
                        "token": token,
                        "stun_servers": stun_servers,
                    }),
                );
            }
        }

        // Salamander obfuscation — XOR-based wire-level scrambling of
        // QUIC packets so DPI can't fingerprint the Hysteria 2 protocol.
        // This is the **anti-DPI** layer (Realm above is the
        // anti-IP-block layer; together they form the Hysteria
        // anti-censorship stack — Realm alone leaves the wire pattern
        // recognisable).
        //
        // Per https://hysteria.network/docs/advanced/Obfuscation/ +
        // https://sing-box.sagernet.org/configuration/inbound/hysteria2/.
        // Both inbound (server) AND outbound (client) MUST set the
        // SAME obfs password — it's a server-wide secret, not per-user
        // (the obfuscation happens BEFORE per-user auth in the QUIC
        // handshake). `client_config` and `share_link` mirror the
        // password automatically.
        //
        // Activation rule: emit IFF `hysteria2.obfs.password` is set
        // and non-empty after trim. We currently only support
        // `salamander` (the only type sing-box / upstream Hysteria 2
        // ships); the type field is hardcoded.
        if let Some(obfs_pw) = obfs_password(ctx) {
            if let Some(map) = inbound.as_object_mut() {
                map.insert(
                    "obfs".to_string(),
                    json!({ "type": "salamander", "password": obfs_pw }),
                );
            }
        }

        Ok(inbound)
    }

    fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<serde_json::Value> {
        let pw = user.tuic_password.as_deref().ok_or_else(|| {
            CoreError::Render(format!(
                "user '{}' has no tuic_password — cannot mint a Hysteria2 client config",
                user.id.0
            ))
        })?;
        let mut out = json!({
            "type": "hysteria2",
            "tag": "hy2-out",
            "server": ctx.server.address,
            "server_port": 8444,
            "password": pw,
            "tls": { "enabled": true, "insecure": true, "alpn": ["h3"] }
        });
        // Mirror the server-side obfs config — without it the client
        // can't even open the QUIC handshake against an obfs-enabled
        // server. Same secret, same ctx.
        if let Some(obfs_pw) = obfs_password(ctx) {
            if let Some(map) = out.as_object_mut() {
                map.insert(
                    "obfs".to_string(),
                    json!({ "type": "salamander", "password": obfs_pw }),
                );
            }
        }
        Ok(out)
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        // Per review-agent finding: `unwrap_or_default()` would emit
        // `hysteria2://@host/...` which clients parse fine but can't
        // authenticate — silent failure for the end user. Refuse instead.
        let raw_pw = user.tuic_password.as_deref().ok_or_else(|| {
            CoreError::Render(format!(
                "user '{}' has no tuic_password — cannot mint a Hysteria2 link",
                user.id.0
            ))
        })?;
        // Official URI scheme (https://hysteria.network/docs/developers/URI-Scheme/):
        //   hysteria2://<auth>@<host>:<port>/?sni=<sni>&insecure=1
        //   [&obfs=salamander&obfs-password=<pct-encoded>]
        // ALPN is negotiated at TLS handshake regardless; we skip it here.
        let pw = utf8_percent_encode(raw_pw, USERINFO);
        let name = utf8_percent_encode(&user.id.0, FRAGMENT);
        // Build the obfs query suffix when the server has it configured.
        // The query parameter name is `obfs-password` (with hyphen) per
        // the official URI scheme — NOT `obfsParam` or `obfs_password`.
        // Pinned by `h8_share_link_obfs_query_format`.
        let obfs_suffix = match obfs_password(ctx) {
            Some(opw) => {
                // QUERY set (not USERINFO) — values in URL query
                // position MUST escape `+` (form-decoders read as
                // space), `&` (would split into a new param), `=`
                // (would re-key). Pinned by `h8_share_link_obfs_query_format`.
                let opw_enc = utf8_percent_encode(opw, QUERY);
                format!("&obfs=salamander&obfs-password={opw_enc}")
            }
            None => String::new(),
        };
        // `host` is the URL authority host — IPv6 literals MUST be
        // bracketed here (RFC 3986). `sni` is a bare TLS server-name,
        // NOT a URL host, so it keeps the raw address: a bracketed SNI
        // would be wrong.
        Ok(format!(
            "hysteria2://{pw}@{host}:8444/?sni={sni}&insecure=1{obfs_suffix}#{name}",
            pw = pw,
            host = host_for_url(&ctx.server.address),
            sni = ctx.server.address,
            name = name,
            obfs_suffix = obfs_suffix,
        ))
    }
}

/// Read + trim the optional Salamander obfs password from
/// `RenderCtx::secrets`. Returns `None` for an absent OR
/// empty/whitespace-only secret — matches the realm-empty contract
/// (we don't activate optional features on a blank secret because
/// sing-box would only complain at deploy time).
fn obfs_password<'a>(ctx: &'a RenderCtx<'a>) -> Option<&'a str> {
    ctx.secrets
        .get("hysteria2.obfs.password")
        .map(String::as_str)
        .filter(|s| !s.trim().is_empty())
}
