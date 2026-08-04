use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde_json::json;
use vpnctl_core::url_host::host_for_url;
use vpnctl_core::{Protocol, ProtocolId, RenderCtx, Result, User};

/// Set of bytes that must be percent-encoded in URL fragments (RFC 3986):
/// everything that controls URL parsing, plus space/`#`/`?` which would
/// otherwise truncate or open a new component.
const FRAGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'#')
    .add(b'?')
    .add(b'/')
    .add(b'@')
    .add(b':');

/// uTLS ClientHello fingerprint the client mimics for the REALITY handshake.
///
/// Was `"chrome"` (matched legacy `get-vless.sh`). Switched to `"randomized"`
/// on 2026-06-16: RU mobile/broadband DPI (TSPU) began fingerprinting the
/// fixed Chrome uTLS ClientHello and RST-resetting REALITY sessions — clients
/// that emit it (v2rayTun/Xray, Streisand/sing-box) stopped connecting while
/// Shadowrocket (its own ClientHello) kept working. Field-confirmed with
/// multiviruss: same is/REALITY config failed on `fp=chrome`, connected on
/// `fp=randomized`. `randomized` makes each handshake a fresh randomized
/// ClientHello, defeating the static-fingerprint rule. Validated against
/// sing-box 1.13.12 (`sing-box check`) and Xray-core 26.3.27 (both accept it).
///
/// `pub(crate)` so `vless_xhttp` reuses this exact value instead of
/// duplicating the literal.
pub(crate) const REALITY_UTLS_FP: &str = "randomized";

/// Default REALITY dest / `serverName` when the server carries no explicit
/// `vless.sni` secret.
///
/// Was `"www.microsoft.com"` (matched legacy `get-vless.sh`). Switched to
/// `"yahoo.com"` on 2026-06-25 after an A/B from a RU network proved
/// `www.microsoft.com` is a **fragile** REALITY dest: REALITY's TLS "steal"
/// only completes for the `randomized` uTLS ClientHello — `firefox`/`chrome`
/// ClientHellos get EOF (microsoft's TLS server does something REALITY can't
/// relay — HRR / cert-chain / extension mismatch — for those profiles).
/// `yahoo.com` is permissive → robust to **every** fingerprint, matching the
/// proven 3x-ui config on the same nl box. Many clients (v2RayTun/Xray-family,
/// the ninitux app) don't honour `randomized` or let the user pick chrome/
/// firefox, so a microsoft dest silently broke them; yahoo sidesteps it.
///
/// This is the **default only** — `vless.sni` is per-server secret material,
/// so a server that needs byte-identical legacy behaviour (e.g. a phone
/// holding a cached bash `sni=www.microsoft.com` link) can pin microsoft
/// explicitly. See `vless_explicit_microsoft_sni_byte_equal_with_bash_scripts`
/// in `spec_share_link_byte_equality.rs`.
pub const DEFAULT_REALITY_SNI: &str = "yahoo.com";

/// VLESS + REALITY на TCP:443.
///
/// **Stateless**: ключи REALITY и SNI приходят через [`RenderCtx::secrets`]
/// — это позволяет одной инстанции жить в `Registry` и работать с любым
/// сервером, секреты которого хранятся в `inventory::server_secrets`.
///
/// Конвенция ключей:
///
/// - `vless.private_key` (required) — REALITY x25519 private (base64-url-no-pad)
/// - `vless.public_key`  (required) — REALITY x25519 public  (base64-url-no-pad)
/// - `vless.short_id`    (required) — REALITY short ID (8 hex)
/// - `vless.sni`         (optional, default [`DEFAULT_REALITY_SNI`] = `yahoo.com`)
#[derive(Debug, Default)]
pub struct VlessReality;

impl VlessReality {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for VlessReality {
    fn id(&self) -> ProtocolId {
        ProtocolId("vless+reality".to_string())
    }

    fn dpi_risk(&self) -> vpnctl_core::DpiRisk {
        // REALITY serves a real TLS handshake to a real upstream
        // (`dest:` SNI, default yahoo.com — see DEFAULT_REALITY_SNI); any
        // probe that doesn't carry valid VLESS-flow auth gets transparently
        // forwarded to that upstream, so DPI sees authentic upstream HTML
        // and cannot distinguish our server from a real visitor.
        // This is the gold-standard 2026 anti-probing posture.
        vpnctl_core::DpiRisk::Strong
    }

    fn server_secret_specs(&self) -> Vec<vpnctl_core::ServerSecretSpec> {
        use vpnctl_core::ServerSecretSpec::{ShortId, X25519Keypair};
        // REALITY x25519 keypair + 8-byte short_id — the same crypto
        // primitives the bash vpn-control minted, byte-for-byte.
        vec![
            X25519Keypair {
                private_key: "vless.private_key",
                public_key: "vless.public_key",
            },
            ShortId {
                key: "vless.short_id",
            },
        ]
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        // Default REALITY cover port. Per-server `vless.listen_port`
        // override is honoured by `effective_listen_ports` below.
        &[("tcp", 443)]
    }

    fn effective_listen_ports(
        &self,
        secrets: &std::collections::HashMap<String, String>,
    ) -> Vec<(&'static str, u16)> {
        // Mirror the `server_inbound` / `client_config` / `share_link`
        // override semantics EXACTLY: parse `vless.listen_port`, fall back
        // to the gold-standard 443 on absence or a typo. Keeping the
        // firewall step, the port-conflict guard and the drift table in
        // sync with what sing-box actually binds is the whole point —
        // cdn incident 2026-08-05: reality moved to 8443 via the override
        // while ufw + drift still assumed the static default, so the port
        // was firewalled and the admin table showed «no fixed port».
        let port: u16 = secrets
            .get("vless.listen_port")
            .and_then(|s| s.parse().ok())
            .unwrap_or(443);
        vec![("tcp", port)]
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<serde_json::Value> {
        let private_key = ctx.require("vless.private_key")?;
        let short_id = ctx.require("vless.short_id")?;
        let sni = ctx.or_default("vless.sni", DEFAULT_REALITY_SNI);
        // Per-server listen port override (post-2026-05-26). Default
        // 443 is the gold-standard cover (looks like real HTTPS),
        // but on a co-tenant host where :443 is owned by a legacy
        // 3x-ui Docker container, vpnctl needs to bind elsewhere.
        // Operator sets `vless.listen_port` server-secret to e.g.
        // `8443`; invalid values fall through to 443 so a typo
        // never silently drops the inbound to port 0.
        let listen_port: u16 = ctx
            .secrets
            .get("vless.listen_port")
            .and_then(|s| s.parse().ok())
            .unwrap_or(443);

        // XTLS-Vision sub-protocol is the **required** flow for VLESS +
        // REALITY in modern sing-box (≥ 1.4): without it the client
        // either gets a 400-style handshake reject ("flow not match") or
        // falls back to plain TLS proxying, defeating the REALITY
        // anti-DPI cover. Pinned to a string so a typo here surfaces in
        // `vless_server_inbound_user_carries_xtls_vision_flow` — caught
        // during vps-is-01 import (the bash-vpn-control deploys all set
        // `xtls-rprx-vision` and migrated clients would handshake-fail
        // without it).
        let users_json: Vec<_> = users
            .iter()
            .map(|u| {
                json!({
                    "uuid": u.uuid,
                    "name": u.id.0,
                    "flow": "xtls-rprx-vision",
                })
            })
            .collect();

        Ok(json!({
            "type": "vless",
            "tag": "vless-in",
            "listen": "::",
            "listen_port": listen_port,
            "users": users_json,
            "tls": {
                "enabled": true,
                "server_name": sni,
                "reality": {
                    "enabled": true,
                    "handshake": { "server": sni, "server_port": 443 },
                    "private_key": private_key,
                    "short_id": [short_id]
                }
            }
        }))
    }

    fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<serde_json::Value> {
        let public_key = ctx.require("vless.public_key")?;
        let short_id = ctx.require("vless.short_id")?;
        let sni = ctx.or_default("vless.sni", DEFAULT_REALITY_SNI);
        let server_port: u16 = ctx
            .secrets
            .get("vless.listen_port")
            .and_then(|s| s.parse().ok())
            .unwrap_or(443);

        // Mirror the server's `xtls-rprx-vision` flow — server REJECTS
        // sessions whose flow doesn't match the user-record's flow.
        // In sing-box outbound the `flow` field sits at the top level
        // next to `uuid` (per https://sing-box.sagernet.org/configuration/outbound/vless/).
        Ok(json!({
            "type": "vless",
            "tag": "vless-out",
            "server": ctx.server.address,
            "server_port": server_port,
            "uuid": user.uuid,
            "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": true,
                "server_name": sni,
                "utls": { "enabled": true, "fingerprint": REALITY_UTLS_FP },
                "reality": {
                    "enabled": true,
                    "public_key": public_key,
                    "short_id": short_id
                }
            }
        }))
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        let public_key = ctx.require("vless.public_key")?;
        let short_id = ctx.require("vless.short_id")?;
        let sni = ctx.or_default("vless.sni", DEFAULT_REALITY_SNI);
        let port: u16 = ctx
            .secrets
            .get("vless.listen_port")
            .and_then(|s| s.parse().ok())
            .unwrap_or(443);
        // user.id.0 lands in the URL fragment (`#name`) where chars like
        // `#`, ` `, `/` would corrupt the link or open a new component.
        // Percent-encode defensively even though server/CLI validate ids.
        let name = utf8_percent_encode(&user.id.0, FRAGMENT);
        // Parameter order + included params are pinned to match the
        // legacy bash `vpn-control/scripts/get-vless.sh` byte-for-byte:
        //   `?encryption=none&flow=xtls-rprx-vision&security=reality&sni=...&fp=<REALITY_UTLS_FP>&pbk=...&sid=...&type=tcp`
        // (the `fp` value is no longer the bash `chrome` literal — see
        // `REALITY_UTLS_FP` for the 2026-06-16 DPI-evasion switch.)
        // (caught by Pavel's methodology check on db3998c — comparison
        // against the actual bash script showed mine was missing
        // `encryption=none` AND used a different param order, both
        // breaking the "Migration from bash — seamless preservation"
        // requirement in CLAUDE.md). The seven query params are pinned
        // verbatim in `vless_happy_path_byte_equal`.
        //
        // The `:443` in the link is the default — when `vless.listen_port`
        // is set on the server-secrets (3x-ui-coexistence case), the
        // alternate port substitutes in. Byte-equality test stays green
        // because it uses the default secrets (no listen_port override).
        Ok(format!(
            "vless://{uuid}@{addr}:{port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni={sni}&fp={fp}&pbk={pbk}&sid={sid}&type=tcp#{name}",
            uuid = user.uuid,
            addr = host_for_url(&ctx.server.address),
            fp = REALITY_UTLS_FP,
            pbk = public_key,
            sid = short_id,
            sni = sni,
            name = name,
        ))
    }
}
