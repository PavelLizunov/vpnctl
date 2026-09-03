use crate::encoding::{FRAGMENT, USERINFO};
use percent_encoding::utf8_percent_encode;
use serde_json::json;
use vpnctl_core::url_host::host_for_url;
use vpnctl_core::{CoreError, Protocol, ProtocolId, RenderCtx, Result, User};

/// AnyTLS — TCP/TLS multiplexed proxy designed as a REALITY
/// successor for networks where TLS-mimic gets DPI'd despite
/// proper SNI handshake.
///
/// **Why ship this:** different fingerprint from VLESS+REALITY.
/// AnyTLS uses standard TLS 1.3 handshake with operator-configurable
/// SNI but ADDS a stream-multiplexing layer on top — when DPI
/// pattern-matches on REALITY's specific timing/sizes, AnyTLS
/// presents a different shape. Useful as fallback when REALITY
/// gets detected on a given network.
///
/// **Sing-box version:** requires ≥ 1.12.0. Our staging runs
/// 1.13.11 — fine. Older nodes deployed before this commit need
/// upgrade (sing-box check rejects unknown `type` at deploy time
/// so fails loud, not silent).
///
/// **Per-user secret:** same trade-off as Hysteria2 — reuses
/// `User.tuic_password` as the AnyTLS password. A leak in any
/// of {TUIC, Hysteria2, AnyTLS} clients compromises all three.
/// Acceptable in v0.4.x; a future `User.anytls_password` would
/// be pure-additive when needed.
///
/// **TLS cert paths:** reuses `tuic.cert_path` / `tuic.key_path`
/// from `RenderCtx::secrets`. One self-signed cert per node,
/// shared across TUIC/Hysteria2/AnyTLS.
///
/// **Port:** TCP 8843. Convention: TUIC=8443/UDP, Hy2=8444/UDP,
/// AnyTLS=8843/TCP. Could move to 443 (real-HTTPS mimic) when
/// VLESS+REALITY isn't already there.
///
/// **Stateless**, like every other Protocol in this crate.
#[derive(Debug, Default)]
pub struct AnyTls;

impl AnyTls {
    pub fn new() -> Self {
        Self
    }
}

/// Listen port. Public so tests can format share-links + admin UI
/// can format expected-port drift checks without duplicating the
/// literal.
pub const ANYTLS_PORT: u16 = 8843;

impl Protocol for AnyTls {
    fn id(&self) -> ProtocolId {
        ProtocolId("anytls".to_string())
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[("tcp", ANYTLS_PORT)]
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<serde_json::Value> {
        let cert_path = ctx.or_default("tuic.cert_path", "/etc/sing-box/cert.pem");
        let key_path = ctx.or_default("tuic.key_path", "/etc/sing-box/key.pem");

        // Per-user: skip users without tuic_password (same convention
        // as Hysteria2's `server_inbound`). AnyTLS needs at least
        // one user or sing-box rejects the inbound; the wider config
        // assembly handles "no users at all on this server" by not
        // emitting the inbound — protocol-level we just produce
        // whatever the user list contains.
        let users_json: Vec<_> = users
            .iter()
            .filter_map(|u| {
                u.tuic_password
                    .as_ref()
                    .map(|pw| json!({ "name": u.id.0, "password": pw }))
            })
            .collect();

        Ok(json!({
            "type": "anytls",
            "tag": "anytls-in",
            "listen": "::",
            "listen_port": ANYTLS_PORT,
            "users": users_json,
            "tls": {
                "enabled": true,
                "certificate_path": cert_path,
                "key_path": key_path,
            }
        }))
    }

    fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<serde_json::Value> {
        // Consistent with `share_link`: refuse to mint a client config
        // with an empty password — the client would auth-fail anyway,
        // and surfacing as Render error gives the operator a clear
        // signal vs. silently producing a broken JSON. (Review-agent
        // finding: previous impl returned empty-string password, two
        // different behaviours for the same missing-secret case.)
        let pw = user.tuic_password.as_deref().ok_or_else(|| {
            CoreError::Render(format!(
                "user '{}' has no tuic_password — cannot mint an AnyTLS client config",
                user.id.0
            ))
        })?;
        Ok(json!({
            "type": "anytls",
            "tag": "anytls-out",
            "server": ctx.server.address,
            "server_port": ANYTLS_PORT,
            "password": pw,
            "tls": { "enabled": true, "insecure": true }
        }))
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        // Same hard-error split as Hysteria2: a user with no auth
        // material can't authenticate, so minting a link would be
        // a silent failure.
        let raw_pw = user.tuic_password.as_deref().ok_or_else(|| {
            CoreError::Render(format!(
                "user '{}' has no tuic_password — cannot mint an AnyTLS link",
                user.id.0
            ))
        })?;
        // Official URI scheme (anytls/anytls-go docs/uri_scheme.md):
        //   anytls://<auth>@<host>[:<port>]/?sni=<sni>&insecure=1
        // sni=<address> + insecure=1 because we use a self-signed cert.
        let pw = utf8_percent_encode(raw_pw, USERINFO);
        let name = utf8_percent_encode(&user.id.0, FRAGMENT);
        // `host` is the URL authority host — IPv6 literals MUST be
        // bracketed here (RFC 3986). `sni` is a bare TLS server-name,
        // NOT a URL host, so it keeps the raw address.
        Ok(format!(
            "anytls://{pw}@{host}:{port}/?sni={sni}&insecure=1#{name}",
            pw = pw,
            host = host_for_url(&ctx.server.address),
            sni = ctx.server.address,
            port = ANYTLS_PORT,
            name = name,
        ))
    }
}
