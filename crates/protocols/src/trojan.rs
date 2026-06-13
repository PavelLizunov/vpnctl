use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde_json::json;
use vpnctl_core::url_host::host_for_url;
use vpnctl_core::{CoreError, Protocol, ProtocolId, RenderCtx, Result, User};

/// Trojan — venerable TLS-mimic protocol. Predates REALITY, simpler
/// than AnyTLS, fits as a third "TLS-looking" channel when an
/// operator wants maximum protocol diversity on a node.
///
/// **Why ship it:** widely-deployed and well-understood; many older
/// VPN clients ship Trojan support but not REALITY/AnyTLS. Adds
/// another channel without significant cost.
///
/// **Sing-box version:** any (Trojan has been in sing-box since
/// v0.1; no version concern).
///
/// **Per-user secret:** reuses `User.tuic_password` as the Trojan
/// password. Same trade-off as Hysteria2/AnyTLS: leak in any
/// client compromises all sibling protocols using that secret.
///
/// **TLS cert paths:** reuses `tuic.cert_path` / `tuic.key_path`.
/// One self-signed cert per node, shared across TUIC/Hy2/AnyTLS/Trojan.
///
/// **Port:** TCP 8643. Convention rolls forward —
/// 443/TCP=VLESS+REALITY, 8443/UDP=TUIC, 8444/UDP=Hy2, 8843/TCP=AnyTLS,
/// 8643/TCP=Trojan. Could move to 443 if operator drops REALITY on
/// a node.
///
/// **Stateless**, like every other Protocol in this crate.
#[derive(Debug, Default)]
pub struct Trojan;

impl Trojan {
    pub fn new() -> Self {
        Self
    }
}

/// Listen port. Public so admin's drift detector can recognize the
/// inbound on a probe.
pub const TROJAN_PORT: u16 = 8643;

/// Percent-encode set for the password embedded in the URI auth.
/// Same shape as Hysteria2/AnyTLS USERINFO.
const USERINFO: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'@')
    .add(b'/')
    .add(b':')
    .add(b'\\')
    .add(b'[')
    .add(b']');

const FRAGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'#')
    .add(b'?');

impl Protocol for Trojan {
    fn id(&self) -> ProtocolId {
        ProtocolId("trojan".to_string())
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[("tcp", TROJAN_PORT)]
    }

    fn dpi_risk(&self) -> vpnctl_core::DpiRisk {
        // Our Trojan inbound serves a self-signed cert with NO
        // `fallback:` upstream (see `server_inbound` below — only
        // `tls.certificate_path` + `tls.key_path`, no fallback).
        // Active TLS probe → self-signed cert without a real serving
        // website behind it → textbook "Trojan-without-fallback"
        // fingerprint blocked in RU/CN since 2022. Without a real
        // upstream this protocol is no better than raw SS-2022 in a
        // probing environment. Review-agent NM-12: «active TLS probes
        // get a self-signed cert with no real HTML behind it».
        //
        // To upgrade to Moderate/Strong: wire a real nginx fallback
        // on 443 + plumb its address into `tls.fallback.server` and
        // document the operator burden.
        vpnctl_core::DpiRisk::Weak
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<serde_json::Value> {
        let cert_path = ctx.or_default("tuic.cert_path", "/etc/sing-box/cert.pem");
        let key_path = ctx.or_default("tuic.key_path", "/etc/sing-box/key.pem");

        let users_json: Vec<_> = users
            .iter()
            .filter_map(|u| {
                u.tuic_password
                    .as_ref()
                    .map(|pw| json!({ "name": u.id.0, "password": pw }))
            })
            .collect();

        Ok(json!({
            "type": "trojan",
            "tag": "trojan-in",
            "listen": "::",
            "listen_port": TROJAN_PORT,
            "users": users_json,
            "tls": {
                "enabled": true,
                "certificate_path": cert_path,
                "key_path": key_path,
            }
        }))
    }

    fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<serde_json::Value> {
        let pw = user.tuic_password.as_deref().ok_or_else(|| {
            CoreError::Render(format!(
                "user '{}' has no tuic_password — cannot mint a Trojan client config",
                user.id.0
            ))
        })?;
        Ok(json!({
            "type": "trojan",
            "tag": "trojan-out",
            "server": ctx.server.address,
            "server_port": TROJAN_PORT,
            "password": pw,
            "tls": { "enabled": true, "insecure": true }
        }))
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        let raw_pw = user.tuic_password.as_deref().ok_or_else(|| {
            CoreError::Render(format!(
                "user '{}' has no tuic_password — cannot mint a Trojan link",
                user.id.0
            ))
        })?;
        // Trojan URI scheme (de-facto standard, widely supported):
        //   trojan://<password>@<host>:<port>?sni=<sni>&allowInsecure=1#<tag>
        // Note `allowInsecure` (camelCase), NOT `insecure` — Trojan
        // clients historically use this parameter name; switching to
        // `insecure` would break older clients silently.
        let pw = utf8_percent_encode(raw_pw, USERINFO);
        let name = utf8_percent_encode(&user.id.0, FRAGMENT);
        // `host` is the URL authority host — IPv6 literals MUST be
        // bracketed here (RFC 3986). `sni` is a bare TLS server-name,
        // NOT a URL host, so it keeps the raw address.
        Ok(format!(
            "trojan://{pw}@{host}:{port}?sni={sni}&allowInsecure=1#{name}",
            pw = pw,
            host = host_for_url(&ctx.server.address),
            sni = ctx.server.address,
            port = TROJAN_PORT,
            name = name,
        ))
    }
}
