use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde_json::json;
use vpnctl_core::{Protocol, ProtocolId, RenderCtx, Result, User};

/// Userinfo-safe set: everything that has a structural meaning in
/// `<userinfo>@<host>` of an authority component (RFC 3986 §3.2.1).
const USERINFO: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
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
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'#')
    .add(b'?');

/// TUIC v5 на UDP:8443. Self-signed cert — на клиенте `insecure: true`
/// (UUID+password — настоящая аутентификация, TLS чисто для шифрования).
///
/// **Stateless**: пути к сертификатам приходят через [`RenderCtx::secrets`].
///
/// Конвенция ключей:
///
/// - `tuic.cert_path` (optional, default `/etc/sing-box/cert.pem`)
/// - `tuic.key_path`  (optional, default `/etc/sing-box/key.pem`)
#[derive(Debug, Default)]
pub struct TuicV5;

impl TuicV5 {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for TuicV5 {
    fn id(&self) -> ProtocolId {
        ProtocolId("tuic-v5".to_string())
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<serde_json::Value> {
        let cert_path = ctx.or_default("tuic.cert_path", "/etc/sing-box/cert.pem");
        let key_path = ctx.or_default("tuic.key_path", "/etc/sing-box/key.pem");

        let users_json: Vec<_> = users
            .iter()
            .filter_map(|u| {
                u.tuic_password
                    .as_ref()
                    .map(|pw| json!({ "uuid": u.uuid, "name": u.id.0, "password": pw }))
            })
            .collect();

        Ok(json!({
            "type": "tuic",
            "tag": "tuic-in",
            "listen": "::",
            "listen_port": 8443,
            "congestion_control": "bbr",
            "users": users_json,
            "tls": {
                "enabled": true,
                "alpn": ["h3"],
                "certificate_path": cert_path,
                "key_path": key_path,
            }
        }))
    }

    fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<serde_json::Value> {
        Ok(json!({
            "type": "tuic",
            "tag": "tuic-out",
            "server": ctx.server.address,
            "server_port": 8443,
            "uuid": user.uuid,
            "password": user.tuic_password.clone().unwrap_or_default(),
            "congestion_control": "bbr",
            "udp_relay_mode": "native",
            "tls": { "enabled": true, "insecure": true, "alpn": ["h3"] }
        }))
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        let raw_pw = user.tuic_password.clone().unwrap_or_default();
        // Both UUID and password sit inside the userinfo segment, where `:`,
        // `@`, `/`, and space would corrupt parsing. Name sits in the fragment.
        let uuid = utf8_percent_encode(&user.uuid, USERINFO);
        let pw = utf8_percent_encode(&raw_pw, USERINFO);
        let name = utf8_percent_encode(&user.id.0, FRAGMENT);
        Ok(format!(
            "tuic://{uuid}:{pw}@{addr}:8443?congestion_control=bbr&alpn=h3&allow_insecure=1#{name}",
            uuid = uuid,
            pw = pw,
            addr = ctx.server.address,
            name = name,
        ))
    }
}
