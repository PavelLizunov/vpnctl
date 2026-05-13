use serde_json::json;
use vpnctl_core::{Protocol, ProtocolId, Result, Server, User};

/// TUIC v5 на UDP:8443. Self-signed cert — на клиенте `insecure: true`.
pub struct TuicV5;

impl TuicV5 {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TuicV5 {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for TuicV5 {
    fn id(&self) -> ProtocolId {
        ProtocolId("tuic-v5".to_string())
    }

    fn server_inbound(&self, users: &[User]) -> Result<serde_json::Value> {
        let users_json: Vec<_> = users
            .iter()
            .filter_map(|u| {
                u.tuic_password.as_ref().map(|pw| {
                    json!({ "uuid": u.uuid, "name": u.id.0, "password": pw })
                })
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
                "certificate_path": "/etc/sing-box/cert.pem",
                "key_path": "/etc/sing-box/key.pem"
            }
        }))
    }

    fn client_config(&self, server: &Server, user: &User) -> Result<serde_json::Value> {
        Ok(json!({
            "type": "tuic",
            "tag": "tuic-out",
            "server": server.address,
            "server_port": 8443,
            "uuid": user.uuid,
            "password": user.tuic_password.clone().unwrap_or_default(),
            "congestion_control": "bbr",
            "udp_relay_mode": "native",
            "tls": { "enabled": true, "insecure": true, "alpn": ["h3"] }
        }))
    }

    fn share_link(&self, server: &Server, user: &User) -> Result<String> {
        Ok(format!(
            "tuic://{uuid}:{pw}@{addr}:8443?congestion_control=bbr&alpn=h3&allow_insecure=1#{name}",
            uuid = user.uuid,
            pw = user.tuic_password.clone().unwrap_or_default(),
            addr = server.address,
            name = user.id.0
        ))
    }
}
