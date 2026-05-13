use serde_json::json;
use vpnctl_core::{Protocol, ProtocolId, Result, Server, User};

/// VLESS + REALITY на TCP:443. SNI по умолчанию — `www.microsoft.com`.
#[derive(Debug, Clone)]
pub struct VlessReality {
    pub sni: String,
    pub short_id: String,
    pub public_key: String,
    pub private_key: String,
}

impl VlessReality {
    pub fn new(sni: String, short_id: String, public_key: String, private_key: String) -> Self {
        Self {
            sni,
            short_id,
            public_key,
            private_key,
        }
    }
}

impl Protocol for VlessReality {
    fn id(&self) -> ProtocolId {
        ProtocolId("vless+reality".to_string())
    }

    fn server_inbound(&self, users: &[User]) -> Result<serde_json::Value> {
        let users_json: Vec<_> = users
            .iter()
            .map(|u| json!({ "uuid": u.uuid, "name": u.id.0, "flow": "" }))
            .collect();
        Ok(json!({
            "type": "vless",
            "tag": "vless-in",
            "listen": "::",
            "listen_port": 443,
            "users": users_json,
            "tls": {
                "enabled": true,
                "server_name": self.sni,
                "reality": {
                    "enabled": true,
                    "handshake": { "server": self.sni, "server_port": 443 },
                    "private_key": self.private_key,
                    "short_id": [self.short_id]
                }
            }
        }))
    }

    fn client_config(&self, server: &Server, user: &User) -> Result<serde_json::Value> {
        Ok(json!({
            "type": "vless",
            "tag": "vless-out",
            "server": server.address,
            "server_port": 443,
            "uuid": user.uuid,
            "tls": {
                "enabled": true,
                "server_name": self.sni,
                "utls": { "enabled": true, "fingerprint": "chrome" },
                "reality": {
                    "enabled": true,
                    "public_key": self.public_key,
                    "short_id": self.short_id
                }
            }
        }))
    }

    fn share_link(&self, server: &Server, user: &User) -> Result<String> {
        Ok(format!(
            "vless://{uuid}@{addr}:443?type=tcp&security=reality&pbk={pbk}&sid={sid}&sni={sni}&fp=chrome#{name}",
            uuid = user.uuid,
            addr = server.address,
            pbk = self.public_key,
            sid = self.short_id,
            sni = self.sni,
            name = user.id.0
        ))
    }
}
