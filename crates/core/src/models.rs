use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use crate::error::{CoreError, Result};
use crate::id::{KernelId, ProtocolId, ServerId, UserId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    pub id: ServerId,
    pub address: String,
    pub ssh_port: u16,
    pub ssh_user: String,
    pub kernels: Vec<KernelId>,
    pub enabled_protocols: Vec<ProtocolId>,
    #[serde(default)]
    pub trusted_host_fingerprint: Option<String>,
    #[serde(default = "default_hoster")]
    pub hoster: String,
    #[serde(default)]
    pub jump_via: Option<ServerId>,
    #[serde(default = "default_usage_coefficient")]
    pub usage_coefficient: f64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedJumpRoute {
    pub host: String,
    pub user: String,
    pub port: u16,
    pub jump_fingerprint: String,
    pub target_fingerprint: String,
}

fn default_hoster() -> String {
    "generic".to_string()
}
fn default_usage_coefficient() -> f64 {
    1.0
}

#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub uuid: String,
    #[serde(skip_serializing, default)]
    pub tuic_password: Option<String>,
    pub wireguard_pubkey: Option<String>,
    #[serde(skip_serializing, default)]
    pub wireguard_private: Option<String>,
    #[serde(skip_serializing, default)]
    pub sub_token: Option<String>,
    #[serde(skip_serializing, default)]
    pub vpn_router_device_id: Option<String>,
    #[serde(default)]
    pub disabled: bool,
}

impl User {
    #[must_use]
    pub fn with_per_server_uuid(&self, new_uuid: &str) -> Self {
        let mut out = self.clone();
        out.uuid = new_uuid.to_string();
        out
    }
}

impl fmt::Debug for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("uuid", &self.uuid)
            .field(
                "tuic_password",
                &self.tuic_password.as_ref().map(|_| "<redacted>"),
            )
            .field("wireguard_pubkey", &self.wireguard_pubkey)
            .field(
                "wireguard_private",
                &self.wireguard_private.as_ref().map(|_| "<redacted>"),
            )
            .field("sub_token", &self.sub_token.as_ref().map(|_| "<redacted>"))
            .field(
                "vpn_router_device_id",
                &self.vpn_router_device_id.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Debug)]
pub struct RenderCtx<'a> {
    pub server: &'a Server,
    pub secrets: &'a HashMap<String, String>,
    pub peers: &'a [User],
}

impl<'a> RenderCtx<'a> {
    pub fn new(server: &'a Server, secrets: &'a HashMap<String, String>) -> Self {
        Self {
            server,
            secrets,
            peers: &[],
        }
    }

    pub fn with_peers(
        server: &'a Server,
        secrets: &'a HashMap<String, String>,
        peers: &'a [User],
    ) -> Self {
        Self {
            server,
            secrets,
            peers,
        }
    }

    pub fn require(&self, key: &str) -> Result<&str> {
        self.secrets
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| CoreError::MissingSecret {
                server: self.server.id.clone(),
                key: key.to_string(),
            })
    }

    pub fn or_default<'b>(&'b self, key: &str, default: &'b str) -> &'b str {
        self.secrets.get(key).map(String::as_str).unwrap_or(default)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod user_secret_redaction {
    use super::*;

    fn loaded_user() -> User {
        User {
            id: UserId("alice".into()),
            uuid: "uuid-public-not-secret".into(),
            tuic_password: Some("PW_TUIC_MUST_NOT_LEAK".into()),
            wireguard_pubkey: Some("PUBKEY_OK_TO_PRINT_44CHARS_ENDING_EQ_VALUEAA=".into()),
            wireguard_private: Some("PRIV_WG_MUST_NOT_LEAK".into()),
            sub_token: Some("SUB_TOKEN_MUST_NOT_LEAK".into()),
            vpn_router_device_id: Some("DEVICE_ID_MUST_NOT_LEAK_a92b915".into()),
            disabled: false,
        }
    }

    #[test]
    fn user_debug_redacts_all_secret_fields() {
        let dbg = format!("{:?}", loaded_user());
        for forbidden in [
            "PW_TUIC_MUST_NOT_LEAK",
            "PRIV_WG_MUST_NOT_LEAK",
            "SUB_TOKEN_MUST_NOT_LEAK",
            "DEVICE_ID_MUST_NOT_LEAK",
        ] {
            assert!(!dbg.contains(forbidden), "Debug leaked {forbidden}: {dbg}");
        }
        assert!(
            dbg.contains("<redacted>"),
            "expected redaction marker: {dbg}"
        );
        assert!(dbg.contains("alice"));
        assert!(dbg.contains("PUBKEY_OK_TO_PRINT"));
    }

    #[test]
    fn user_serialize_skips_all_secret_fields() {
        let json = serde_json::to_string(&loaded_user()).unwrap();
        for forbidden in [
            "PW_TUIC_MUST_NOT_LEAK",
            "PRIV_WG_MUST_NOT_LEAK",
            "SUB_TOKEN_MUST_NOT_LEAK",
            "DEVICE_ID_MUST_NOT_LEAK",
            "tuic_password",
            "wireguard_private",
            "sub_token",
            "vpn_router_device_id",
        ] {
            assert!(
                !json.contains(forbidden),
                "Serialize leaked {forbidden}: {json}"
            );
        }
        assert!(json.contains("alice"));
        assert!(json.contains("PUBKEY_OK_TO_PRINT"));
    }
}
