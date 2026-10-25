use std::collections::HashMap;
use std::fmt;

use crate::error::Result;
use crate::id::ProtocolId;
use crate::models::{RenderCtx, User};

pub trait Protocol: fmt::Debug + Send + Sync {
    fn id(&self) -> ProtocolId;

    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<serde_json::Value>;

    fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<serde_json::Value>;

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String>;

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[]
    }

    fn effective_listen_ports(
        &self,
        _secrets: &HashMap<String, String>,
    ) -> Vec<(&'static str, u16)> {
        self.listen_ports().to_vec()
    }

    fn appears_in_sing_box_sub(&self) -> bool {
        true
    }

    fn appears_in_stock_sing_box_sub(&self) -> bool {
        self.appears_in_sing_box_sub()
    }

    fn dpi_risk(&self) -> DpiRisk {
        DpiRisk::Moderate
    }

    fn validate_server(&self, _ctx: &RenderCtx<'_>) -> Result<()> {
        Ok(())
    }

    fn server_secret_specs_for(
        &self,
        _secrets: &HashMap<String, String>,
    ) -> Result<Vec<ServerSecretSpec>> {
        Ok(self.server_secret_specs())
    }

    fn server_secret_specs(&self) -> Vec<ServerSecretSpec> {
        Vec::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerSecretSpec {
    Password {
        key: &'static str,
        entropy_bytes: usize,
    },
    Base64Key {
        key: &'static str,
        key_bytes: usize,
    },
    X25519Keypair {
        private_key: &'static str,
        public_key: &'static str,
    },
    WireguardKeypair {
        private_key: &'static str,
        public_key: &'static str,
    },
    ShortId {
        key: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpiRisk {
    Strong,
    Moderate,
    Weak,
}

impl DpiRisk {
    pub fn label(self) -> &'static str {
        match self {
            DpiRisk::Strong => "DPI: strong",
            DpiRisk::Moderate => "DPI: moderate",
            DpiRisk::Weak => "DPI: weak",
        }
    }

    pub fn tooltip(self) -> &'static str {
        match self {
            DpiRisk::Strong => {
                "Active-probe-resistant: TLS handshake to a real upstream / no fixed wire signature. Recommended."
            }
            DpiRisk::Moderate => {
                "Recognisable on careful active probing (QUIC version, AEAD-on-port-N) but not trivially blocked. Useful as a fallback."
            }
            DpiRisk::Weak => {
                "Trivially fingerprintable in RU/IR/CN 2026 (Shadowsocks high-entropy first byte, raw WireGuard 0x01 handshake tag, Trojan-without-fallback self-signed cert, Hysteria2 on legacy servers that lack the Salamander obfs secret — re-deploy mints it). Consider hiding via NM-10."
            }
        }
    }

    pub fn border_css(self) -> &'static str {
        match self {
            DpiRisk::Strong => "var(--acc-good, #2c5f2d)",
            DpiRisk::Moderate => "var(--rule)",
            DpiRisk::Weak => "var(--acc-bad, #97233f)",
        }
    }

    pub fn text_css(self) -> &'static str {
        match self {
            DpiRisk::Strong => "var(--acc-good, #2c5f2d)",
            DpiRisk::Moderate => "var(--mute)",
            DpiRisk::Weak => "var(--acc-bad, #97233f)",
        }
    }
}
