//! wgturn protocol — companion to the `wgturn` kernel.
//!
//! The wgturn-core daemon (see `crates/kernels/src/wgturn.rs`) hosts
//! a custom wire format combining a VK-TURN-relayed transport with a
//! WireGuard backend. The client URL format is `wgturn://...` and
//! mirrors upstream's `pkg/wgshare` encoder.
//!
//! ## Phase 1 (this commit) — stub only
//!
//! `share_link` returns a `CoreError::Render` explaining that offline
//! generation is not yet implemented. Until the `pkg/wgshare` Go
//! encoder is ported to Rust, per-user provisioning happens by SSHing
//! to the VPN server and running:
//!
//! ```text
//! wgturn-cli provision-url --vk-link '<https://vk.com/call/join/...>'
//! ```
//!
//! …which prints a fresh `wgturn://` URL. The admin UI surfaces a
//! «provision via SSH» button that shells out via the daemon's own
//! SSH transport (no operator-facing manual shell — CLAUDE.md
//! «operator-action policy»).
//!
//! ## Phase 2 (next session)
//!
//! Port `pkg/wgshare`'s URL encoder so `share_link` can generate the
//! URL from `RenderCtx::secrets` (server VK link + ephemeral session
//! ID + per-user WireGuard keypair) without a server round-trip. The
//! protocol stays stateless — all keys arrive via `ctx.secrets` /
//! `user.wireguard_*` fields.
//!
//! ## server_inbound + client_config
//!
//! Both return empty objects today — wgturn-core's TOML config is
//! emitted entirely by the `wgturn` kernel's `render_config`; this
//! protocol doesn't contribute a sub-block. The methods exist purely
//! to satisfy the `Protocol` trait; they're never called by the
//! current kernel implementation (the `_wgturn_proto` lookup in
//! `wgturn::render_config` is a tag-only check).
//!
//! Stateless, like every other Protocol in this crate.

use serde_json::json;
use vpnctl_core::{CoreError, Protocol, ProtocolId, RenderCtx, Result, User};

/// Default UDP port `wgturn-cli serve` listens on. Kept in sync with
/// `crates/kernels/src/wgturn.rs::DEFAULT_LISTEN_PORT` — the value is
/// duplicated rather than shared because the kernels and protocols
/// crates are independent (kernel × protocol orthogonality).
pub const WGTURN_PORT: u16 = 56000;

#[derive(Debug, Default)]
pub struct WgTurn;

impl WgTurn {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for WgTurn {
    fn id(&self) -> ProtocolId {
        ProtocolId("wgturn".to_string())
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        // Single UDP listener — the VK-TURN demuxer.
        &[("udp", WGTURN_PORT)]
    }

    fn server_inbound(&self, _ctx: &RenderCtx<'_>, _users: &[User]) -> Result<serde_json::Value> {
        // wgturn-core renders its OWN TOML via the kernel's
        // `render_config`; the protocol doesn't contribute a sing-box-
        // style inbound block. Returning an empty marker keeps the
        // trait shape uniform without polluting any merged config.
        Ok(json!({ "type": "wgturn" }))
    }

    fn client_config(&self, _ctx: &RenderCtx<'_>, _user: &User) -> Result<serde_json::Value> {
        // Same reasoning — the client config is the `wgturn://` URL
        // (rendered offline in phase 2, server-side in phase 1), not
        // a JSON blob. Trait-compliance stub.
        Ok(json!({ "type": "wgturn" }))
    }

    fn share_link(&self, _ctx: &RenderCtx<'_>, _user: &User) -> Result<String> {
        // Phase 1 contract: explicitly fail so the admin UI surfaces
        // a clear «mint via server» path instead of producing an
        // invalid URL. Phase 2 ports `pkg/wgshare` and replaces this
        // body with the real encoder.
        Err(CoreError::Render(
            "wgturn share-link not yet generated offline; pending pkg/wgshare port \
             (use the «provision wgturn URL» button on /admin/users/<id>, which \
             SSHes the VPN server and runs `wgturn-cli provision-url`)"
                .into(),
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use vpnctl_core::{KernelId, Server, ServerId, UserId};

    fn dummy_user() -> User {
        User {
            id: UserId("alex".into()),
            uuid: "11111111-1111-1111-1111-111111111111".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: Some("st".into()),
        }
    }

    fn dummy_server() -> Server {
        Server {
            id: ServerId("wgturn-node".into()),
            address: "203.0.113.42".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("wgturn".into())],
            enabled_protocols: vec![ProtocolId("wgturn".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    #[test]
    fn id_returns_wgturn() {
        assert_eq!(WgTurn::new().id(), ProtocolId("wgturn".into()));
    }

    #[test]
    fn listen_ports_declares_udp_56000() {
        let p = WgTurn::new();
        let ports = p.listen_ports();
        assert_eq!(ports, &[("udp", 56000_u16)]);
    }

    #[test]
    fn share_link_returns_render_error_in_phase_1() {
        // Phase 1 contract pin: offline encoder not implemented yet.
        // A later commit replacing this with a real `wgturn://` URL
        // MUST also flip this test.
        let server = dummy_server();
        let secrets: HashMap<String, String> = HashMap::new();
        let ctx = RenderCtx::new(&server, &secrets);
        let user = dummy_user();
        let err = WgTurn::new().share_link(&ctx, &user).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("wgturn share-link"),
            "error must name the protocol: {msg}"
        );
        assert!(
            msg.contains("pkg/wgshare") || msg.contains("provision"),
            "error must point operator at the workaround: {msg}"
        );
    }

    #[test]
    fn server_inbound_returns_wgturn_marker() {
        let server = dummy_server();
        let secrets: HashMap<String, String> = HashMap::new();
        let ctx = RenderCtx::new(&server, &secrets);
        let v = WgTurn::new().server_inbound(&ctx, &[]).unwrap();
        assert_eq!(v["type"], "wgturn");
    }

    #[test]
    fn client_config_returns_wgturn_marker() {
        let server = dummy_server();
        let secrets: HashMap<String, String> = HashMap::new();
        let ctx = RenderCtx::new(&server, &secrets);
        let user = dummy_user();
        let v = WgTurn::new().client_config(&ctx, &user).unwrap();
        assert_eq!(v["type"], "wgturn");
    }
}
