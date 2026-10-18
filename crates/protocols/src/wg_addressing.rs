use vpnctl_core::{CoreError, RenderCtx, Result, User};

const MAX_HOST_OCTET: u16 = 254;

pub(crate) fn peer_octet_in_slash24(
    ctx: &RenderCtx<'_>,
    user: &User,
    base_octet: u16,
) -> Result<u16> {
    if ctx.peers.is_empty() {
        return Ok(base_octet);
    }
    let idx = ctx
        .peers
        .iter()
        .position(|u| u.id == user.id)
        .ok_or_else(|| {
            CoreError::Render(format!(
                "user '{}' not present in granted-peers list of {} peers — \
                 caller likely built RenderCtx for the wrong server or the \
                 grant was revoked mid-render",
                user.id.0,
                ctx.peers.len()
            ))
        })?;
    let octet = base_octet.saturating_add(u16::try_from(idx).unwrap_or(u16::MAX));
    if octet > MAX_HOST_OCTET {
        return Err(CoreError::Render(format!(
            "/24 has only {} peer slots; user '{}' index {idx} would overflow",
            MAX_HOST_OCTET - base_octet + 1,
            user.id.0
        )));
    }
    Ok(octet)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, UserId};

    fn dummy_user(id: &str) -> User {
        User {
            id: UserId(id.into()),
            uuid: format!("{id}-uuid"),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        }
    }

    fn dummy_server() -> Server {
        Server {
            id: ServerId("s1".into()),
            address: "203.0.113.1".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("wireguard".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    #[test]
    fn empty_peers_returns_base_octet() {
        let server = dummy_server();
        let secrets: HashMap<String, String> = HashMap::new();
        let ctx = RenderCtx::new(&server, &secrets);
        let user = dummy_user("alex");
        assert_eq!(peer_octet_in_slash24(&ctx, &user, 2).unwrap(), 2);
        assert_eq!(peer_octet_in_slash24(&ctx, &user, 5).unwrap(), 5);
    }

    #[test]
    fn user_at_known_index_returns_offset_octet() {
        let server = dummy_server();
        let secrets: HashMap<String, String> = HashMap::new();
        let peers: Vec<User> = ["alex", "brian", "clara"]
            .iter()
            .map(|n| dummy_user(n))
            .collect();
        let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
        assert_eq!(peer_octet_in_slash24(&ctx, &peers[0], 2).unwrap(), 2);
        assert_eq!(peer_octet_in_slash24(&ctx, &peers[1], 2).unwrap(), 3);
        assert_eq!(peer_octet_in_slash24(&ctx, &peers[2], 2).unwrap(), 4);
    }

    #[test]
    fn user_missing_from_non_empty_peers_errors_loud() {
        let server = dummy_server();
        let secrets: HashMap<String, String> = HashMap::new();
        let peers = vec![dummy_user("alex"), dummy_user("brian")];
        let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
        let stranger = dummy_user("clara");
        let err = peer_octet_in_slash24(&ctx, &stranger, 2).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("not present"), "got: {msg}");
        assert!(msg.contains("clara"), "must name the user: {msg}");
    }

    #[test]
    fn octet_overflow_past_254_errors() {
        let server = dummy_server();
        let secrets: HashMap<String, String> = HashMap::new();
        let peers: Vec<User> = (0..254).map(|i| dummy_user(&format!("u-{i:03}"))).collect();
        let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
        let last = peers.last().unwrap();
        let err = peer_octet_in_slash24(&ctx, last, 2).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("overflow"), "got: {msg}");
    }

    #[test]
    fn highest_valid_index_lands_at_octet_254() {
        let server = dummy_server();
        let secrets: HashMap<String, String> = HashMap::new();
        let peers: Vec<User> = (0..253).map(|i| dummy_user(&format!("u-{i:03}"))).collect();
        let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
        let last = peers.last().unwrap();
        assert_eq!(peer_octet_in_slash24(&ctx, last, 2).unwrap(), 254);
    }
}
