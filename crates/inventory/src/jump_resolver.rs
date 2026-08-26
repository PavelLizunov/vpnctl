//! Jump host resolution and validation helper.

use vpnctl_core::{PinnedJumpRoute, Server, ServerId};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JumpResolverError {
    #[error("jump target '{0}' missing from inventory")]
    MissingJumpServer(ServerId),

    #[error("server '{0}' cannot jump to itself")]
    SelfJump(ServerId),

    #[error("nested jump target '{0}' is not allowed (max 1 hop)")]
    NestedJump(ServerId),

    #[error("jump target '{0}' or jump server '{1}' is missing trusted_host_fingerprint")]
    MissingFingerprint(ServerId, ServerId),

    #[error("server '{0}' has an invalid trusted_host_fingerprint")]
    InvalidFingerprint(ServerId),
}

/// Resolve a target's optional one-hop route, requiring canonical pins for both hosts.
pub fn resolve_jump_host(
    target: &Server,
    jump_record: Option<&Server>,
) -> Result<Option<PinnedJumpRoute>, JumpResolverError> {
    let Some(ref jump_id) = target.jump_via else {
        return Ok(None);
    };

    let jump = jump_record.ok_or_else(|| JumpResolverError::MissingJumpServer(jump_id.clone()))?;

    if jump.id != *jump_id {
        return Err(JumpResolverError::MissingJumpServer(jump_id.clone()));
    }
    if jump.id == target.id || jump.address == target.address {
        return Err(JumpResolverError::SelfJump(target.id.clone()));
    }
    if jump.jump_via.is_some() {
        return Err(JumpResolverError::NestedJump(jump.id.clone()));
    }

    let Some(target_fp) = target
        .trusted_host_fingerprint
        .as_deref()
        .filter(|fp| !fp.trim().is_empty())
    else {
        return Err(JumpResolverError::MissingFingerprint(
            target.id.clone(),
            jump.id.clone(),
        ));
    };
    let Some(jump_fp) = jump
        .trusted_host_fingerprint
        .as_deref()
        .filter(|fp| !fp.trim().is_empty())
    else {
        return Err(JumpResolverError::MissingFingerprint(
            target.id.clone(),
            jump.id.clone(),
        ));
    };

    let target_fingerprint = vpnctl_host_fingerprint::canonicalize_sha256(target_fp)
        .ok_or_else(|| JumpResolverError::InvalidFingerprint(target.id.clone()))?;
    let jump_fingerprint = vpnctl_host_fingerprint::canonicalize_sha256(jump_fp)
        .ok_or_else(|| JumpResolverError::InvalidFingerprint(jump.id.clone()))?;

    Ok(Some(PinnedJumpRoute {
        host: jump.address.clone(),
        user: jump.ssh_user.clone(),
        port: jump.ssh_port,
        jump_fingerprint,
        target_fingerprint,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP1: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const FP2_PADDED_URL_SAFE: &str = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB-_=";

    fn make_server(id: &str, address: &str, jump_via: Option<&str>, fp: Option<&str>) -> Server {
        Server {
            id: ServerId(id.into()),
            address: address.into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            hoster: "generic".into(),
            kernels: vec![],
            enabled_protocols: vec![],
            trusted_host_fingerprint: fp.map(Into::into),
            jump_via: jump_via.map(|j| ServerId(j.into())),
            usage_coefficient: 1.0,
        }
    }

    #[test]
    fn direct_server_without_jump_via_returns_ok_none() {
        let target = make_server("target", "10.0.0.1", None, None);
        assert_eq!(resolve_jump_host(&target, None), Ok(None));
    }

    #[test]
    fn rejects_missing_mismatched_self_and_nested_jump_records() {
        let target = make_server("target", "10.0.0.1", Some("bastion"), Some(FP1));
        assert_eq!(
            resolve_jump_host(&target, None),
            Err(JumpResolverError::MissingJumpServer(ServerId(
                "bastion".into()
            )))
        );

        let wrong = make_server("wrong", "10.0.0.2", None, Some(FP1));
        assert_eq!(
            resolve_jump_host(&target, Some(&wrong)),
            Err(JumpResolverError::MissingJumpServer(ServerId(
                "bastion".into()
            )))
        );

        let self_address = make_server("bastion", "10.0.0.1", None, Some(FP1));
        assert_eq!(
            resolve_jump_host(&target, Some(&self_address)),
            Err(JumpResolverError::SelfJump(ServerId("target".into())))
        );

        let nested = make_server("bastion", "10.0.0.2", Some("hop0"), Some(FP1));
        assert_eq!(
            resolve_jump_host(&target, Some(&nested)),
            Err(JumpResolverError::NestedJump(ServerId("bastion".into())))
        );
    }

    #[test]
    fn requires_both_fingerprints() {
        let missing_target = make_server("target", "10.0.0.1", Some("bastion"), None);
        let missing_jump = make_server("bastion", "10.0.0.2", None, None);
        let pinned_jump = make_server("bastion", "10.0.0.2", None, Some(FP1));
        let pinned_target = make_server("target", "10.0.0.1", Some("bastion"), Some(FP1));

        for result in [
            resolve_jump_host(&missing_target, Some(&pinned_jump)),
            resolve_jump_host(&pinned_target, Some(&missing_jump)),
        ] {
            assert_eq!(
                result,
                Err(JumpResolverError::MissingFingerprint(
                    ServerId("target".into()),
                    ServerId("bastion".into())
                ))
            );
        }
    }

    #[test]
    fn rejects_malformed_fingerprints() {
        let bad_target = make_server("target", "10.0.0.1", Some("bastion"), Some("bad"));
        let good_jump = make_server("bastion", "10.0.0.2", None, Some(FP1));
        assert_eq!(
            resolve_jump_host(&bad_target, Some(&good_jump)),
            Err(JumpResolverError::InvalidFingerprint(ServerId(
                "target".into()
            )))
        );

        let good_target = make_server("target", "10.0.0.1", Some("bastion"), Some(FP1));
        let bad_jump = make_server("bastion", "10.0.0.2", None, Some("bad"));
        assert_eq!(
            resolve_jump_host(&good_target, Some(&bad_jump)),
            Err(JumpResolverError::InvalidFingerprint(ServerId(
                "bastion".into()
            )))
        );
    }

    #[test]
    fn returns_canonical_pinned_route() {
        let target = make_server(
            "target",
            "10.0.0.1",
            Some("bastion"),
            Some(FP2_PADDED_URL_SAFE),
        );
        let jump = make_server("bastion", "10.0.0.2", None, Some(FP1));
        assert_eq!(
            resolve_jump_host(&target, Some(&jump)),
            Ok(Some(PinnedJumpRoute {
                host: "10.0.0.2".into(),
                user: "root".into(),
                port: 22,
                jump_fingerprint: FP1.into(),
                target_fingerprint: "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB+/".into(),
            }))
        );
    }
}
