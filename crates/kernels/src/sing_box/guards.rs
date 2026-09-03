use std::collections::{BTreeSet, HashSet};
use vpnctl_core::{CoreError, Result};

/// Read helper: the set of user UUIDs declared in a *live* sing-box
/// config, returned in sorted order (`BTreeSet`) for a deterministic
/// caller-side diff render.
///
/// Used by the daemon's drift-detail card to compare the UUIDs the node
/// is actually serving against the UUIDs inventory expects, so the
/// operator can see *which* user accounts drifted, not just that a
/// count differs. Parse failures (truncated SSH read, non-JSON blob)
/// collapse to an empty set rather than an error — the card degrades to
/// "no on-node users observed" instead of failing the whole page.
///
/// This is a pure read over already-parsed bytes: it adds no new
/// kernel/protocol coupling, it just re-exposes the same extraction the
/// pre-apply diff guard already does internally.
pub fn live_config_user_uuids(config_bytes: &[u8]) -> BTreeSet<String> {
    extract_user_uuids(config_bytes)
        .map(|set| set.into_iter().collect())
        .unwrap_or_default()
}

/// Extract every `uuid` value found in `inbounds[*].users[*]` of a
/// sing-box JSON config. Tolerant of non-VLESS inbounds (which don't
/// carry a `users` array) and of inbounds whose users use a different
/// auth shape — only entries with a real `"uuid"` string key are
/// returned. Used by the pre-apply diff guard.
pub(super) fn extract_user_uuids(config_bytes: &[u8]) -> Result<HashSet<String>> {
    let v: serde_json::Value = serde_json::from_slice(config_bytes).map_err(CoreError::from)?;
    let mut out = HashSet::new();
    let Some(inbounds) = v.get("inbounds").and_then(|x| x.as_array()) else {
        return Ok(out);
    };
    for inbound in inbounds {
        let Some(users) = inbound.get("users").and_then(|x| x.as_array()) else {
            continue;
        };
        for u in users {
            if let Some(uuid) = u.get("uuid").and_then(|x| x.as_str()) {
                out.insert(uuid.to_string());
            }
        }
    }
    Ok(out)
}

/// Compute the set of user UUIDs that are present in the OLD config
/// but absent from the NEW config — i.e. would be REMOVED if we
/// proceeded with the apply. Empty result = safe to proceed.
pub(super) fn user_uuid_diff(old: &[u8], new: &[u8]) -> Result<HashSet<String>> {
    let old_uuids = extract_user_uuids(old)?;
    let new_uuids = extract_user_uuids(new)?;
    Ok(old_uuids.difference(&new_uuids).cloned().collect())
}

/// Reserved-ports pre-apply guard (post-2026-05-26, Pavel:
/// «важно конкретно для этого сервера заблокировать часть
/// функционала, чтоб через админку нельзя было что-то перетереть»).
///
/// Returns `Err` with the offending port(s) if `config_bytes` (a
/// rendered sing-box JSON) declares any `inbounds[].listen_port`
/// that intersects `reserved`. Empty `reserved` is a no-op — most
/// servers in the fleet stay byte-equivalent to pre-0028.
///
/// The fence is **fail-CLOSED**: parse failures of `config_bytes`
/// also return Err. This is the opposite policy from
/// `user_uuid_diff` — there we fail-OPEN because the OLD config
/// might be hand-edited; here the NEW config is what *we* render,
/// so a parse failure means our own renderer produced malformed
/// JSON and the safest move is to refuse to upload it.
///
/// Called from every `apply_config` site (CLI deploy, daemon
/// deploy, wizard bootstrap). The trait signature itself is not
/// changed — the validator is a free function so kernels other
/// than sing-box don't have to opt in.
pub fn validate_config_excludes_ports(config_bytes: &[u8], reserved: &[u16]) -> Result<()> {
    if reserved.is_empty() {
        return Ok(());
    }
    let parsed: serde_json::Value = serde_json::from_slice(config_bytes).map_err(|e| {
        CoreError::Render(format!(
            "sing-box config: reserved-ports guard could not parse rendered JSON ({e}); \
             refusing to apply"
        ))
    })?;
    let Some(inbounds) = parsed.get("inbounds").and_then(|v| v.as_array()) else {
        // No inbounds[] at all — vacuously safe (the renderer may
        // produce a config with only outbounds for some future
        // route-only role). Don't false-flag.
        return Ok(());
    };
    let reserved_set: HashSet<u16> = reserved.iter().copied().collect();
    let mut collisions: Vec<u16> = Vec::new();
    for inbound in inbounds {
        let Some(port_value) = inbound.get("listen_port") else {
            continue;
        };
        let Some(port_u64) = port_value.as_u64() else {
            continue;
        };
        let Ok(port) = u16::try_from(port_u64) else {
            continue;
        };
        if reserved_set.contains(&port) {
            collisions.push(port);
        }
    }
    if collisions.is_empty() {
        return Ok(());
    }
    collisions.sort_unstable();
    collisions.dedup();
    Err(CoreError::Render(format!(
        "sing-box config: refusing to apply — rendered inbounds[] bind reserved port(s) {:?} \
         on this server (full reserved list: {:?}). These ports are protected by the operator \
         (typically a co-tenant service like a legacy 3x-ui panel on :443). Reconfigure the \
         offending protocol to a non-reserved port via /admin/servers/<id> → Enabled protocols, \
         or drop the reservation via the Reserved-ports section if you truly want to overwrite \
         the co-tenant.",
        collisions, reserved
    )))
}
