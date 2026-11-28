use serde_json::Value;
use std::collections::{BTreeSet, HashSet};
use vpnctl_core::{CoreError, Result};

pub fn live_config_user_uuids(config_bytes: &[u8]) -> BTreeSet<String> {
    extract_user_uuids(config_bytes)
        .map(|set| set.into_iter().collect())
        .unwrap_or_default()
}

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
        let password_is_uuid = is_trusttunnel_or_mieru(inbound);
        for u in users {
            let uuid = if password_is_uuid {
                u["password"]
                    .as_str()
                    .filter(|uuid| vpnctl_crypto::is_valid_uuid(uuid))
            } else {
                u["uuid"].as_str()
            };
            if let Some(uuid) = uuid {
                out.insert(uuid.to_string());
            }
        }
    }
    Ok(out)
}

fn is_trusttunnel_or_mieru(inbound: &Value) -> bool {
    matches!(inbound["type"].as_str(), Some("trusttunnel" | "mieru"))
}

pub(super) fn contains_trusttunnel_or_mieru(config_bytes: &[u8]) -> Result<bool> {
    let invalid_config =
        || CoreError::Render("could not inspect the live sing-box inbounds".into());
    let config: Value = serde_json::from_slice(config_bytes).map_err(|_| invalid_config())?;
    let config = config.as_object().ok_or_else(invalid_config)?;
    let Some(inbounds) = config.get("inbounds") else {
        return Ok(false);
    };
    let inbounds = inbounds.as_array().ok_or_else(invalid_config)?;
    if inbounds
        .iter()
        .any(|inbound| inbound["type"].as_str().is_none())
    {
        return Err(invalid_config());
    }
    Ok(inbounds.iter().any(is_trusttunnel_or_mieru))
}

pub(super) fn user_uuid_diff(old: &[u8], new: &[u8]) -> Result<HashSet<String>> {
    let old_uuids = extract_user_uuids(old)?;
    let new_uuids = extract_user_uuids(new)?;
    Ok(old_uuids.difference(&new_uuids).cloned().collect())
}

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
    let listeners = ["inbounds", "endpoints"]
        .into_iter()
        .filter_map(|key| parsed.get(key).and_then(|value| value.as_array()))
        .flatten();
    let reserved_set: HashSet<u16> = reserved.iter().copied().collect();
    let mut collisions: Vec<u16> = Vec::new();
    for inbound in listeners {
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
