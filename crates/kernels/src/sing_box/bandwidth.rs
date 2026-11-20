use std::collections::HashMap;
use std::net::IpAddr;

use serde_json::{Value, json};
use vpnctl_core::{CoreError, Result, User};

pub const USER_BANDWIDTH_KEY: &str = "sing-box.user_bandwidth_mbps";
pub const USER_BANDWIDTH_MAX_MBPS: u32 = 4000;

pub(super) const VERIFY_USER_BANDWIDTH_SUPPORT: &str = r#"set -eu
printf '%s\n' '{"route":{"vpnctl_user_bandwidth":{"bits_per_second":40000000}}}' |
    /usr/bin/sing-box check -c /dev/stdin >/dev/null 2>&1
output=$(printf '%s\n' '{"route":{"vpnctl_user_bandwidth":{"bits_per_second":1}}}' |
    /usr/bin/sing-box check -c /dev/stdin 2>&1) && exit 1
printf '%s\n' "$output" | grep -Fq 'vpnctl_user_bandwidth.bits_per_second must be at least 8'
printf '%s\n' vpnctl-user-bandwidth-supported
"#;

pub(super) fn config_requests_user_bandwidth(config: &[u8]) -> bool {
    serde_json::from_slice::<Value>(config)
        .ok()
        .is_some_and(|value| value["route"]["vpnctl_user_bandwidth"].is_object())
}

pub(super) fn render_user_bandwidth(
    secrets: &HashMap<String, String>,
    endpoints: &[Value],
    users: &[User],
) -> Result<Option<Value>> {
    let Some(value) = secrets.get(USER_BANDWIDTH_KEY) else {
        return Ok(None);
    };
    let rate: u32 = value
        .parse()
        .ok()
        .filter(|rate| *rate <= USER_BANDWIDTH_MAX_MBPS)
        .ok_or_else(|| CoreError::Render("invalid sing-box per-user speed in Mbit/s".into()))?;
    if rate == 0 {
        return Ok(None);
    }
    let names_by_key: HashMap<&str, &str> = users
        .iter()
        .filter(|user| !user.disabled)
        .filter_map(|user| {
            user.wireguard_pubkey
                .as_deref()
                .map(|key| (key, user.id.0.as_str()))
        })
        .collect();
    let mut mappings = HashMap::new();
    for endpoint in endpoints {
        let tag = endpoint["tag"]
            .as_str()
            .ok_or_else(|| CoreError::Render("missing WireGuard endpoint tag".into()))?;
        let peers = endpoint["peers"]
            .as_array()
            .ok_or_else(|| CoreError::Render("missing WireGuard endpoint peers".into()))?;
        let mut addresses = HashMap::new();
        for peer in peers {
            let user = peer["public_key"]
                .as_str()
                .and_then(|key| names_by_key.get(key))
                .ok_or_else(|| {
                    CoreError::Render("unmapped WireGuard peer for user speed".into())
                })?;
            let host_prefixes = peer["allowed_ips"]
                .as_array()
                .ok_or_else(|| CoreError::Render("missing WireGuard peer host addresses".into()))?;
            for prefix in host_prefixes {
                let address = prefix
                    .as_str()
                    .and_then(|prefix| prefix.split_once('/'))
                    .and_then(|(address, bits)| {
                        let address: IpAddr = address.parse().ok()?;
                        let expected = if address.is_ipv4() { "32" } else { "128" };
                        (bits == expected).then_some(address)
                    })
                    .ok_or_else(|| {
                        CoreError::Render("invalid WireGuard peer host address".into())
                    })?;
                if addresses.insert(address, *user).is_some() {
                    return Err(CoreError::Render(
                        "duplicate WireGuard peer host address".into(),
                    ));
                }
            }
        }
        mappings.insert(tag, addresses);
    }

    Ok(Some(json!({
        "bits_per_second": rate * 1_000_000,
        "wireguard_peers": mappings,
    })))
}
