use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use serde_json::{Value, json};
use vpnctl_core::{CoreError, Result, User};

pub const USER_BANDWIDTH_KEY: &str = "sing-box.user_bandwidth_mbps";
pub const USER_BANDWIDTH_OVERRIDES_KEY: &str = "sing-box.user_bandwidth_overrides_mbps";
pub const USER_BANDWIDTH_MAX_MBPS: u32 = 4000;

pub(super) const VERIFY_USER_BANDWIDTH_SUPPORT: &str = r#"set -eu
printf '%s\n' '{"route":{"vpnctl_user_bandwidth":{"bits_per_second":40000000}}}' |
    /usr/bin/sing-box check -c /dev/stdin >/dev/null 2>&1
output=$(printf '%s\n' '{"route":{"vpnctl_user_bandwidth":{"bits_per_second":1}}}' |
    /usr/bin/sing-box check -c /dev/stdin 2>&1) && exit 1
printf '%s\n' "$output" | grep -Fq 'vpnctl_user_bandwidth.bits_per_second must be at least 8'
printf '%s\n' vpnctl-user-bandwidth-supported
"#;

pub(super) const VERIFY_USER_BANDWIDTH_OVERRIDES_SUPPORT: &str = r#"set -eu
printf '%s\n' '{"route":{"vpnctl_user_bandwidth":{"bits_per_second":40000000,"user_bits_per_second":{"fixture":80000000}}}}' |
    /usr/bin/sing-box check -c /dev/stdin >/dev/null 2>&1
output=$(printf '%s\n' '{"route":{"vpnctl_user_bandwidth":{"bits_per_second":40000000,"user_bits_per_second":{"fixture":1}}}}' |
    /usr/bin/sing-box check -c /dev/stdin 2>&1) && exit 1
printf '%s\n' "$output" | grep -Fq 'vpnctl_user_bandwidth.user_bits_per_second must be at least 8'
printf '%s\n' vpnctl-user-bandwidth-supported
"#;

pub(super) fn user_bandwidth_support_probe(config: &[u8]) -> Option<&'static str> {
    let config = serde_json::from_slice::<Value>(config).ok()?;
    let bandwidth = config["route"]["vpnctl_user_bandwidth"].as_object()?;
    if bandwidth.contains_key("user_bits_per_second") {
        Some(VERIFY_USER_BANDWIDTH_OVERRIDES_SUPPORT)
    } else {
        Some(VERIFY_USER_BANDWIDTH_SUPPORT)
    }
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

    let mut bandwidth = json!({
        "bits_per_second": rate * 1_000_000,
        "wireguard_peers": mappings,
    });
    if let Some(overrides) = secrets.get(USER_BANDWIDTH_OVERRIDES_KEY) {
        let configured: BTreeMap<String, u32> = serde_json::from_str(overrides)
            .map_err(|_| CoreError::Render("invalid sing-box speed overrides".into()))?;
        if configured
            .values()
            .any(|rate| !(1..=USER_BANDWIDTH_MAX_MBPS).contains(rate))
        {
            return Err(CoreError::Render(
                "invalid sing-box speed override in Mbit/s".into(),
            ));
        }
        let named_rates: BTreeMap<&str, u32> = users
            .iter()
            .filter(|user| !user.disabled)
            .filter_map(|user| {
                let user_id = user.id.0.as_str();
                let override_rate = *configured.get(user_id)?;
                (override_rate != rate).then_some((user_id, override_rate * 1_000_000))
            })
            .collect();
        if !named_rates.is_empty() {
            bandwidth["user_bits_per_second"] = json!(named_rates);
        }
    }
    Ok(Some(bandwidth))
}
