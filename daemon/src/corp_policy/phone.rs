use std::collections::HashSet;
use std::net::IpAddr;

use ipnet::IpNet;

use super::domains::{intersects, normalize_dns};
use super::{PhoneRule, PolicyError, normalize_site};

pub fn normalize_phone_value(kind: &str, value: &str) -> Result<String, PolicyError> {
    if value.is_empty()
        || value.encode_utf16().count() > 4096
        || value.chars().any(char::is_control)
    {
        return Err(PolicyError);
    }
    match kind {
        "domain_suffix" => {
            let domain = normalize_site(value)?;
            if intersects(&domain, "admin.corp.ninitux.com") {
                return Err(PolicyError);
            }
            Ok(domain)
        }
        "ip_cidr" => {
            let input = value.trim();
            let network: IpNet = if input.contains('/') {
                input.parse().map_err(|_| PolicyError)?
            } else {
                let address: IpAddr = input.parse().map_err(|_| PolicyError)?;
                IpNet::from(address)
            };
            if matches!(network.addr(), IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some()) {
                return Err(PolicyError);
            }
            Ok(network.trunc().to_string())
        }
        _ => Err(PolicyError),
    }
}

pub fn validate_phone_rules(rules: &[PhoneRule]) -> Result<(), PolicyError> {
    if rules.len() > 64 {
        return Err(PolicyError);
    }
    let mut seen = HashSet::with_capacity(rules.len());
    for rule in rules {
        let normalized = if rule.kind == "domain_suffix" {
            normalize_dns(&rule.value)?
        } else {
            normalize_phone_value(&rule.kind, &rule.value)?
        };
        if normalized != rule.value
            || (rule.kind == "domain_suffix" && intersects(&rule.value, "admin.corp.ninitux.com"))
            || !matches!(rule.action.as_str(), "direct" | "proxy")
            || !seen.insert((rule.kind.as_str(), rule.value.as_str()))
            || rule.comment.len() > 256
            || rule.comment.chars().any(char::is_control)
        {
            return Err(PolicyError);
        }
    }
    for (index, left) in rules.iter().enumerate() {
        for right in &rules[index + 1..] {
            if left.kind != right.kind || left.action == right.action {
                continue;
            }
            let overlap = if left.kind == "domain_suffix" {
                intersects(&left.value, &right.value)
            } else {
                let a: IpNet = left.value.parse().map_err(|_| PolicyError)?;
                let b: IpNet = right.value.parse().map_err(|_| PolicyError)?;
                a.contains(&b.addr()) || b.contains(&a.addr())
            };
            if overlap {
                return Err(PolicyError);
            }
        }
    }
    Ok(())
}

pub fn seed_phone_rules() -> Result<Vec<PhoneRule>, PolicyError> {
    let rules = [
        "uiscom.ru",
        "uiscom.co",
        "comagic.ru",
        "callbackhunter.com",
        "195.211.120.35/32",
    ]
    .into_iter()
    .map(|value| PhoneRule {
        kind: if value.contains('/') {
            "ip_cidr"
        } else {
            "domain_suffix"
        }
        .into(),
        value: value.into(),
        action: "direct".into(),
        comment: String::new(),
    })
    .collect::<Vec<_>>();
    validate_phone_rules(&rules)?;
    Ok(rules)
}
