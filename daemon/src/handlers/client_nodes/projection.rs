use std::net::IpAddr;

use serde::Serialize;
use vpnctl_inventory::NodeHealthRow;

#[derive(Serialize)]
pub(super) struct NodesResponse {
    pub(super) schema: u8,
    pub(super) generated_at: i64,
    pub(super) max_age_seconds: u64,
    pub(super) nodes: Vec<NodeMetadata>,
}

#[derive(Serialize)]
pub(super) struct NodeMetadata {
    endpoint_host: String,
    country_iso: Option<String>,
    memory_total_mib: Option<u64>,
    memory_available_mib: Option<u64>,
    load_1min_x100: Option<u32>,
    observed_at: Option<i64>,
    age_seconds: Option<u64>,
    freshness: &'static str,
}

impl NodeMetadata {
    pub(super) fn new(
        endpoint_host: String,
        country_iso: Option<String>,
        sample: Option<&NodeHealthRow>,
        now: i64,
        ttl: u64,
    ) -> Self {
        let memory = sample
            .and_then(|s| s.mem_total_mib.zip(s.mem_available_mib))
            .filter(|(total, available)| *total > 0 && available <= total);
        let observed_at = sample.map(|s| s.ts.timestamp());
        let age_seconds = observed_at
            .and_then(|ts| now.checked_sub(ts))
            .and_then(|age| u64::try_from(age).ok());
        Self {
            endpoint_host,
            country_iso,
            memory_total_mib: memory.map(|(total, _)| total),
            memory_available_mib: memory.map(|(_, available)| available),
            load_1min_x100: sample.and_then(|s| s.load_1min_x100),
            observed_at,
            age_seconds,
            freshness: match age_seconds {
                Some(age) if age <= ttl => "fresh",
                Some(_) => "stale",
                None => "unknown",
            },
        }
    }
}

pub(super) fn ttl_for_interval(interval: u64) -> u64 {
    interval.saturating_mul(2).saturating_add(120).min(86_400)
}

pub(super) fn country_for_node(
    node_address: &str,
    cached_ips: &[IpAddr],
    lookup: impl FnMut(IpAddr) -> Option<String>,
) -> Option<String> {
    match node_address.parse() {
        Ok(ip) => country_for_ips(&[ip], lookup),
        Err(_) => country_for_ips(cached_ips, lookup),
    }
}

pub(super) fn country_for_ips(
    ips: &[IpAddr],
    mut lookup: impl FnMut(IpAddr) -> Option<String>,
) -> Option<String> {
    let mut country: Option<String> = None;
    for ip in ips {
        let found = lookup(*ip)?;
        if found.len() != 2 || !found.bytes().all(|b| b.is_ascii_alphabetic()) {
            return None;
        }
        let found = found.to_ascii_uppercase();
        if country.as_ref().is_some_and(|country| country != &found) {
            return None;
        }
        country = Some(found);
    }
    country
}
