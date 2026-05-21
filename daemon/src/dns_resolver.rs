//! Phase 5a-2 — reverse-DNS (PTR) resolver task.
//!
//! Walks the latest SnapshotCache entries for unique destination
//! IPs that don't have a `host` populated by sing-box, calls
//! `getent hosts <ip>` via a spawn_blocking subprocess (no Rust
//! DNS dependency — avoids glibc 2.38+ pull from hickory-resolver),
//! and UPSERTs into `dns_ptr_cache`. The admin UI reads the cache
//! on render and shows hostnames where available.
//!
//! ## Why getent, not hickory-resolver
//!
//! Adding `hickory-resolver` (or any pure-Rust async DNS lib)
//! would pull in ~300 KiB binary growth AND open the door to
//! glibc version drift (the crate uses ring or aws-lc-rs internally
//! for DNSSEC, which transitively can pull 2.38+ syscalls and
//! break the bookworm-2.36 deploy target). `getent hosts <ip>`
//! is available on every Debian system, returns either the
//! hostname or empty stdout, and shells out via the same
//! `std::process::Command` + `tokio::task::spawn_blocking` pattern
//! we use everywhere else (ssh_subprocess, geoip-update, etc).
//!
//! ## Cadence + bounds
//!
//! Tick interval: 5 minutes (env override
//! `VPNCTLD_DNS_RESOLVER_INTERVAL_SECS`). On each tick:
//!  1. Collect unique destination IPs from latest snapshots
//!     across all servers in SnapshotCache.
//!  2. Skip IPs already in the cache (regardless of hostname
//!     None/Some — the cache row IS the answer).
//!  3. Resolve at most `MAX_LOOKUPS_PER_TICK` (default 50) new
//!     IPs per tick to bound subprocess fork rate.
//!  4. Per-lookup timeout 3 seconds (handles slow DNS / unreachable
//!     resolvers gracefully).
//!  5. Persist each result (including None for no-PTR) so we
//!     don't re-query for the TTL window.

use std::process::Command;
use std::time::Duration;

use vpnctl_core::ServerId;
use vpnctl_inventory::SqliteInventory;

use crate::snapshot_cache::SnapshotCache;

/// Default tick interval for the resolver task. Matches the
/// clash-poller cadence so by the time we render a server-detail
/// page, the destinations in the snapshot have ~5min of resolver
/// runway to populate the cache.
pub const DEFAULT_INTERVAL_SECS: u64 = 5 * 60;
/// Per-lookup timeout for `getent`. Strict — operator-facing UI
/// shouldn't wait on a dead DNS server; if the lookup is slow the
/// IP gets a cached "no answer" and is re-queried after TTL.
pub const LOOKUP_TIMEOUT_SECS: u64 = 3;
/// Cap per tick to bound subprocess fork rate. 50 lookups × 3s
/// timeout each = worst case 150s for a quiet resolver, well
/// under the 5-min tick.
pub const MAX_LOOKUPS_PER_TICK: usize = 50;

/// Spawn the periodic DNS resolver task. Returns the JoinHandle
/// so `build()` keeps it alive for the process lifetime.
pub fn spawn_dns_resolver(
    inv: SqliteInventory,
    snapshot_cache: SnapshotCache,
) -> tokio::task::JoinHandle<()> {
    use tokio::time::{MissedTickBehavior, interval};

    let interval_secs: u64 = std::env::var("VPNCTLD_DNS_RESOLVER_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n: &u64| n > 0)
        .unwrap_or(DEFAULT_INTERVAL_SECS);

    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(interval_secs));
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // Skip the immediate first tick — daemon startup is hot,
        // and the snapshot cache won't have data yet anyway.
        tick.tick().await;
        loop {
            tick.tick().await;
            if let Err(e) = resolve_one_tick(&inv, &snapshot_cache).await {
                tracing::warn!(
                    target = "vpnctld::dns_resolver",
                    error = %e,
                    "dns resolver tick failed; will retry next tick"
                );
            }
        }
    })
}

/// One tick body — extracted for testability.
pub async fn resolve_one_tick(
    inv: &SqliteInventory,
    snapshot_cache: &SnapshotCache,
) -> anyhow::Result<()> {
    // Collect unique destination IPs from latest snapshots across
    // all known servers. We can't iterate the cache directly (it
    // only exposes `.get(server_id)`), so use the inventory list.
    let servers = inv.list_servers().await?;
    let mut all_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
    for s in &servers {
        if let Some(snap) = snapshot_cache.get(&ServerId(s.id.0.clone())) {
            for c in &snap.snapshot.connections {
                // Only resolve destination IPs that DON'T already
                // carry a sing-box-derived host. We're filling the
                // gap, not replacing.
                if c.metadata.host.is_empty() && !c.metadata.destination_ip.is_empty() {
                    all_ips.insert(c.metadata.destination_ip.clone());
                }
            }
        }
    }
    if all_ips.is_empty() {
        tracing::debug!(
            target = "vpnctld::dns_resolver",
            "no destination IPs to resolve this tick"
        );
        return Ok(());
    }

    // Filter out IPs already in the cache (positive or negative
    // cached). bulk lookup in one SQL pass.
    let ips_vec: Vec<String> = all_ips.iter().cloned().collect();
    let cached = inv.lookup_dns_ptr_bulk(&ips_vec).await?;
    let unresolved: Vec<String> = ips_vec
        .into_iter()
        .filter(|ip| !cached.contains_key(ip))
        .take(MAX_LOOKUPS_PER_TICK)
        .collect();
    if unresolved.is_empty() {
        tracing::debug!(
            target = "vpnctld::dns_resolver",
            "all destination IPs already cached"
        );
        return Ok(());
    }

    let attempt = unresolved.len();
    let mut resolved_count: usize = 0;
    for ip in &unresolved {
        let host = resolve_one(ip).await;
        if host.is_some() {
            resolved_count += 1;
        }
        if let Err(e) = inv.upsert_dns_ptr(ip, host.as_deref()).await {
            tracing::warn!(
                target = "vpnctld::dns_resolver",
                ip = %ip,
                error = %e,
                "dns_ptr_cache upsert failed"
            );
        }
    }
    tracing::info!(
        target = "vpnctld::dns_resolver",
        attempted = attempt,
        resolved = resolved_count,
        "dns resolver tick: {resolved_count}/{attempt} returned a hostname"
    );
    Ok(())
}

/// Resolve a single IP via `getent hosts <ip>`. Returns the
/// hostname string (first field after the IP) or None when the
/// lookup fails, times out, or returns no PTR.
///
/// Runs in `spawn_blocking` because `std::process::Command::output()`
/// is blocking. `tokio::process` is NOT used per project-wide
/// glibc-2.39 hazard (pidfd_spawnp).
pub async fn resolve_one(ip: &str) -> Option<String> {
    // Defense: only spawn for syntactically-IP-shaped input.
    // `getent hosts foo.bar` would do a FORWARD lookup which we
    // don't want; reject anything with a letter so the subprocess
    // gets only well-formed IPv4/IPv6 strings.
    if !ip
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '.' | ':' | 'a'..='f' | 'A'..='F'))
    {
        return None;
    }
    let ip_owned = ip.to_string();
    tokio::task::spawn_blocking(move || resolve_blocking(&ip_owned))
        .await
        .ok()?
}

/// Synchronous worker for `resolve_one`. Runs `getent hosts` with
/// a hard timeout via `Command::output()` + a one-shot watchdog
/// thread that kills the child if it overruns. Returns parsed
/// hostname or None.
fn resolve_blocking(ip: &str) -> Option<String> {
    // Spawn with stdout/stderr pipes captured. We use `Command`
    // (not `tokio::process`) per glibc-2.36 deploy constraint.
    let mut child = Command::new("getent")
        .arg("hosts")
        .arg(ip)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;

    // Watchdog: if the child doesn't finish in LOOKUP_TIMEOUT_SECS,
    // kill it. We poll wait() with a short sleep budget.
    let deadline = std::time::Instant::now() + Duration::from_secs(LOOKUP_TIMEOUT_SECS);
    loop {
        match child.try_wait().ok()? {
            Some(_) => break,
            None => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    // `getent hosts 8.8.8.8` returns e.g. "8.8.8.8         dns.google\n"
    // — tab-or-space-separated; first field is the IP, second is
    // the canonical hostname.
    parse_getent_hosts_line(&stdout)
}

/// Pure parser — pulled out for unit tests so we can verify the
/// parsing without spawning a subprocess.
pub fn parse_getent_hosts_line(stdout: &str) -> Option<String> {
    let first_line = stdout.lines().next()?;
    let mut parts = first_line.split_whitespace();
    let _ip = parts.next()?;
    let hostname = parts.next()?;
    if hostname.is_empty() {
        return None;
    }
    Some(hostname.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_getent_returns_hostname_from_canonical_line() {
        let out = "8.8.8.8         dns.google\n";
        assert_eq!(parse_getent_hosts_line(out), Some("dns.google".into()));
    }

    #[test]
    fn parse_getent_handles_multiple_hostnames_returns_first() {
        // `getent` can append aliases on the same line.
        let out = "1.1.1.1         one.one.one.one cloudflare-dns.com\n";
        assert_eq!(parse_getent_hosts_line(out), Some("one.one.one.one".into()));
    }

    #[test]
    fn parse_getent_handles_ipv6_address() {
        let out = "2606:4700:4700::1111 one.one.one.one\n";
        assert_eq!(parse_getent_hosts_line(out), Some("one.one.one.one".into()));
    }

    #[test]
    fn parse_getent_empty_stdout_returns_none() {
        assert_eq!(parse_getent_hosts_line(""), None);
    }

    #[test]
    fn parse_getent_only_ip_no_hostname_returns_none() {
        // No PTR record — getent prints just the IP, no second field.
        let out = "1.2.3.4\n";
        assert_eq!(parse_getent_hosts_line(out), None);
    }

    #[tokio::test]
    async fn resolve_one_rejects_non_ip_input_without_spawning() {
        // Defense-in-depth: forward lookup is NOT what we want;
        // arbitrary input must not reach `getent`.
        assert!(resolve_one("attacker.example.com").await.is_none());
        assert!(resolve_one("rm -rf /").await.is_none());
        assert!(resolve_one("foo bar").await.is_none());
    }

    #[tokio::test]
    async fn resolve_one_accepts_valid_ipv4_chars_only() {
        // We don't assert the lookup SUCCEEDS (depends on the
        // container's DNS), only that the input passes validation
        // and the function returns either Some or None without panic.
        let _ = resolve_one("8.8.8.8").await;
        let _ = resolve_one("2606:4700:4700::1111").await;
    }
}
