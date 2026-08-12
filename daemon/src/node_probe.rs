//! Phase H chunk 1 — node telemetry probe.
//!
//! Same SSH-curl pattern as `clash_api` (Track-3 chunk 1): vpnctld
//! SSH's into a VPN node and runs a single shell script that emits
//! a well-defined text format; we parse in Rust.
//!
//! # What it collects
//!
//! - **systemd:** `systemctl is-active sing-box`, `is-active fail2ban`,
//!   plus sing-box's monotonic `NRestarts` counter (`systemctl show`)
//!   so the health monitor can detect a crash+auto-restart that happens
//!   BETWEEN two probes (both samples read `active`)
//! - **disk:** `df -BM /` (root filesystem usage; logs/db live here)
//! - **memory:** `/proc/meminfo` MemTotal + MemAvailable
//! - **load:** `/proc/loadavg` 1-min average
//! - **listening sockets:** `ss -tunlp` → set of `(proto, port)` tuples
//! - **sing-box log size:** `stat -c %s /var/log/sing-box.log` (caught
//!   real risk Pavel flagged — without logrotate this grows unbounded;
//!   chunk 4 will surface a "log >500MB" alert)
//!
//! # Why a single script (not multiple `exec` calls)
//!
//! One round-trip vs six. SSH session setup is the expensive part;
//! once open, running a 20-line bash script vs one `df` command is
//! the same wall-clock. We emit a tagged-line format so the parser
//! can pick fields by prefix regardless of order:
//!
//! ```text
//! SVC sing-box active
//! SVC fail2ban active
//! DISK /  9876  20480
//! MEM  483 960
//! LOAD 0.04
//! PORT tcp 443
//! PORT tcp 8443
//! PORT udp 8388
//! LOG_SB 308432
//! ```
//!
//! Numeric values are MiB (memory + disk) or raw counts (load is
//! float, log_sb is bytes). Anything we can't parse → `Probe`
//! field stays `None` rather than failing the whole snapshot.
//!
//! # No daemon wiring yet
//!
//! This chunk is read-only — types + parser + spec tests. Chunk 2
//! adds the inventory side; chunk 3 wires the periodic poller.
//! Same gating as Track-3: each chunk independently testable.

use async_trait::async_trait;
use std::collections::BTreeSet;
use vpnctl_core::SshTransport;

/// Snapshot of a single node's health at one tick. Fields are
/// `Option` because partial-success is preferred over a hard
/// failure when one parser misbehaves — the operator still wants
/// to see the OTHER metrics if `ss` lacks permission to enumerate
/// processes or `/proc/meminfo` format drifts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Probe {
    pub sing_box_active: Option<bool>,
    pub fail2ban_active: Option<bool>,
    pub disk_used_mib: Option<u64>,
    pub disk_total_mib: Option<u64>,
    pub mem_available_mib: Option<u64>,
    pub mem_total_mib: Option<u64>,
    /// 1-minute load average × 100 (so we can store as u32 without
    /// fractional handling; UI divides by 100 on render).
    pub load_1min_x100: Option<u32>,
    /// Listening sockets as `(proto, port)`. `BTreeSet` so the
    /// rendered set is deterministic (same input → same JSON →
    /// byte-stable across runs).
    pub listening: BTreeSet<(String, u16)>,
    pub sing_box_log_bytes: Option<u64>,

    // ─── Phase G chunk 2 — banned-self detector inputs ───────────
    /// Daemon's outbound IP as observed from the node, parsed from
    /// `$SSH_CLIENT`'s first space-separated field (the client IP).
    /// `None` when the script could not capture it (`SSH_CLIENT`
    /// unset, e.g. someone heavily customised sshd's `AcceptEnv`).
    /// Used by [`Probe::fail2ban_self_banned`] derivation, NOT
    /// rendered directly.
    pub probe_source_ip: Option<String>,

    /// All currently-banned sshd IPs as reported by
    /// `fail2ban-client status sshd`. `Some([])` means fail2ban is
    /// up but nothing is currently banned; `None` means
    /// `fail2ban-client` was not runnable (not installed, sshd jail
    /// missing, command exited non-zero) — the operator-facing
    /// «no signal» state, NOT «definitely clear».
    pub fail2ban_banned_ips: Option<Vec<String>>,

    /// Derived during parse: `Some(true)` iff `probe_source_ip` is
    /// present AND that IP appears in `fail2ban_banned_ips`.
    /// `Some(false)` iff both are present but our IP is NOT in the
    /// list. `None` otherwise (no signal — either we don't know our
    /// IP or fail2ban didn't report). Caller uses this verdict
    /// directly for the `server.fail2ban.banned_self` alert.
    pub fail2ban_self_banned: Option<bool>,

    // ─── PR-Q — kernel software versions ─────────────────────────
    /// On-node software versions keyed by kernel name, e.g.
    /// `{"sing-box": "1.13.12", "caddy": "2.8.4"}`. `BTreeMap` so the
    /// serialised JSON has deterministic key order (byte-stable
    /// across runs). Empty when the probe captured no `VER` lines
    /// (old node whose script predates the version capture, or a tick
    /// where every version command failed) — the poller persists
    /// `NULL` in that case rather than `{}`. Backs the admin UI's
    /// drift-detail card.
    pub kernel_versions: std::collections::BTreeMap<String, String>,
    /// Active state for every declared kernel whose `Kernel::status`
    /// call succeeded. Stored beside the versions in the existing
    /// node-health JSON column.
    pub kernel_active: std::collections::BTreeMap<String, bool>,

    // ─── Traffic ground-truth — public-interface byte counters ───
    /// Default-route interface name (e.g. `ens18`, `eth0`). `None` when
    /// the node has no default route or `ip route` was unreadable.
    pub nic_iface: Option<String>,
    /// RAW cumulative `rx_bytes` / `tx_bytes` of the default-route
    /// interface (`/sys/class/net/<iface>/statistics/`). NOT deltas —
    /// the gap computation diffs consecutive stored readings with a
    /// reboot/reset guard. This is the SERVER-WIDE ground truth: it
    /// catches ALL traffic on the node (incl. non-sing-box protocols
    /// clash-api can't see — naive/Caddy, dns-tunnel, wgturn), so it
    /// reconciles with the hoster's billing. `None` when the counters
    /// were unreadable (kept independent of `nic_iface` for parser
    /// partial-success symmetry).
    pub nic_rx_bytes: Option<u64>,
    pub nic_tx_bytes: Option<u64>,

    // ─── Restart detection — monotonic systemd counter ───────────
    /// sing-box's monotonic systemd `NRestarts` counter
    /// (`systemctl show -p NRestarts --value sing-box`). Counts how
    /// many times systemd has restarted the unit since the counter
    /// was last reset (host reboot / `systemctl reset-failed`). The
    /// health monitor diffs consecutive readings: an INCREASE means
    /// sing-box OOM/crashed and was auto-restarted BETWEEN two probes
    /// even though both samples report `active` — the gap the plain
    /// `sing_box_active` down/up detector can never see. `None` when
    /// `systemctl show` was unreadable (non-systemd host, old systemd
    /// without `NRestarts`, or a tick where the command failed).
    pub sing_box_nrestarts: Option<u64>,
}

impl Probe {
    /// Convenience: disk usage as percentage (0–100). Returns `None`
    /// if either field is `None` or total is 0 (avoid div-by-zero).
    pub fn disk_pct(&self) -> Option<u8> {
        let used = self.disk_used_mib?;
        let total = self.disk_total_mib?;
        if total == 0 {
            return None;
        }
        // Cap at 100 — partition over-commit could in theory report
        // used > total (snapshots, sparse files); clamp keeps the UI
        // sane.
        let pct = (used.saturating_mul(100) / total).min(100);
        u8::try_from(pct).ok()
    }

    /// Memory used percentage = 100 - (avail × 100 / total).
    pub fn mem_used_pct(&self) -> Option<u8> {
        let avail = self.mem_available_mib?;
        let total = self.mem_total_mib?;
        if total == 0 {
            return None;
        }
        let used_pct = 100u64.saturating_sub(avail.saturating_mul(100) / total);
        u8::try_from(used_pct.min(100)).ok()
    }
}

/// Errors `ProbeClient::snapshot` may return.
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    /// SSH transport layer failed.
    #[error("ssh transport: {0}")]
    Transport(String),
    /// SSH succeeded but the probe script produced output the parser
    /// couldn't make sense of AT ALL (every line malformed). Partial
    /// parse failures don't return Err — they just leave individual
    /// `Probe` fields as `None`.
    #[error("probe parse: no recognizable lines")]
    NothingParsed,
    /// SSH "succeeded" but the script never reached its trailing
    /// PROBE_OK sentinel — every body command failed and `|| true`
    /// silently swallowed the errors. Surfaced as a distinct variant
    /// so the UI can show "probe failed entirely" (likely shell
    /// missing, /proc unreadable, busybox stripped) rather than the
    /// less-actionable "nothing parsed" (which now means "we DID
    /// reach the sentinel but no metric line parsed"). Caught by
    /// review-agent on the burst review.
    #[error("probe script never reached PROBE_OK sentinel — body failed entirely")]
    ScriptDidNotComplete,
}

/// Single-script probe sent to the node. Self-contained — uses only
/// busybox-compatible tools, no jq, no awk-3-specific syntax.
///
/// Public so chunk 2 can audit-log it verbatim and tests can
/// build expected-output fixtures.
pub const PROBE_SCRIPT: &str = r#"
set -e
# systemd services we care about
for s in sing-box fail2ban; do
    state=$(systemctl is-active "$s" 2>/dev/null || true)
    echo "SVC $s ${state:-unknown}"
done
# sing-box monotonic restart counter. `is-active` only sees the state AT
# each probe, so a sing-box that OOMs and is auto-restarted BETWEEN two
# ten-minute probes shows `active` at both samples and the down detector
# never fires. NRestarts (systemd ≥ v235) is monotonic since the last
# host reboot / `systemctl reset-failed`; the daemon diffs consecutive
# readings and alerts on an increase. Empty value (no systemd / no
# NRestarts support) is swallowed → parser leaves the field NULL.
echo "NRESTARTS $(systemctl show -p NRestarts --value sing-box 2>/dev/null || true)"
# root filesystem usage in MiB (avoid -h since human suffix varies)
df -BM / 2>/dev/null | awk 'NR==2 {gsub(/M/,"",$3); gsub(/M/,"",$2); print "DISK /  " $3 "  " $2}' || true
# meminfo — MemTotal + MemAvailable in MiB (1 MiB = 1024 kB)
awk '/^MemTotal:/ {t=int($2/1024)} /^MemAvailable:/ {a=int($2/1024)} END {print "MEM  " a " " t}' /proc/meminfo 2>/dev/null || true
# loadavg
awk '{print "LOAD " $1}' /proc/loadavg 2>/dev/null || true
# listening sockets — ss is in iproute2, ships with every modern Debian
ss -tunl 2>/dev/null | awk 'NR>1 {
    proto=$1; sub(/.*:/, "", $5); print "PORT " proto " " $5
}' | sort -u || true
# sing-box log file size (bytes); 0 if missing
sb_log=/var/log/sing-box.log
if [ -f "$sb_log" ]; then
    echo "LOG_SB $(stat -c %s "$sb_log" 2>/dev/null || echo 0)"
fi
# Phase G chunk 2 — banned-self detector inputs.
# SSH_CLIENT format: "<client_ip> <client_port> <server_port>". sshd
# sets this from the kernel-known source IP of the connection, which
# clients cannot forge. Extract first space-separated field.
if [ -n "${SSH_CLIENT:-}" ]; then
    echo "SSH_CLIENT_IP ${SSH_CLIENT%% *}"
fi
# fail2ban banned IPs. Output of `fail2ban-client status sshd`:
#     ...
#     `- Banned IP list:	1.2.3.4 5.6.7.8
# Emit ONE BAN line per IP so the parser doesn't need to split.
# LC_ALL=C pins English output across non-C-locale hosts. Silent on
# missing fail2ban-client / sshd jail (exit non-zero swallowed).
if command -v fail2ban-client >/dev/null 2>&1; then
    LC_ALL=C fail2ban-client status sshd 2>/dev/null | awk -F: '
        /Banned IP list/ {
            sub(/^[[:space:]]+/, "", $2)
            n = split($2, ips, /[[:space:]]+/)
            for (i = 1; i <= n; i++) if (ips[i] != "") print "BAN " ips[i]
        }'
fi
# Kernel software versions. Busybox-safe, no outbound HTTP — the
# version strings come from the binaries already installed on the node.
# One "VER <name> <version>" line per kernel the probe could read. Used
# by the admin UI's drift-detail card to compare on-node vs fleet-target.
sb_ver=$(sing-box version 2>/dev/null | awk '/version/{print $NF; exit}')
[ -n "$sb_ver" ] && echo "VER sing-box $sb_ver"
command -v caddy >/dev/null 2>&1 && echo "VER caddy $(caddy version 2>/dev/null | awk '{print $1; exit}')"
# Public-interface byte counters — server-wide traffic ground truth.
# Catches ALL protocols (incl. non-sing-box: naive/Caddy, dns-tunnel,
# wgturn) so the total reconciles with the hoster's billing. Pick the
# default-route interface (the one carrying internet egress/ingress);
# emit its RAW cumulative rx/tx — the daemon diffs readings over time.
nic=$(ip route show default 2>/dev/null | awk '/default/ {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
if [ -n "$nic" ] && [ -d "/sys/class/net/$nic/statistics" ]; then
    rx=$(cat "/sys/class/net/$nic/statistics/rx_bytes" 2>/dev/null || echo "")
    tx=$(cat "/sys/class/net/$nic/statistics/tx_bytes" 2>/dev/null || echo "")
    [ -n "$rx" ] && [ -n "$tx" ] && echo "NIC $nic $rx $tx"
fi
# Completion sentinel. Every `|| true` above can silently swallow
# errors; without this line a totally-broken probe (no /proc, missing
# `ss`, busybox stripped) returns empty stdout and the parser can't
# tell "node OK, just quiet" from "node fundamentally broken".
# Parser requires this line; absence ⇒ `ScriptDidNotComplete`.
echo "PROBE_OK"
"#;

/// Trait the poller calls. Defined to mirror `ClashClient` for
/// consistency + so chunk 3 can wrap with retry/metrics layers
/// without re-implementing the parser.
#[async_trait]
pub trait ProbeClient: Send + Sync {
    async fn snapshot(&self) -> Result<Probe, ProbeError>;
}

/// Default implementation: SSH-exec to one VPN node.
#[derive(Debug)]
pub struct SshProbeClient<'a> {
    ssh: &'a dyn SshTransport,
}

impl<'a> SshProbeClient<'a> {
    pub fn new(ssh: &'a dyn SshTransport) -> Self {
        Self { ssh }
    }
}

#[async_trait]
impl ProbeClient for SshProbeClient<'_> {
    async fn snapshot(&self) -> Result<Probe, ProbeError> {
        let raw = self
            .ssh
            .exec(PROBE_SCRIPT)
            .await
            .map_err(|e| ProbeError::Transport(e.to_string()))?;
        parse_probe_output(&raw)
    }
}

/// Parse the tagged-line format the script emits.
pub fn parse_probe_output(raw: &str) -> Result<Probe, ProbeError> {
    let mut probe = Probe::default();
    let mut any_parsed = false;
    let mut saw_sentinel = false;
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line == "PROBE_OK" {
            saw_sentinel = true;
            continue;
        }
        let mut parts = line.split_whitespace();
        let tag = match parts.next() {
            Some(t) => t,
            None => continue,
        };
        match tag {
            "SVC" => {
                let name = parts.next();
                let state = parts.next();
                let active = match state {
                    Some("active") => Some(true),
                    Some(_) => Some(false),
                    None => continue,
                };
                match name {
                    Some("sing-box") => {
                        probe.sing_box_active = active;
                        any_parsed = true;
                    }
                    Some("fail2ban") => {
                        probe.fail2ban_active = active;
                        any_parsed = true;
                    }
                    _ => continue,
                }
            }
            "DISK" => {
                // DISK <mount> <used> <total>
                let _mount = parts.next();
                if let (Some(u), Some(t)) = (parts.next(), parts.next())
                    && let (Ok(uu), Ok(tt)) = (u.parse::<u64>(), t.parse::<u64>())
                {
                    probe.disk_used_mib = Some(uu);
                    probe.disk_total_mib = Some(tt);
                    any_parsed = true;
                }
            }
            "MEM" => {
                // MEM <avail> <total>
                if let (Some(a), Some(t)) = (parts.next(), parts.next())
                    && let (Ok(aa), Ok(tt)) = (a.parse::<u64>(), t.parse::<u64>())
                {
                    probe.mem_available_mib = Some(aa);
                    probe.mem_total_mib = Some(tt);
                    any_parsed = true;
                }
            }
            "LOAD" => {
                // LOAD <float>
                if let Some(l) = parts.next()
                    && let Ok(f) = l.parse::<f64>()
                {
                    // Round-half-away-from-zero into ×100.
                    let scaled = (f * 100.0).round();
                    if (0.0..=u32::MAX as f64).contains(&scaled) {
                        probe.load_1min_x100 = Some(scaled as u32);
                        any_parsed = true;
                    }
                }
            }
            "PORT" => {
                // PORT <proto> <port>
                if let (Some(p), Some(n)) = (parts.next(), parts.next())
                    && let Ok(port) = n.parse::<u16>()
                {
                    let proto = p.to_ascii_lowercase();
                    if proto == "tcp" || proto == "udp" {
                        probe.listening.insert((proto, port));
                        any_parsed = true;
                    }
                }
            }
            "LOG_SB" => {
                if let Some(b) = parts.next()
                    && let Ok(bytes) = b.parse::<u64>()
                {
                    probe.sing_box_log_bytes = Some(bytes);
                    any_parsed = true;
                }
            }
            "SSH_CLIENT_IP" => {
                // Defensive: validate it looks like a v4/v6 literal
                // before accepting. fail2ban stores literal IPs in
                // the banned list, so string-equal comparison is
                // what we need; reject anything containing a slash
                // (CIDR) or whitespace (junk).
                if let Some(ip) = parts.next()
                    && !ip.is_empty()
                    && !ip.contains('/')
                    && parts.next().is_none()
                {
                    probe.probe_source_ip = Some(ip.to_string());
                    any_parsed = true;
                }
            }
            "BAN" => {
                if let Some(ip) = parts.next()
                    && !ip.is_empty()
                {
                    probe
                        .fail2ban_banned_ips
                        .get_or_insert_with(Vec::new)
                        .push(ip.to_string());
                    any_parsed = true;
                }
            }
            "VER" => {
                // VER <kernel-name> <version>. Loose validation: a
                // version captured from arbitrary on-node binaries is
                // untrusted text rendered in the admin UI. Accept only
                // a non-empty, whitespace-free token of bounded length
                // (`parts.next()` already splits on whitespace, so the
                // value is single-token; the length cap defends against
                // a binary printing a banner instead of a version).
                if let (Some(name), Some(ver)) = (parts.next(), parts.next())
                    && parts.next().is_none()
                    && !name.is_empty()
                    && !ver.is_empty()
                    && ver.len() <= 32
                {
                    probe
                        .kernel_versions
                        .insert(name.to_string(), ver.to_string());
                    any_parsed = true;
                }
            }
            "NIC" => {
                // NIC <iface> <rx_bytes> <tx_bytes> — RAW cumulative
                // counters of the default-route interface. All three
                // fields set together (partial-success not meaningful
                // for a counter pair; either we read the iface's stats
                // or we didn't).
                if let (Some(ifc), Some(rx), Some(tx)) = (parts.next(), parts.next(), parts.next())
                    && parts.next().is_none()
                    && !ifc.is_empty()
                    && let (Ok(r), Ok(t)) = (rx.parse::<u64>(), tx.parse::<u64>())
                {
                    probe.nic_iface = Some(ifc.to_string());
                    probe.nic_rx_bytes = Some(r);
                    probe.nic_tx_bytes = Some(t);
                    any_parsed = true;
                }
            }
            "NRESTARTS" => {
                // NRESTARTS <count> — monotonic systemd restart counter
                // for sing-box. Empty value (systemctl failed / no
                // NRestarts support) yields no token → leave the field
                // None rather than treating it as zero (zero is a real,
                // meaningful reading: "unit never restarted").
                if let Some(n) = parts.next()
                    && let Ok(count) = n.parse::<u64>()
                {
                    probe.sing_box_nrestarts = Some(count);
                    any_parsed = true;
                }
            }
            _ => continue,
        }
    }
    // Sentinel-first: a totally-broken probe (no shell, no /proc)
    // returns empty stdout — distinguishing from "we ran but nothing
    // parsed" matters because the operator-facing failure modes
    // differ. See `ProbeError::ScriptDidNotComplete` for the
    // rationale (review-agent finding).
    if !saw_sentinel {
        return Err(ProbeError::ScriptDidNotComplete);
    }
    // Derive fail2ban_self_banned verdict. Both inputs must be
    // present — partial signal yields `None` (caller's no-op path).
    // This deliberately does NOT fire on empty-bans-list-but-IP-
    // known: that's "fail2ban running, nobody banned" → `Some(false)`,
    // the operator-clear state.
    if let (Some(my_ip), Some(bans)) = (
        probe.probe_source_ip.as_ref(),
        probe.fail2ban_banned_ips.as_ref(),
    ) {
        probe.fail2ban_self_banned = Some(bans.iter().any(|b| b == my_ip));
    }
    if any_parsed {
        Ok(probe)
    } else {
        Err(ProbeError::NothingParsed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use vpnctl_ssh::MockTransport;

    const SAMPLE: &str = "\
SVC sing-box active
SVC fail2ban active
DISK /  9876  20480
MEM  483 960
LOAD 0.04
PORT tcp 22
PORT tcp 443
PORT tcp 8443
PORT udp 8388
PORT udp 8443
LOG_SB 308432
VER sing-box 1.13.12
VER caddy 2.8.4
NIC ens18 123456789 987654321
NRESTARTS 3
PROBE_OK
";

    #[test]
    fn parses_full_probe_output() {
        let p = parse_probe_output(SAMPLE).unwrap();
        assert_eq!(p.sing_box_active, Some(true));
        assert_eq!(p.fail2ban_active, Some(true));
        assert_eq!(p.disk_used_mib, Some(9876));
        assert_eq!(p.disk_total_mib, Some(20480));
        assert_eq!(p.mem_available_mib, Some(483));
        assert_eq!(p.mem_total_mib, Some(960));
        assert_eq!(p.load_1min_x100, Some(4));
        assert_eq!(p.sing_box_log_bytes, Some(308_432));
        assert_eq!(p.listening.len(), 5);
        assert!(p.listening.contains(&("tcp".into(), 443)));
        assert!(p.listening.contains(&("udp".into(), 8443)));
        // SAMPLE has no SSH_CLIENT_IP / BAN lines → no signal.
        assert_eq!(p.probe_source_ip, None);
        assert_eq!(p.fail2ban_banned_ips, None);
        assert_eq!(p.fail2ban_self_banned, None);
        // PR-Q — VER lines populate the kernel-version map.
        assert_eq!(
            p.kernel_versions.get("sing-box").map(String::as_str),
            Some("1.13.12")
        );
        assert_eq!(
            p.kernel_versions.get("caddy").map(String::as_str),
            Some("2.8.4")
        );
        assert_eq!(p.kernel_versions.len(), 2);
        // Traffic ground-truth — NIC line parses into the cumulative
        // counters used for the gap computation.
        assert_eq!(p.nic_iface.as_deref(), Some("ens18"));
        assert_eq!(p.nic_rx_bytes, Some(123_456_789));
        assert_eq!(p.nic_tx_bytes, Some(987_654_321));
        // Restart detection — NRESTARTS line parses into the monotonic
        // systemd counter the health monitor diffs across samples.
        assert_eq!(p.sing_box_nrestarts, Some(3));
    }

    #[test]
    fn nrestarts_line_parses_and_handles_absent_or_empty() {
        // A present counter parses (including zero — a real reading).
        let zero = parse_probe_output("SVC sing-box active\nNRESTARTS 0\nPROBE_OK\n").unwrap();
        assert_eq!(zero.sing_box_nrestarts, Some(0));
        // No NRESTARTS line (non-systemd host / old systemd) → None, NOT
        // zero — the monitor must distinguish "no signal" from "never
        // restarted".
        let absent = parse_probe_output("SVC sing-box active\nPROBE_OK\n").unwrap();
        assert_eq!(absent.sing_box_nrestarts, None);
        // Empty value (the script's `|| true` swallowed a failure) emits a
        // bare tag with no token → None.
        let empty = parse_probe_output("SVC sing-box active\nNRESTARTS\nPROBE_OK\n").unwrap();
        assert_eq!(empty.sing_box_nrestarts, None);
        // Non-numeric junk → None (parser rejects, field stays unset).
        let junk = parse_probe_output("SVC sing-box active\nNRESTARTS abc\nPROBE_OK\n").unwrap();
        assert_eq!(junk.sing_box_nrestarts, None);
    }

    #[test]
    fn nic_line_partial_or_malformed_leaves_fields_none() {
        // No NIC line at all → all three None (node with no default route).
        let none = parse_probe_output("SVC sing-box active\nPROBE_OK\n").unwrap();
        assert_eq!(none.nic_iface, None);
        assert_eq!(none.nic_rx_bytes, None);
        assert_eq!(none.nic_tx_bytes, None);
        // Non-numeric counter → the whole NIC line is rejected (no partial).
        let bad = parse_probe_output("SVC sing-box active\nNIC ens18 abc 100\nPROBE_OK\n").unwrap();
        assert_eq!(bad.nic_iface, None);
        assert_eq!(bad.nic_rx_bytes, None);
    }

    // ─── Phase G chunk 2 — banned-self detector parser ─────────

    #[test]
    fn parses_ssh_client_ip_and_bans_yields_self_banned_true() {
        // Daemon's outbound IP is among the banned set → fire.
        let raw = "\
SVC sing-box active
SSH_CLIENT_IP 192.168.0.236
BAN 192.168.0.236
BAN 1.2.3.4
PROBE_OK
";
        let p = parse_probe_output(raw).unwrap();
        assert_eq!(p.probe_source_ip.as_deref(), Some("192.168.0.236"));
        assert_eq!(
            p.fail2ban_banned_ips,
            Some(vec!["192.168.0.236".into(), "1.2.3.4".into()])
        );
        assert_eq!(
            p.fail2ban_self_banned,
            Some(true),
            "our IP appears in the banned set → must fire"
        );
    }

    #[test]
    fn parses_bans_without_self_match_yields_self_banned_false() {
        // fail2ban running, some IPs banned, none is ours → clear.
        let raw = "\
SVC sing-box active
SSH_CLIENT_IP 192.168.0.236
BAN 1.2.3.4
BAN 5.6.7.8
PROBE_OK
";
        let p = parse_probe_output(raw).unwrap();
        assert_eq!(
            p.fail2ban_self_banned,
            Some(false),
            "bans present but not our IP → operator-clear"
        );
    }

    #[test]
    fn parses_no_bans_with_ip_known_yields_self_banned_false() {
        // fail2ban up, BAN line absent (means we DID query and got
        // no entries — empty `Banned IP list:` produces zero BAN
        // lines from the awk script). We still emitted SSH_CLIENT_IP,
        // so the verdict requires fail2ban_banned_ips = Some(_).
        // The parser only derives `Some(_)` for self_banned when
        // BOTH inputs are Some — an absent BAN entirely (no BAN
        // lines at all) leaves fail2ban_banned_ips as None.
        //
        // This test pins that semantics: "fail2ban-client missing
        // OR jail missing OR command failed" all look identical
        // (zero BAN lines) and produce a No-signal verdict, not
        // a false-positive "everything's clear".
        let raw = "\
SVC sing-box active
SSH_CLIENT_IP 192.168.0.236
PROBE_OK
";
        let p = parse_probe_output(raw).unwrap();
        assert_eq!(p.probe_source_ip.as_deref(), Some("192.168.0.236"));
        assert_eq!(p.fail2ban_banned_ips, None);
        assert_eq!(
            p.fail2ban_self_banned, None,
            "no BAN signal → no verdict (NOT a false 'clear')"
        );
    }

    #[test]
    fn parses_bans_without_ssh_client_yields_no_verdict() {
        // Defensive: even if fail2ban reports bans, without knowing
        // our own IP we can't say whether we're in there. Strictly
        // no-signal — caller's no-op path.
        let raw = "\
SVC sing-box active
BAN 1.2.3.4
PROBE_OK
";
        let p = parse_probe_output(raw).unwrap();
        assert_eq!(p.probe_source_ip, None);
        assert_eq!(p.fail2ban_banned_ips, Some(vec!["1.2.3.4".into()]));
        assert_eq!(
            p.fail2ban_self_banned, None,
            "without our IP, cannot decide → no verdict"
        );
    }

    #[test]
    fn ssh_client_ip_rejects_cidr_and_junk() {
        // Defensive shape gate: an IP with a `/` (CIDR) or extra
        // tokens after the IP is rejected as malformed.
        let raw_cidr = "\
SVC sing-box active
SSH_CLIENT_IP 192.168.0.236/24
PROBE_OK
";
        let p = parse_probe_output(raw_cidr).unwrap();
        assert_eq!(
            p.probe_source_ip, None,
            "CIDR-shaped value must be rejected upstream"
        );

        let raw_extra = "\
SVC sing-box active
SSH_CLIENT_IP 192.168.0.236 something-else-here
PROBE_OK
";
        let p = parse_probe_output(raw_extra).unwrap();
        assert_eq!(
            p.probe_source_ip, None,
            "extra tokens on the line must be rejected"
        );
    }

    #[test]
    fn disk_pct_calculation() {
        let p = Probe {
            disk_used_mib: Some(9876),
            disk_total_mib: Some(20480),
            ..Probe::default()
        };
        // 9876 / 20480 = 48.22%, floor → 48
        assert_eq!(p.disk_pct(), Some(48));
    }

    #[test]
    fn disk_pct_handles_division_by_zero() {
        let p = Probe {
            disk_used_mib: Some(100),
            disk_total_mib: Some(0),
            ..Probe::default()
        };
        assert_eq!(p.disk_pct(), None);
    }

    #[test]
    fn disk_pct_clamps_over_100() {
        let p = Probe {
            disk_used_mib: Some(110),
            disk_total_mib: Some(100),
            ..Probe::default()
        };
        // Overcommit (snapshots, sparse). Clamp to 100, not panic.
        assert_eq!(p.disk_pct(), Some(100));
    }

    #[test]
    fn mem_used_pct_calculation() {
        let p = Probe {
            mem_available_mib: Some(483),
            mem_total_mib: Some(960),
            ..Probe::default()
        };
        // used = 100 - (483 * 100 / 960) = 100 - 50 = 50
        assert_eq!(p.mem_used_pct(), Some(50));
    }

    #[test]
    fn parses_inactive_services() {
        let raw = "SVC sing-box inactive\nSVC fail2ban failed\nPROBE_OK\n";
        let p = parse_probe_output(raw).unwrap();
        assert_eq!(p.sing_box_active, Some(false));
        assert_eq!(p.fail2ban_active, Some(false));
    }

    #[test]
    fn skips_unknown_tags_quietly() {
        let raw = "JUNK something\nSVC sing-box active\nMORE junk\nPROBE_OK\n";
        let p = parse_probe_output(raw).unwrap();
        assert_eq!(p.sing_box_active, Some(true));
    }

    #[test]
    fn nothing_parsed_returns_err_when_sentinel_present_but_no_metric() {
        // Body lines all garbage but sentinel reached → distinct from
        // ScriptDidNotComplete; means "we ran, just no metrics".
        let raw = "garbage\nmore garbage\nPROBE_OK\n";
        let err = parse_probe_output(raw).unwrap_err();
        assert!(matches!(err, ProbeError::NothingParsed));
    }

    #[test]
    fn no_sentinel_returns_script_did_not_complete() {
        // The interesting failure mode: shell broken, /proc unreadable,
        // ss missing — every `|| true` swallows the error, stdout is
        // empty / has no PROBE_OK line. Different operator action
        // than NothingParsed.
        let err = parse_probe_output("").unwrap_err();
        assert!(matches!(err, ProbeError::ScriptDidNotComplete));
        let err2 = parse_probe_output("garbage\nmore garbage\n").unwrap_err();
        assert!(matches!(err2, ProbeError::ScriptDidNotComplete));
    }

    #[test]
    fn partial_parse_succeeds_with_some_fields_none() {
        // Only LOAD parses; everything else garbage. Sentinel present.
        let raw = "LOAD 1.23\nDISK garbage data\nMEM also broken\nPROBE_OK\n";
        let p = parse_probe_output(raw).unwrap();
        assert_eq!(p.load_1min_x100, Some(123));
        assert_eq!(p.disk_used_mib, None);
        assert_eq!(p.mem_available_mib, None);
    }

    #[test]
    fn listening_set_is_deterministic_sort_order() {
        // BTreeSet → iteration order matches sort order; same input
        // twice produces same Vec when iterated.
        let p1 = parse_probe_output(SAMPLE).unwrap();
        let p2 = parse_probe_output(SAMPLE).unwrap();
        let v1: Vec<_> = p1.listening.iter().collect();
        let v2: Vec<_> = p2.listening.iter().collect();
        assert_eq!(v1, v2);
    }

    #[tokio::test]
    async fn snapshot_via_mock_ssh_returns_parsed_probe() {
        let ssh = MockTransport::new();
        ssh.expect(PROBE_SCRIPT, SAMPLE);
        let client = SshProbeClient::new(&ssh);
        let p = client.snapshot().await.unwrap();
        assert_eq!(p.sing_box_active, Some(true));
        assert_eq!(p.disk_pct(), Some(48));
    }

    #[tokio::test]
    async fn snapshot_with_garbage_returns_script_did_not_complete() {
        // No PROBE_OK sentinel → ScriptDidNotComplete (NOT
        // NothingParsed). The garbage doesn't matter; the absence
        // of the sentinel does.
        let ssh = MockTransport::new();
        ssh.expect(PROBE_SCRIPT, "junk\nmore junk\n");
        let client = SshProbeClient::new(&ssh);
        let err = client.snapshot().await.unwrap_err();
        assert!(matches!(err, ProbeError::ScriptDidNotComplete));
    }

    // ─── PR-Q — kernel-version capture parser ──────────────────

    #[test]
    fn parses_kernel_versions_from_ver_lines() {
        let raw = "\
SVC sing-box active
VER sing-box 1.13.12
VER caddy 2.8.4
PROBE_OK
";
        let p = parse_probe_output(raw).unwrap();
        assert_eq!(
            p.kernel_versions.get("sing-box").map(String::as_str),
            Some("1.13.12")
        );
        assert_eq!(
            p.kernel_versions.get("caddy").map(String::as_str),
            Some("2.8.4")
        );
    }

    #[test]
    fn missing_ver_lines_yields_empty_map_not_error() {
        // A probe with no VER lines is still a valid probe — the map is
        // simply empty, NOT an error (old node / partial-probe tick).
        let raw = "SVC sing-box active\nPROBE_OK\n";
        let p = parse_probe_output(raw).unwrap();
        assert!(
            p.kernel_versions.is_empty(),
            "no VER lines → empty map, not error"
        );
    }

    #[test]
    fn malformed_ver_lines_are_skipped() {
        // Missing the version token, an empty value, extra trailing
        // tokens (a banner instead of a bare version), and an
        // over-32-char value are all rejected; only the well-formed
        // line lands in the map.
        let long = "x".repeat(33);
        let raw = format!(
            "\
VER sing-box
VER caddy 2.8.4 extra-banner-token
VER bad {long}
VER good 1.0.0
PROBE_OK
"
        );
        let p = parse_probe_output(&raw).unwrap();
        assert_eq!(
            p.kernel_versions.get("good").map(String::as_str),
            Some("1.0.0")
        );
        assert!(!p.kernel_versions.contains_key("sing-box"));
        assert!(!p.kernel_versions.contains_key("caddy"));
        assert!(!p.kernel_versions.contains_key("bad"));
        assert_eq!(p.kernel_versions.len(), 1);
    }

    #[test]
    fn probe_script_pins_security_invariants() {
        // Doesn't curl anywhere (no exfil), uses standard tools only,
        // doesn't write to stdout from sing-box itself (would leak
        // user data into our parser). Pin against future edits that
        // would weaken these.
        assert!(!PROBE_SCRIPT.contains("curl"), "no outbound HTTP");
        assert!(!PROBE_SCRIPT.contains("wget"), "no outbound HTTP");
        assert!(!PROBE_SCRIPT.contains("nc "), "no netcat");
        assert!(PROBE_SCRIPT.contains("ss -tunl"), "uses ss");
        assert!(
            PROBE_SCRIPT.contains("/proc/loadavg"),
            "uses /proc, not uptime command"
        );
        // Phase G chunk 2 — banned-self detector probes.
        assert!(
            PROBE_SCRIPT.contains("SSH_CLIENT"),
            "emits SSH_CLIENT_IP for banned-self verdict"
        );
        assert!(
            PROBE_SCRIPT.contains("fail2ban-client status sshd"),
            "queries fail2ban for banned sshd IPs"
        );
        assert!(
            PROBE_SCRIPT.contains("LC_ALL=C"),
            "pins fail2ban-client English output across non-C locales"
        );
        // PR-Q — kernel-version capture is busybox-safe (the no-curl /
        // no-wget asserts above must continue to hold with VER lines
        // present) and reads versions from on-node binaries.
        assert!(
            PROBE_SCRIPT.contains("sing-box version"),
            "captures sing-box version for the drift-detail card"
        );
        assert!(
            PROBE_SCRIPT.contains("VER sing-box"),
            "emits a VER line the parser can pick up"
        );
    }
}
