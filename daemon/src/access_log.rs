//! Bounded back-pressure for `/sub/<token>` access logging.
//!
//! Why this exists
//! ---------------
//! Phase Track-1 first wired the access log via `tokio::spawn` per
//! request — fire-and-forget, no concurrency cap. Both the retroactive
//! review-agent (review #3) and security-review (security #2)
//! independently flagged the same DoS surface: an attacker holding ONE
//! valid sub-token can hit `/sub/<token>` in a tight loop, each hit
//! spawns a background task, the SQLite pool saturates, the task
//! queue grows unbounded — eventually OOM.
//!
//! This module replaces the spawn-per-request pattern with:
//!   1. A bounded `tokio::sync::mpsc` channel sized at
//!      `ACCESS_LOG_CHANNEL_CAP` records (default 1024).
//!   2. ONE dedicated writer task that drains the channel sequentially
//!      and calls `inv.log_sub_access(...)` per record.
//!   3. The `/sub` handler does `try_send` (non-blocking) — full
//!      channel → drop the record + warn-log (back-pressure signal).
//!      The HTTP response is unaffected (still 200).
//!
//! Lifecycle
//! ---------
//! `AppState` owns the `Sender`. Cloning `AppState` (which axum does
//! per-request via `with_state`) clones the sender — channel stays
//! open as long as ANY clone of the state lives. When the runtime
//! shuts down (graceful shutdown drops the router + state), all
//! senders drop, the receiver sees `None`, the writer task drains
//! pending records and exits.
//!
//! Why a dedicated writer instead of N spawn-per-request
//! -----------------------------------------------------
//! The SQLite pool is small (8 connections); per-request spawn already
//! serialised at that bottleneck. The dedicated writer makes the
//! serialisation explicit AND bounds the in-memory queue, which is
//! what the spawn model lacked.

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use vpnctl_core::UserId;
use vpnctl_inventory::SqliteInventory;

/// Channel capacity. 1024 records is plenty: at ~150 bytes per record
/// (UserId String + IP String + UA String + ints) the queue caps at
/// ~150 KiB. Even on a flooded daemon the writer task drains at SQLite-
/// INSERT speed (sub-millisecond on WAL), so the queue rarely fills
/// past single digits in practice. The bound exists so a pathological
/// burst can't OOM the process before the operator notices the abuse
/// signal.
pub const ACCESS_LOG_CHANNEL_CAP: usize = 1024;

/// One subscription-fetch record en route to `sub_access_log`. The
/// `/sub` handler builds this and sends it; the writer task drains
/// and persists it.
#[derive(Debug, Clone)]
pub struct AccessLogRecord {
    pub user_id: UserId,
    pub ip: String,
    pub ua: Option<String>,
    pub status: u16,
    pub bytes: u64,
    // Track-1.2 (migration 0019) — richer per-request metadata.
    // All Optional; handler captures what it can off the incoming
    // request, writer leaves NULL in SQL when None.
    pub accept_language: Option<String>,
    pub http_version: Option<String>,
    pub device_class: Option<String>,
    // GeoIP fields are FILLED INSIDE THE WRITER TASK, not the
    // handler — keeps handler latency stable + lets us batch /
    // cache / mock lookups in one place. Handler always passes
    // None for these.
    pub geo_country: Option<String>,
    pub geo_asn: Option<String>,
    // Track-1.4 (migration 0020) — TLS client fingerprint forwarded
    // by nginx via `X-SSL-JA3` / `X-SSL-JA4` headers. Handler reads
    // them ONLY when the immediate peer is in
    // `VPNCTLD_TRUSTED_PROXIES` (same trust gate as XFF). Stays
    // None until the operator installs an nginx-side JA3/JA4 module
    // — schema is ready; capture is gated on host config.
    pub tls_ja3: Option<String>,
    pub tls_ja4: Option<String>,
}

/// Spin up the writer task. Returns the channel sender (handed to
/// `AppState` so handlers can `try_send`) plus the `JoinHandle` (so
/// `build()` can keep it alive for the process lifetime, and tests
/// can `abort()` it deterministically).
///
/// The writer loop terminates ONLY when all senders drop — that's the
/// graceful-shutdown signal. There is no explicit cancellation token
/// because the `mpsc::Receiver::recv()` returning `None` is the
/// canonical "channel closed" check; adding a token would just be a
/// second source of truth that could disagree.
pub fn spawn_writer(inv: SqliteInventory) -> (mpsc::Sender<AccessLogRecord>, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel::<AccessLogRecord>(ACCESS_LOG_CHANNEL_CAP);
    let handle = tokio::spawn(run_writer(inv, rx));
    (tx, handle)
}

/// Drain the channel forever (until all senders drop). Each record is
/// persisted via `log_sub_access`; failures log a warn but never abort
/// the loop — losing one row is preferable to losing the whole
/// abuse-detection feature because of a transient SQLite hiccup.
async fn run_writer(inv: SqliteInventory, mut rx: mpsc::Receiver<AccessLogRecord>) {
    // GeoIP lookup is best-effort: if the daemon was built without
    // the DB, or the DB file isn't present, every lookup returns
    // None and the columns stay NULL. We construct ONCE here so the
    // mmap (when available) is shared across all writes for this
    // task's lifetime.
    let geoip = crate::geoip::GeoLookup::from_env();
    if geoip.is_loaded() {
        tracing::info!(
            target = "vpnctld::access_log_writer",
            "GeoIP DB loaded — sub_access_log rows will be enriched with country + ASN"
        );
    } else {
        tracing::debug!(
            target = "vpnctld::access_log_writer",
            "GeoIP DB not loaded — geo_country / geo_asn columns will be NULL (set VPNCTLD_GEOIP_DIR + drop GeoLite2-{{City,ASN}}.mmdb to enable)"
        );
    }

    while let Some(mut rec) = rx.recv().await {
        // Enrich with GeoIP before persisting (handler always sends
        // None for these two; we fill them here so handler latency
        // is unaffected by DB lookups).
        if geoip.is_loaded() {
            if let Ok(parsed_ip) = rec.ip.parse() {
                if let Some(info) = geoip.lookup(parsed_ip) {
                    // Compute asn_label first so the partial-move of
                    // `info.country_iso` below doesn't surprise the
                    // reader. (Borrow ends at the `;`, so order isn't
                    // strictly necessary — just easier to follow.)
                    let asn_label = info.asn_label();
                    if rec.geo_country.is_none() {
                        rec.geo_country = info.country_iso;
                    }
                    if rec.geo_asn.is_none() {
                        rec.geo_asn = asn_label;
                    }
                }
            }
        }
        let log_result = inv
            .log_sub_access_rich(
                &rec.user_id,
                &rec.ip,
                rec.ua.as_deref(),
                rec.status,
                rec.bytes,
                rec.accept_language.as_deref(),
                rec.http_version.as_deref(),
                rec.device_class.as_deref(),
                rec.geo_country.as_deref(),
                rec.geo_asn.as_deref(),
                rec.tls_ja3.as_deref(),
                rec.tls_ja4.as_deref(),
            )
            .await;
        match log_result {
            Ok(()) => {
                // Pavel 2026-05-21: «если видим 127.0.0.1 или любой из
                // 192.168/10/172.16-31 (метка LAN) и 169.254.* — это
                // инцидент, который требует разбирательства». The
                // writer is the right hook site — handler stays
                // latency-stable, the persisted row is linkable from
                // the alert payload, the predicate is a pure match on
                // `IpKind` + a `&str` compare on `device_class`.
                //
                // Dedup bucket is per-user (`sub_access.suspicious_local_ip:<user_id>`)
                // so one chatty user can't swallow another user's
                // alert via the partial UNIQUE index on
                // (kind, COALESCE(server_id,'__GLOBAL__')) WHERE
                // acked_at IS NULL. The single allowlist entry today
                // is the phase6-monitor canary (see
                // /etc/cron.d/phase6-monitor on the daemon host; UA
                // tagged `phase6-monitor/1.0 (…-compat probe)` →
                // `parse_ua_short` returns `Some("phase6-monitor (canary)")`).
                let kind = crate::ip_kind::classify_ip(&rec.ip);
                if kind.is_lan_or_loopback()
                    && !is_lan_alert_allowed(rec.device_class.as_deref())
                    && !is_trusted_reverse_proxy(&rec.ip)
                    && !is_allowlisted_service_ip(&rec.ip)
                {
                    if let Err(e) = fire_suspicious_local_ip_alert(&inv, &rec, kind).await {
                        tracing::warn!(
                            target = "vpnctld::access_log_writer",
                            user = %rec.user_id,
                            ip = %rec.ip,
                            kind = kind.label(),
                            error = %e,
                            "sub_access.suspicious_local_ip alert insert failed (row persisted, no alert raised this time)"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    target = "vpnctld::access_log_writer",
                    user = %rec.user_id,
                    ip = %rec.ip,
                    error = %e,
                    "log_sub_access write failed (record dropped)"
                );
            }
        }
    }
    tracing::info!(
        target = "vpnctld::access_log_writer",
        "channel closed, writer exiting cleanly"
    );
}

/// User-Agent labels that are EXPECTED to hit a LAN / loopback peer
/// IP and therefore should NOT raise
/// `sub_access.suspicious_local_ip`. The values are the
/// `parse_ua_short` output strings (NOT raw UA — the snapshot
/// already normalises across UA-version drift).
///
/// Today this list has one entry — Pavel's `/etc/cron.d/phase6-monitor`
/// canary, which hits localhost daily and was the original false-
/// positive that motivated the alert design. Promote to an
/// `admin_settings` row (operator-editable via /admin/settings)
/// once we have a second entry — until then the recompile-to-extend
/// posture is the safer default (every addition forces a
/// review-agent gate).
const SUSPICIOUS_LAN_ALLOWED_UAS: &[&str] = &["phase6-monitor (canary)"];

/// True when this `device_class` snapshot is on the allowlist for
/// LAN/loopback peer IPs (i.e. don't fire the alert).
fn is_lan_alert_allowed(device_class: Option<&str>) -> bool {
    match device_class {
        Some(s) => SUSPICIOUS_LAN_ALLOWED_UAS.contains(&s),
        None => false,
    }
}

/// True when `ip_str` parses to an `IpAddr` that is **explicitly
/// listed** in `VPNCTLD_TRUSTED_PROXIES`. In that case the LAN IP
/// is the operator-configured reverse-proxy ingress (typically nginx
/// terminating TLS on a different host), NOT a suspicious local
/// fetch. Without this gate, a trusted-proxies misconfiguration
/// (env-var unset OR proxy host added to the LAN but XFF not sent)
/// produces one false-positive alert per legit external client —
/// alert-fatigue that hides real LAN-fetch incidents.
///
/// **Regression catch (2026-05-23, follow-up to I4):** Bundle 1 made
/// `trusted_proxies()` empty-by-default. On prod 192.168.0.236 the
/// env-var wasn't set after deploy; every legit /sub fetch through
/// nginx (192.168.0.207) fired this alert. The env-var was set
/// post-incident, AND this trusted-proxy gate was added so a future
/// operator hitting the same path («ah, trusted-proxies must be
/// set») ALSO doesn't see false-positives from the LAN-detector
/// during the few minutes between deploy and env-config.
fn is_trusted_reverse_proxy(ip_str: &str) -> bool {
    match ip_str.parse::<std::net::IpAddr>() {
        Ok(ip) => crate::real_ip::trusted_proxies().contains(&ip),
        Err(_) => false,
    }
}

/// Lazy-init cache of `VPNCTLD_SUSPICIOUS_IP_ALLOWLIST` — operator-
/// declared SERVICE hosts whose subscription fetches are expected and
/// must not raise `sub_access.suspicious_local_ip`. Same OnceLock
/// posture as `real_ip::trusted_proxies` (config is daemon-lifetime).
static SUSPICIOUS_IP_ALLOWLIST: std::sync::OnceLock<Vec<std::net::IpAddr>> =
    std::sync::OnceLock::new();

/// Read `VPNCTLD_SUSPICIOUS_IP_ALLOWLIST` (comma-separated `IpAddr`
/// list; default EMPTY — every LAN/loopback fetch alerts unless the
/// operator opts specific hosts out).
///
/// Why this exists (alerts-cleanup 2026-06-10): on Pavel's homelab the
/// open alert feed was ~80% `suspicious_local_ip` rows caused by OUR
/// OWN service traffic — post-deploy verification curls from the
/// claude-chat container (192.168.0.200) and localhost smoke checks
/// (127.0.0.1). Those are not incidents; alert-fatigue buries the one
/// row that IS (an unknown LAN device fetching a subscription).
/// Distinct from `VPNCTLD_TRUSTED_PROXIES`: a proxy forwards OTHER
/// clients (XFF is honoured, alerting then sees the real source); an
/// allowlisted host is itself the expected client. The access-log ROW
/// is still written either way — only the alert is skipped, so the
/// user's fetch history stays complete.
fn suspicious_ip_allowlist() -> &'static [std::net::IpAddr] {
    SUSPICIOUS_IP_ALLOWLIST.get_or_init(|| {
        std::env::var("VPNCTLD_SUSPICIOUS_IP_ALLOWLIST")
            .ok()
            .map(|s| {
                s.split(',')
                    .filter_map(|x| x.trim().parse::<std::net::IpAddr>().ok())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    })
}

/// True when `ip_str` is on the operator's expected-service-host
/// allowlist (don't fire the suspicious-LAN alert). Thin env wrapper
/// over [`is_allowlisted_service_ip_with`] — the `_with` split keeps
/// the positive branch testable without process-mutating env vars
/// (same convention as `real_ip::resolve_real_ip_with`).
fn is_allowlisted_service_ip(ip_str: &str) -> bool {
    is_allowlisted_service_ip_with(ip_str, suspicious_ip_allowlist())
}

fn is_allowlisted_service_ip_with(ip_str: &str, allowlist: &[std::net::IpAddr]) -> bool {
    match ip_str.parse::<std::net::IpAddr>() {
        Ok(ip) => allowlist.contains(&ip),
        Err(_) => false,
    }
}

/// Fire (or no-op-dedup against an existing unacked) the
/// `sub_access.suspicious_local_ip:<user_id>` alert. A fresh alert is
/// also mirrored to the audit timeline and the configured notification
/// transport; a deduplicated repeat stays quiet on all three surfaces.
/// The `:<user_id>` suffix gives each user its own dedup bucket via
/// the partial UNIQUE index on `(kind, COALESCE(server_id,
/// '__GLOBAL__')) WHERE acked_at IS NULL`. Severity is `warning`
/// — this is a discrepancy worth investigating, not an outage.
///
/// Payload is strictly non-secret: never include `sub_token`,
/// `uuid`, `wireguard_private`, etc.
async fn fire_suspicious_local_ip_alert(
    inv: &SqliteInventory,
    rec: &AccessLogRecord,
    kind: crate::ip_kind::IpKind,
) -> anyhow::Result<()> {
    let kind_str = format!("sub_access.suspicious_local_ip:{}", rec.user_id);
    let ua_label = rec
        .device_class
        .as_deref()
        .unwrap_or_else(|| rec.ua.as_deref().unwrap_or("(none)"));
    let summary = format!(
        "local-loop fetch · user={} · ip={} [{}] · ua={}",
        rec.user_id,
        rec.ip,
        kind.label(),
        ua_label,
    );
    let payload = serde_json::json!({
        "user_id": rec.user_id.0,
        "ip": rec.ip,
        "ip_kind": kind.label(),
        "ua": rec.ua,
        "device_class": rec.device_class,
        "accept_language": rec.accept_language,
        "http_version": rec.http_version,
    });
    let payload_str = payload.to_string();
    if let Some(alert_id) = inv
        .insert_alert_if_no_unacked(&kind_str, None, "warning", &summary, Some(&payload_str))
        .await?
    {
        // Every newly-created operator alert is reflected in the
        // unified audit timeline. This writer originally inserted only
        // the alert row, which made this security-relevant condition
        // invisible from /admin/audit.
        if let Err(e) = inv
            .audit(
                "vpnctld",
                "alert.fire",
                Some(&rec.user_id.0),
                Some(&serde_json::json!({
                    "alert_id": alert_id,
                    "kind": kind_str,
                    "severity": "warning",
                    "summary": summary,
                })),
            )
            .await
        {
            tracing::warn!(
                target = "vpnctld::access_log_writer",
                alert_id,
                user = %rec.user_id,
                error = %e,
                "alert.fire audit row failed; suspicious-IP alert remains open"
            );
        }

        // Reuse the common localized delivery path. It is best-effort:
        // a missing or failing transport never hides the durable alert
        // row above.
        crate::node_probe_poller::push_alert(
            inv,
            &kind_str,
            "warning",
            &rec.user_id.0,
            &payload,
            Some(alert_id),
        )
        .await;
    }
    Ok(())
}

/// Helper used by the `/sub` handler: try to enqueue a record without
/// blocking. Channel-full → log a `warn` (the back-pressure signal —
/// operator should investigate why the writer is falling behind) and
/// drop the record; channel-closed → log an `error` (writer task
/// crashed, which shouldn't happen).
///
/// Returns `true` if the record was enqueued, `false` if dropped.
/// Callers don't normally check the return — the response is 200
/// either way; this is purely a logging-completeness signal.
pub fn try_enqueue(tx: &mpsc::Sender<AccessLogRecord>, rec: AccessLogRecord) -> bool {
    use tokio::sync::mpsc::error::TrySendError;
    match tx.try_send(rec) {
        Ok(()) => true,
        Err(TrySendError::Full(rec)) => {
            tracing::warn!(
                target = "vpnctld::sub",
                user = %rec.user_id,
                ip = %rec.ip,
                cap = ACCESS_LOG_CHANNEL_CAP,
                "access log channel full ({} records), dropping row (back-pressure trigger)",
                ACCESS_LOG_CHANNEL_CAP
            );
            false
        }
        Err(TrySendError::Closed(rec)) => {
            tracing::error!(
                target = "vpnctld::sub",
                user = %rec.user_id,
                ip = %rec.ip,
                "access log channel closed unexpectedly — writer task exited; row lost"
            );
            false
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// `is_trusted_reverse_proxy` returns false for any input on its
    /// own — but it must not PANIC on garbage. The real
    /// trusted-proxies set is env-driven (`VPNCTLD_TRUSTED_PROXIES`),
    /// which makes a fully-positive test process-mutating + flaky
    /// under cargo test. We pin the no-panic + obvious-false cases
    /// here; the positive «IP is in the trusted list» branch is
    /// covered indirectly by `real_ip::tests::*_with` variants
    /// (which exercise the same `&[IpAddr]` lookup).
    /// Alerts-cleanup 2026-06-10: service hosts on the allowlist must
    /// suppress the suspicious-LAN alert; everything else must not.
    /// Positive branch via `_with` (env-free, parallel-safe).
    #[test]
    fn allowlisted_service_ip_matches_exactly() {
        let list: Vec<std::net::IpAddr> = vec![
            "127.0.0.1".parse().unwrap(),
            "192.168.0.200".parse().unwrap(),
        ];
        assert!(is_allowlisted_service_ip_with("127.0.0.1", &list));
        assert!(is_allowlisted_service_ip_with("192.168.0.200", &list));
        assert!(!is_allowlisted_service_ip_with("192.168.0.201", &list));
        assert!(!is_allowlisted_service_ip_with("not-an-ip", &list));
        assert!(!is_allowlisted_service_ip_with("127.0.0.1", &[]));
    }

    #[test]
    fn is_trusted_reverse_proxy_returns_false_for_garbage_input() {
        assert!(!is_trusted_reverse_proxy(""));
        assert!(!is_trusted_reverse_proxy("not-an-ip"));
        assert!(!is_trusted_reverse_proxy("999.999.999.999"));
    }

    #[test]
    fn is_trusted_reverse_proxy_returns_false_when_env_empty() {
        // Default test env has VPNCTLD_TRUSTED_PROXIES unset →
        // `trusted_proxies()` returns `&[]` → no IP can match.
        // (Post-I4 contract from Bundle 1.)
        assert!(!is_trusted_reverse_proxy("192.168.0.207"));
        assert!(!is_trusted_reverse_proxy("10.0.0.1"));
        assert!(!is_trusted_reverse_proxy("127.0.0.1"));
    }

    #[tokio::test]
    async fn suspicious_local_ip_alert_is_audited_once_per_open_condition() {
        let dir = tempfile::tempdir().unwrap();
        let inv = SqliteInventory::open(&dir.path().join("inv.db"))
            .await
            .unwrap();
        let rec = AccessLogRecord {
            user_id: UserId("alice".into()),
            ip: "192.168.1.23".into(),
            ua: Some("Hiddify".into()),
            status: 200,
            bytes: 128,
            accept_language: None,
            http_version: None,
            device_class: Some("Hiddify".into()),
            geo_country: None,
            geo_asn: None,
            tls_ja3: None,
            tls_ja4: None,
        };

        fire_suspicious_local_ip_alert(&inv, &rec, crate::ip_kind::IpKind::LanRfc1918)
            .await
            .unwrap();
        // The alert is still open, so a repeat must remain a complete
        // no-op: no duplicate feed row and no duplicate audit event.
        fire_suspicious_local_ip_alert(&inv, &rec, crate::ip_kind::IpKind::LanRfc1918)
            .await
            .unwrap();

        let alerts = inv.recent_alerts(10, false).await.unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, "sub_access.suspicious_local_ip:alice");

        let audit = inv.recent_audit(10).await.unwrap();
        let fires: Vec<_> = audit
            .iter()
            .filter(|entry| entry.action == "alert.fire")
            .collect();
        assert_eq!(fires.len(), 1, "fresh alert must have one audit event");
        assert_eq!(fires[0].target.as_deref(), Some("alice"));
    }
}
