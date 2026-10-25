use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use vpnctl_core::UserId;
use vpnctl_inventory::SqliteInventory;

pub const ACCESS_LOG_CHANNEL_CAP: usize = 1024;

#[derive(Debug, Clone)]
pub struct AccessLogRecord {
    pub user_id: UserId,
    pub ip: String,
    pub ua: Option<String>,
    pub status: u16,
    pub bytes: u64,
    pub accept_language: Option<String>,
    pub http_version: Option<String>,
    pub device_class: Option<String>,
    pub geo_country: Option<String>,
    pub geo_asn: Option<String>,
    pub tls_ja3: Option<String>,
    pub tls_ja4: Option<String>,
}

pub fn spawn_writer(inv: SqliteInventory) -> (mpsc::Sender<AccessLogRecord>, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel::<AccessLogRecord>(ACCESS_LOG_CHANNEL_CAP);
    let handle = tokio::spawn(run_writer(inv, rx));
    (tx, handle)
}

pub async fn drain_writer(mut handle: JoinHandle<()>) {
    match tokio::time::timeout(std::time::Duration::from_secs(10), &mut handle).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::warn!(
            target = "vpnctld::access_log_writer",
            %error,
            "access-log writer exited before draining cleanly"
        ),
        Err(_) => {
            tracing::warn!(
                target = "vpnctld::access_log_writer",
                "access-log writer did not drain within 10 seconds; stopping it"
            );
            handle.abort();
            let _ = handle.await;
        }
    }
}

async fn run_writer(inv: SqliteInventory, mut rx: mpsc::Receiver<AccessLogRecord>) {
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

    let mut batch = Vec::with_capacity(50);
    while let Some(rec) = rx.recv().await {
        batch.push(rec);
        while batch.len() < 50 {
            match rx.try_recv() {
                Ok(r) => batch.push(r),
                Err(_) => break,
            }
        }

        for r in &mut batch {
            if geoip.is_loaded()
                && let Ok(parsed_ip) = r.ip.parse()
                && let Some(info) = geoip.lookup(parsed_ip)
            {
                let asn_label = info.asn_label();
                if r.geo_country.is_none() {
                    r.geo_country = info.country_iso;
                }
                if r.geo_asn.is_none() {
                    r.geo_asn = asn_label;
                }
            }
        }

        let inputs: Vec<vpnctl_inventory::SubAccessEntryInput> = batch
            .iter()
            .map(|r| vpnctl_inventory::SubAccessEntryInput {
                user_id: r.user_id.clone(),
                ip: r.ip.clone(),
                ua: r.ua.clone(),
                status: r.status,
                bytes: r.bytes,
                accept_language: r.accept_language.clone(),
                http_version: r.http_version.clone(),
                device_class: r.device_class.clone(),
                geo_country: r.geo_country.clone(),
                geo_asn: r.geo_asn.clone(),
                tls_ja3: r.tls_ja3.clone(),
                tls_ja4: r.tls_ja4.clone(),
            })
            .collect();

        match inv.log_sub_access_batch(&inputs).await {
            Ok(()) => {
                for r in &batch {
                    let kind = crate::ip_kind::classify_ip(&r.ip);
                    if kind.is_lan_or_loopback()
                        && !is_lan_alert_allowed(r.device_class.as_deref())
                        && !is_trusted_reverse_proxy(&r.ip)
                        && !is_allowlisted_service_ip(&r.ip)
                        && let Err(e) = fire_suspicious_local_ip_alert(&inv, r, kind).await
                    {
                        tracing::warn!(
                            target = "vpnctld::access_log_writer",
                            user = %r.user_id,
                            ip = %r.ip,
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
                    batch_len = batch.len(),
                    error = %e,
                    "batch log_sub_access write failed; falling back to per-record insert"
                );
                for input in &inputs {
                    if let Err(err) = inv.log_sub_access_batch(std::slice::from_ref(input)).await {
                        tracing::warn!(
                            target = "vpnctld::access_log_writer",
                            user = %input.user_id,
                            error = %err,
                            "fallback log_sub_access record write failed"
                        );
                    }
                }
            }
        }
        batch.clear();
    }
    tracing::info!(
        target = "vpnctld::access_log_writer",
        "channel closed, writer exiting cleanly"
    );
}

const SUSPICIOUS_LAN_ALLOWED_UAS: &[&str] = &["phase6-monitor (canary)"];

fn is_lan_alert_allowed(device_class: Option<&str>) -> bool {
    match device_class {
        Some(s) => SUSPICIOUS_LAN_ALLOWED_UAS.contains(&s),
        None => false,
    }
}

fn is_trusted_reverse_proxy(ip_str: &str) -> bool {
    match ip_str.parse::<std::net::IpAddr>() {
        Ok(ip) => crate::real_ip::is_trusted_proxy(ip),
        Err(_) => false,
    }
}

static SUSPICIOUS_IP_ALLOWLIST: std::sync::OnceLock<Vec<std::net::IpAddr>> =
    std::sync::OnceLock::new();

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

fn is_allowlisted_service_ip(ip_str: &str) -> bool {
    is_allowlisted_service_ip_with(ip_str, suspicious_ip_allowlist())
}

fn is_allowlisted_service_ip_with(ip_str: &str, allowlist: &[std::net::IpAddr]) -> bool {
    match ip_str.parse::<std::net::IpAddr>() {
        Ok(ip) => allowlist.contains(&ip),
        Err(_) => false,
    }
}

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

    #[tokio::test]
    async fn shutdown_drains_queued_access_logs_after_router_drop() {
        let dir = tempfile::tempdir().unwrap();
        let inv = SqliteInventory::open(&dir.path().join("inv.db"))
            .await
            .unwrap();
        let user_id = UserId("drain-user".into());
        inv.add_user(&vpnctl_core::User {
            id: user_id.clone(),
            uuid: "00000000-0000-0000-0000-000000000001".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
        let registry = std::sync::Arc::new(crate::app::build_registry().unwrap());
        let (state, writer) = crate::app::make_app_state_for_tests(inv.clone(), registry);
        let app = crate::app::router(state.clone());
        for bytes in 0..125 {
            assert!(try_enqueue(
                &state.access_log_tx,
                AccessLogRecord {
                    user_id: user_id.clone(),
                    ip: "203.0.113.7".into(),
                    ua: None,
                    status: 200,
                    bytes,
                    accept_language: None,
                    http_version: None,
                    device_class: None,
                    geo_country: None,
                    geo_asn: None,
                    tls_ja3: None,
                    tls_ja4: None,
                }
            ));
        }
        drop(state);
        drop(app);
        drain_writer(writer).await;

        let rows = inv.recent_sub_access(&user_id, 200).await.unwrap();
        assert_eq!(rows.len(), 125, "all accepted records must be persisted");
        assert_eq!(
            rows.iter().map(|row| row.bytes).sum::<u64>(),
            (0..125).sum::<u64>()
        );
    }

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
