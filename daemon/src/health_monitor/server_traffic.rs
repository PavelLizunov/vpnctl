use crate::server_traffic::ServerTraffic;
use vpnctl_core::Server;
use vpnctl_inventory::{SqliteInventory, SqliteInventoryError};

pub(super) async fn check_server_traffic_limits(
    inv: &SqliteInventory,
    servers: &[Server],
    now: i64,
) -> Result<(), SqliteInventoryError> {
    for server in servers {
        let traffic = ServerTraffic::load(inv, &server.id, now).await?;
        for (kind, severity, threshold) in [
            (
                "server.traffic_limit",
                "warning",
                traffic.limit.as_ref().map_or(80, |l| l.warning_pct),
            ),
            ("server.traffic_exhausted", "critical", 100),
        ] {
            let Some(limit) = &traffic.limit else {
                inv.ack_open_alerts(kind, Some(&server.id)).await?;
                continue;
            };
            let Some(pct) = traffic.percent() else {
                continue;
            };
            if pct < u64::from(threshold) {
                // A partial/stale lower bound cannot prove the quota is safe.
                if traffic.complete() {
                    inv.ack_open_alerts(kind, Some(&server.id)).await?;
                }
                continue;
            }
            let used = traffic.used_bytes().unwrap_or(0);
            let summary = format!(
                "Hoster traffic: observed {pct}% of monthly limit ({used} / {} bytes, {}); check Activity → Hoster traffic",
                limit.limit_bytes, limit.direction
            );
            let payload = serde_json::json!({
                "used_bytes": used, "limit_bytes": limit.limit_bytes, "direction": limit.direction,
                "pct": pct, "period_start": traffic.period_start, "period_end": traffic.period_end,
                "complete": traffic.complete(), "fresh": traffic.fresh,
            });
            let serialized = serde_json::to_string(&payload)?;
            if let Some(id) = inv
                .insert_alert_if_no_unacked(
                    kind,
                    Some(&server.id),
                    severity,
                    &summary,
                    Some(&serialized),
                )
                .await?
            {
                crate::node_probe_poller::audit_alert_fire(inv, &server.id, id, kind, &summary)
                    .await;
                let subject = crate::node_probe_poller::server_subject(inv, &server.id).await;
                crate::node_probe_poller::push_alert(
                    inv,
                    kind,
                    severity,
                    &subject,
                    &payload,
                    Some(id),
                )
                .await;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use vpnctl_inventory::ServerTrafficLimit;

    #[tokio::test]
    async fn quota_alerts_use_the_selected_direction_include_gap_and_deduplicate() {
        for (direction, expected, rx, tx, limit_bytes) in [
            ("rx", 1, 900, 200, 1000),
            ("tx", 0, 900, 200, 1000),
            ("both", 2, 900, 200, 1000),
            ("both", 2, i64::MAX, i64::MAX, 1),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("inv.db");
            let inv = SqliteInventory::open(&path).await.unwrap();
            let server = Server {
                id: vpnctl_core::ServerId("quota-spec".into()),
                address: "192.0.2.1".into(),
                ssh_port: 22,
                ssh_user: "root".into(),
                kernels: vec![],
                enabled_protocols: vec![],
                trusted_host_fingerprint: None,
                hoster: "synthetic".into(),
                jump_via: None,
                usage_coefficient: 1.0,
            };
            inv.add_server(&server).await.unwrap();
            inv.set_server_traffic_limit(
                &server.id,
                Some(&ServerTrafficLimit {
                    limit_bytes,
                    direction: direction.into(),
                    reset_day: 1,
                    warning_pct: 80,
                }),
                "spec",
            )
            .await
            .unwrap();
            let pool = sqlx::SqlitePool::connect_with(
                sqlx::sqlite::SqliteConnectOptions::new().filename(&path),
            )
            .await
            .unwrap();
            let start = chrono::DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
                .unwrap()
                .timestamp();
            for (n, delta, rx, tx) in [(0, 0, 0, 0), (1, 1200, rx, tx)] {
                sqlx::query("INSERT INTO node_health(server_id,sample_id,ts,nic_iface,nic_rx_bytes,nic_tx_bytes) VALUES('quota-spec',?1,?2,'eth0',?3,?4)")
                    .bind(n.to_string()).bind(chrono::DateTime::from_timestamp(start+delta,0).unwrap().to_rfc3339()).bind(rx).bind(tx).execute(&pool).await.unwrap();
            }
            for _ in 0..2 {
                check_server_traffic_limits(&inv, std::slice::from_ref(&server), start + 1200)
                    .await
                    .unwrap();
            }
            let alerts = inv.recent_alerts(100, false).await.unwrap();
            assert_eq!(alerts.len(), expected, "direction {direction}");
            if direction == "both" {
                assert!(
                    alerts
                        .iter()
                        .any(|a| a.kind == "server.traffic_exhausted" && a.severity == "critical")
                );
            }
            // An observed lower bound below threshold cannot clear a warning.
            sqlx::query("UPDATE node_health SET nic_rx_bytes=0,nic_tx_bytes=0")
                .execute(&pool)
                .await
                .unwrap();
            check_server_traffic_limits(&inv, std::slice::from_ref(&server), start + 4000)
                .await
                .unwrap();
            assert_eq!(inv.recent_alerts(100, false).await.unwrap().len(), expected);
            // The same low readings with complete fresh coverage may clear it.
            check_server_traffic_limits(&inv, std::slice::from_ref(&server), start + 1200)
                .await
                .unwrap();
            assert!(inv.recent_alerts(100, false).await.unwrap().is_empty());
            // Partial history can trigger an alert, and explicit removal clears it.
            sqlx::query("UPDATE node_health SET nic_rx_bytes=1100 WHERE sample_id='1'")
                .execute(&pool)
                .await
                .unwrap();
            check_server_traffic_limits(&inv, std::slice::from_ref(&server), start + 4000)
                .await
                .unwrap();
            if direction != "tx" {
                assert!(!inv.recent_alerts(100, false).await.unwrap().is_empty());
            }
            inv.set_server_traffic_limit(&server.id, None, "spec")
                .await
                .unwrap();
            check_server_traffic_limits(&inv, &[server], start + 4000)
                .await
                .unwrap();
            assert!(inv.recent_alerts(100, false).await.unwrap().is_empty());
        }
    }
}
