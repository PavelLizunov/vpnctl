use sqlx::Row;
use tempfile::TempDir;
use vpnctl_inventory::SqliteInventory;

#[tokio::test]
#[allow(clippy::unwrap_used, clippy::expect_used)]
async fn retention_deletes_search_timestamp_indexes() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("inventory.db");
    let inv = SqliteInventory::open(&path).await.unwrap();
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", path.display()))
        .await
        .unwrap();
    for (table, predicate, index) in [
        (
            "sub_access_log",
            "ts < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
            "idx_sub_access_log_ts",
        ),
        (
            "vpn_connection_stats",
            "ts < strftime('%Y-%m-%dT00:00:00.000Z', 'now', ?1)",
            "idx_vcs_ts",
        ),
        (
            "node_health",
            "ts < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
            "idx_node_health_ts",
        ),
        (
            "server_quality_samples",
            "ts < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
            "idx_server_quality_samples_ts",
        ),
        (
            "protocol_assurance_samples",
            "ts < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
            "idx_protocol_assurance_ts",
        ),
        (
            "admin_alerts",
            "acked_at IS NOT NULL AND acked_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
            "idx_admin_alerts_acked_at",
        ),
        (
            "vpn_user_sessions",
            "last_seen < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1) AND last_seen < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-15 minutes')",
            "idx_vpn_user_sessions_last_seen",
        ),
        (
            "vpn_user_destinations",
            "date < strftime('%Y-%m-%d', 'now', ?1)",
            "idx_vpn_user_destinations_date",
        ),
        (
            "vpn_user_source_ips",
            "date < strftime('%Y-%m-%d', 'now', ?1)",
            "idx_vpn_user_source_ips_date",
        ),
        (
            "vpn_user_ip_concurrency",
            "date < strftime('%Y-%m-%d', 'now', ?1)",
            "idx_vpn_user_ip_concurrency_date",
        ),
        (
            "dns_ptr_cache",
            "resolved_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
            "idx_dns_ptr_cache_resolved_at",
        ),
    ] {
        let sql = format!("EXPLAIN QUERY PLAN DELETE FROM {table} WHERE {predicate}");
        let plan = sqlx::query(&sql)
            .bind("-30 days")
            .fetch_all(&pool)
            .await
            .unwrap();
        let details: Vec<String> = plan.iter().map(|r| r.get("detail")).collect();
        assert!(
            details
                .iter()
                .any(|detail| detail.contains("SEARCH") && detail.contains(index)),
            "{table} retention must use {index}: {details:?}"
        );
    }
    pool.close().await;
    inv.close().await;
}
