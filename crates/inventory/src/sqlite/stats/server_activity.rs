use std::collections::HashMap;

use chrono::{DateTime, Utc};
use sqlx::Row;
use vpnctl_core::{ServerId, UserId};

use crate::sqlite::base::{SqliteInventory, real_client_ip_predicate};
use crate::sqlite::models::{Result, ServerLiveActivity};

impl SqliteInventory {
    /// Detect per-user attribution STALL per server (2026-06-14 — backs the
    /// `server.attribution.stalled` health alert). A server is "stalled"
    /// when, over the recent window, it has live connections (server-wide
    /// rows show `active_connections >= min_active`) but ZERO distinct
    /// attributed users — the clash poll lands server-wide totals while the
    /// sing-box log scrape attributed nobody. This is the signature of an
    /// orphaned sing-box log fd (live log 0-byte) or a persistently failing
    /// scrape — exactly the silent break that hit prod twice (logrotate
    /// orphan, then the `install /dev/null` ensure_installed orphan).
    ///
    /// `window_minutes` spans multiple poll ticks so the transient one-tick
    /// blip right after a sing-box restart does NOT flag. Index-backed by
    /// `idx_vcs_ts` (ts range) + a small GROUP BY.
    pub async fn attribution_stall_servers(
        &self,
        window_minutes: u32,
        min_active: u32,
    ) -> Result<Vec<ServerId>> {
        let rows = sqlx::query(
            "SELECT server_id
             FROM vpn_connection_stats
             WHERE ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)
             GROUP BY server_id
             HAVING MAX(active_connections) >= ?2
                AND COUNT(DISTINCT CASE WHEN user_id IS NOT NULL THEN user_id END) = 0",
        )
        .bind(format!("-{window_minutes} minutes"))
        .bind(i64::from(min_active))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| ServerId(r.get::<String, _>("server_id")))
            .collect())
    }

    /// Weighted totals over the last `since_hours` aligned hourly buckets,
    /// one compact row per server.
    pub async fn weighted_vpn_traffic_by_server(
        &self,
        since_hours: u32,
    ) -> Result<Vec<(ServerId, u64)>> {
        if since_hours == 0 {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            "SELECT
                stats.server_id AS server_id,
                CAST(SUM(
                    (stats.upload_bytes + stats.download_bytes)
                    * COALESCE(servers.usage_coefficient, 1.0)
                ) AS INTEGER) AS total_bytes
             FROM vpn_server_hourly stats
             JOIN servers ON servers.id = stats.server_id
             WHERE stats.hour >= strftime('%Y-%m-%dT%H:00:00.000Z', 'now', ?1)
             GROUP BY stats.server_id",
        )
        .bind(format!("-{} hours", since_hours - 1))
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let server_id: String = row.try_get("server_id")?;
            let total_bytes: i64 = row.try_get("total_bytes")?;
            out.push((ServerId(server_id), total_bytes.max(0) as u64));
        }
        Ok(out)
    }

    /// Phase 4b — single-query rollup of server-wide live activity
    /// for the server-detail tile + dashboard aggregate. Uses
    /// server-wide rows (user_id IS NULL) for the «active now»
    /// counter (clash-api per-tick `active_connections` value) and
    /// sums every row (per-user + server-wide) for the bytes-in-
    /// window counters. `distinct_users_attributed` reports how
    /// many per-user rows landed in the window — meaningful only
    /// AFTER the NM-11 sing-box upstream fix; today the operator
    /// sees `0` and the user-detail's «Live VPN stats» empty-
    /// state explains why.
    pub async fn server_live_activity(
        &self,
        server_id: &ServerId,
        since_hours: u32,
    ) -> Result<ServerLiveActivity> {
        let since = format!("-{since_hours} hours");
        // Single SELECT (Phase 4b post-review fix #2): the previous
        // two-query version had a race where a poller insert
        // between aggregates and «latest active» queries could
        // produce an `active_now` from a tick newer than
        // `last_sample_ts`. SQLite WITH clause holds the row set
        // for both correlated reads in one snapshot.
        let row = sqlx::query(
            "WITH win AS (
                SELECT upload_bytes, download_bytes, ts, user_id, active_connections
                FROM vpn_connection_stats
                WHERE server_id = ?1
                  AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
            )
            SELECT
                COALESCE((SELECT SUM(upload_bytes)   FROM win), 0) AS bytes_up,
                COALESCE((SELECT SUM(download_bytes) FROM win), 0) AS bytes_dn,
                (SELECT MAX(ts) FROM win)                           AS last_ts,
                (SELECT COUNT(DISTINCT user_id) FROM win WHERE user_id IS NOT NULL) AS attributed,
                (SELECT active_connections FROM vpn_connection_stats
                 WHERE server_id = ?1 AND user_id IS NULL
                 ORDER BY ts DESC LIMIT 1)                          AS active_now",
        )
        .bind(&server_id.0)
        .bind(&since)
        .fetch_one(&self.pool)
        .await?;

        let bytes_up: i64 = row.try_get("bytes_up")?;
        let bytes_dn: i64 = row.try_get("bytes_dn")?;
        let last_ts_s: Option<String> = row.try_get("last_ts")?;
        let attributed: i64 = row.try_get("attributed")?;
        let active_now_opt: Option<i64> = row.try_get("active_now")?;
        let active_now: u32 = match active_now_opt {
            Some(v) => u32::try_from(v.max(0)).unwrap_or(u32::MAX),
            None => 0,
        };

        Ok(ServerLiveActivity {
            active_now,
            bytes_up_window: bytes_up.max(0) as u64,
            bytes_dn_window: bytes_dn.max(0) as u64,
            last_sample_ts: last_ts_s.and_then(|t| {
                DateTime::parse_from_rfc3339(&t)
                    .ok()
                    .map(|d| d.with_timezone(&Utc))
            }),
            distinct_users_attributed: u32::try_from(attributed.max(0)).unwrap_or(u32::MAX),
        })
    }

    /// Phase 4c — given a list of source IPs (from a clash-api
    /// snapshot's `metadata.sourceIP` fields), find for each IP the
    /// most-likely `user_id` by counting hits in `sub_access_log`
    /// over the look-back window. Returns a map `source_ip ->
    /// Vec<(user_id, hit_count)>` sorted DESC by hit count, so the
    /// top entry is the most plausible owner. Empty Vec means no
    /// user has hit subscription URL from that IP in the window.
    ///
    /// Why this works despite NM-11: sing-box's clash-api still
    /// emits `sourceIP` (real public IP of client behind VLESS/TUIC
    /// auth). vpnctld's `sub_access_log.ip` also stores the real
    /// client IP for every `/api/v1/app/config/<device>` and
    /// `/sub/<token>` request. The intersection identifies «whose
    /// devices are talking from that IP right now» without sing-box
    /// needing to emit the `user` field. False positives possible
    /// (NAT collision: two real users behind one CGNAT IP), so the
    /// UI labels this «likely» not «is».
    ///
    /// Bounded by `ips.len()` * `look_back_days` rows of
    /// sub_access_log — single GROUP BY query with `WHERE ip IN
    /// (?, ?, ?, …)`. Skips VPN-egress rows (is_vpn_egress = 0)
    /// because those are our own server IPs, not real clients.
    pub async fn users_for_source_ips(
        &self,
        ips: &[String],
        look_back_days: u32,
    ) -> Result<std::collections::HashMap<String, Vec<(UserId, u64)>>> {
        if ips.is_empty() {
            return Ok(HashMap::new());
        }
        // Build the IN-clause placeholders dynamically (sqlx doesn't
        // support `IN (?)` with an array binding). Safe because
        // every `?` gets a single string bind; no string interp of
        // user-controlled data into the SQL itself.
        let placeholders = std::iter::repeat_n("?", ips.len())
            .collect::<Vec<_>>()
            .join(",");
        // `is_vpn_egress = 0` already drops VPN-server-IP fetches, but the
        // homelab LAN + control egress (192.168.0.x, 83.97.108.34, …) are
        // is_vpn_egress=0, so exclude them via `real_client_ip_predicate` —
        // otherwise every user we test/monitor from those IPs looks like
        // they "share" the IP.
        let sql = format!(
            "SELECT ip, user_id, COUNT(*) AS hits
             FROM sub_access_log
             WHERE ip IN ({placeholders})
               AND is_vpn_egress = 0
               AND {pred}
               AND user_id IS NOT NULL
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
             GROUP BY ip, user_id
             ORDER BY ip, hits DESC",
            pred = real_client_ip_predicate("ip")
        );
        let cutoff = format!("-{look_back_days} days");
        let mut q = sqlx::query(&sql);
        for ip in ips {
            q = q.bind(ip);
        }
        q = q.bind(&cutoff);
        let rows = q.fetch_all(&self.pool).await?;
        let mut out: HashMap<String, Vec<(UserId, u64)>> = HashMap::new();
        for r in rows {
            let ip: String = r.try_get("ip")?;
            let uid: String = r.try_get("user_id")?;
            let hits: i64 = r.try_get("hits")?;
            out.entry(ip)
                .or_default()
                .push((UserId(uid), hits.max(0) as u64));
        }
        Ok(out)
    }

    /// Phase 4b — dashboard rollup across every known server.
    /// Returns one `ServerLiveActivity` per `servers.id` (even for
    /// servers the poller never reached — they get the default-
    /// zeroed struct). Caller iterates + sums for the global
    /// dashboard KPI; the per-server map is also available for a
    /// «which server is busy» breakdown.
    pub async fn all_servers_live_activity(
        &self,
        since_hours: u32,
    ) -> Result<Vec<(ServerId, ServerLiveActivity)>> {
        // Returns a Vec keyed by ServerId — Vec rather than
        // HashMap/BTreeMap because the dashboard renderer iterates
        // in insertion order anyway, and the `SELECT … ORDER BY id`
        // below pre-sorts the keys alphabetically, so a Vec is the
        // simplest container that preserves that order at the
        // render site.
        let server_ids = sqlx::query("SELECT id FROM servers ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(server_ids.len());
        for r in server_ids {
            let id: String = r.try_get("id")?;
            let sid = ServerId(id);
            let activity = self.server_live_activity(&sid, since_hours).await?;
            out.push((sid, activity));
        }
        Ok(out)
    }
}
