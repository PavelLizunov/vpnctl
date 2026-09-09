use super::*;
use chrono::{DateTime, Utc};
use sqlx::Row;
use std::collections::HashMap;
use vpnctl_core::ServerId;

/// Sum per-interval deltas of cumulative NIC counters, `readings`
/// oldest→newest as `(iface, rx, tx)` triples. Two discontinuity guards
/// each count the new value itself as that interval's delta (a lower
/// bound; the pre-discontinuity tail is unknowable): a reboot/reset (a
/// reading LOWER than the previous — counter wrapped / NIC reset), and an
/// interface change (`iface` differs from the previous reading — rename
/// `eth0`→`ens18`, uplink failover; the two readings are DIFFERENT
/// counters, so a plain subtraction would be garbage, and a higher new
/// counter would otherwise inflate the total). Fewer than 2 readings ⇒
/// `(0, 0)`. Pure + saturating, so it's spec-testable in isolation and
/// can't overflow on a corrupt counter. Returns `(rx_total, tx_total)`.
pub fn sum_nic_deltas(readings: &[(String, u64, u64)]) -> (u64, u64) {
    let mut rx = 0u64;
    let mut tx = 0u64;
    for w in readings.windows(2) {
        let (piface, prx, ptx) = (&w[0].0, w[0].1, w[0].2);
        let (ciface, crx, ctx) = (&w[1].0, w[1].1, w[1].2);
        let continuous = piface == ciface;
        rx = rx.saturating_add(if continuous && crx >= prx {
            crx - prx
        } else {
            crx
        });
        tx = tx.saturating_add(if continuous && ctx >= ptx {
            ctx - ptx
        } else {
            ctx
        });
    }
    (rx, tx)
}

#[allow(clippy::needless_pass_by_value)]
fn row_to_node_health(r: sqlx::sqlite::SqliteRow) -> Result<NodeHealthRow> {
    let sample_seq: Option<i64> = r.try_get("sample_seq").ok();
    let sample_id: Option<String> = r.try_get("sample_id").ok();
    let ts_s: String = r.try_get("ts")?;
    let ts = DateTime::parse_from_rfc3339(&ts_s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| {
            SqliteInventoryError::Invalid(format!("node_health.ts malformed: {ts_s}: {e}"))
        })?;
    let server_id: String = r.try_get("server_id")?;
    let sb_i: Option<i64> = r.try_get("sing_box_active")?;
    let f2b_i: Option<i64> = r.try_get("fail2ban_active")?;
    let disk_u: Option<i64> = r.try_get("disk_used_mib")?;
    let disk_t: Option<i64> = r.try_get("disk_total_mib")?;
    let mem_a: Option<i64> = r.try_get("mem_available_mib")?;
    let mem_t: Option<i64> = r.try_get("mem_total_mib")?;
    let load_i: Option<i64> = r.try_get("load_1min_x100")?;
    let ports: Option<String> = r.try_get("listening_ports_json")?;
    let log_b: Option<i64> = r.try_get("sing_box_log_bytes")?;
    let kernel_versions: Option<String> = r.try_get("kernel_versions_json")?;
    let nic_iface: Option<String> = r.try_get("nic_iface")?;
    let nic_rx: Option<i64> = r.try_get("nic_rx_bytes")?;
    let nic_tx: Option<i64> = r.try_get("nic_tx_bytes")?;
    let nrestarts: Option<i64> = r.try_get("sing_box_nrestarts")?;
    Ok(NodeHealthRow {
        sample_seq,
        sample_id,
        ts,
        server_id: ServerId(server_id),
        sing_box_active: sb_i.map(|n| n != 0),
        fail2ban_active: f2b_i.map(|n| n != 0),
        disk_used_mib: disk_u.and_then(|n| u64::try_from(n).ok()),
        disk_total_mib: disk_t.and_then(|n| u64::try_from(n).ok()),
        mem_available_mib: mem_a.and_then(|n| u64::try_from(n).ok()),
        mem_total_mib: mem_t.and_then(|n| u64::try_from(n).ok()),
        load_1min_x100: load_i.and_then(|n| u32::try_from(n).ok()),
        listening_ports_json: ports,
        sing_box_log_bytes: log_b.and_then(|n| u64::try_from(n).ok()),
        kernel_versions_json: kernel_versions,
        nic_iface,
        nic_rx_bytes: nic_rx.and_then(|n| u64::try_from(n).ok()),
        nic_tx_bytes: nic_tx.and_then(|n| u64::try_from(n).ok()),
        sing_box_nrestarts: nrestarts.and_then(|n| u64::try_from(n).ok()),
    })
}

#[allow(clippy::needless_pass_by_value)]
fn row_to_service_quality_sample(
    r: sqlx::sqlite::SqliteRow,
) -> Result<crate::quality::ServiceQualitySample> {
    let ts_s: String = r.try_get("ts")?;
    let ts = DateTime::parse_from_rfc3339(&ts_s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| {
            SqliteInventoryError::Invalid(format!(
                "server_quality_samples.ts malformed: {ts_s}: {e}"
            ))
        })?;
    let required_u32 = |column: &'static str, value: i64| -> Result<u32> {
        u32::try_from(value).map_err(|_| {
            SqliteInventoryError::Invalid(format!(
                "server_quality_samples.{column} out of u32 range: {value}"
            ))
        })
    };
    let optional_u32 = |column: &'static str, value: Option<i64>| -> Result<Option<u32>> {
        value.map(|n| required_u32(column, n)).transpose()
    };
    let tcp_json: String = r.try_get("tcp_rtt_ms_json")?;
    let control_json: String = r.try_get("control_rtt_ms_json")?;
    let icmp_json: Option<String> = r.try_get("icmp_rtt_ms_json")?;
    Ok(crate::quality::ServiceQualitySample {
        ts,
        server_id: ServerId(r.try_get("server_id")?),
        vantage: r.try_get("vantage")?,
        target_count: required_u32("target_count", r.try_get("target_count")?)?,
        available_targets: required_u32("available_targets", r.try_get("available_targets")?)?,
        attempts: required_u32("attempts", r.try_get("attempts")?)?,
        successes: required_u32("successes", r.try_get("successes")?)?,
        tcp_rtt_ms: serde_json::from_str(&tcp_json)?,
        control_attempts: required_u32("control_attempts", r.try_get("control_attempts")?)?,
        control_successes: required_u32("control_successes", r.try_get("control_successes")?)?,
        control_rtt_ms: serde_json::from_str(&control_json)?,
        icmp_attempts: optional_u32("icmp_attempts", r.try_get("icmp_attempts")?)?,
        icmp_successes: optional_u32("icmp_successes", r.try_get("icmp_successes")?)?,
        icmp_rtt_ms: icmp_json.as_deref().map(serde_json::from_str).transpose()?,
    })
}

impl SqliteInventory {
    // ──────────────────────────────────────────────────────────────────
    // Phase H chunk 2 — node telemetry storage (node_probe sink)
    //
    // Same shape + lifecycle as `vpn_connection_stats`:
    //   * Daemon poller calls `record_node_health(server_id, &Probe)`
    //     once per tick per server (chunk 3).
    //   * UI reads via `recent_node_health_for_server(id, since_hours)`.
    //   * Retention purge mirrors the others.
    //
    // **Audit exemption** (same rationale as `record_vpn_stats`):
    // probe writes happen at poller cadence × server count; audit
    // log volume would drown human-driven mutations. The table IS the
    // audit trail for telemetry. Documented exemption — not a silent
    // drift from the "every mutation audited" invariant.
    // ──────────────────────────────────────────────────────────────────

    /// Persist one node probe. `listening_ports_json` is the JSON
    /// serialization of the sorted `(proto, port)` set — caller
    /// builds it from `daemon::node_probe::Probe::listening`. Always
    /// stamps `ts` with daemon-side now; clash-api / probes don't
    /// carry their own timestamp.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_node_health(
        &self,
        server_id: &ServerId,
        sing_box_active: Option<bool>,
        fail2ban_active: Option<bool>,
        disk_used_mib: Option<u64>,
        disk_total_mib: Option<u64>,
        mem_available_mib: Option<u64>,
        mem_total_mib: Option<u64>,
        load_1min_x100: Option<u32>,
        listening_ports_json: Option<&str>,
        sing_box_log_bytes: Option<u64>,
        kernel_versions_json: Option<&str>,
        nic_iface: Option<&str>,
        nic_rx_bytes: Option<u64>,
        nic_tx_bytes: Option<u64>,
        sing_box_nrestarts: Option<u64>,
    ) -> Result<()> {
        let sample_id = vpnctl_crypto::gen_uuid();
        // SQLite has no BOOLEAN — map Option<bool> → Option<i64>.
        let sb = sing_box_active.map(i64::from);
        let f2b = fail2ban_active.map(i64::from);
        sqlx::query(
            "INSERT INTO node_health
             (sample_id, ts, server_id, sing_box_active, fail2ban_active,
              disk_used_mib, disk_total_mib,
              mem_available_mib, mem_total_mib,
              load_1min_x100, listening_ports_json, sing_box_log_bytes,
              kernel_versions_json, nic_iface, nic_rx_bytes, nic_tx_bytes,
              sing_box_nrestarts)
             VALUES (?1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                     ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        )
        .bind(sample_id)
        .bind(&server_id.0)
        .bind(sb)
        .bind(f2b)
        .bind(disk_used_mib.and_then(|n| i64::try_from(n).ok()))
        .bind(disk_total_mib.and_then(|n| i64::try_from(n).ok()))
        .bind(mem_available_mib.and_then(|n| i64::try_from(n).ok()))
        .bind(mem_total_mib.and_then(|n| i64::try_from(n).ok()))
        .bind(load_1min_x100.map(i64::from))
        .bind(listening_ports_json)
        .bind(sing_box_log_bytes.and_then(|n| i64::try_from(n).ok()))
        .bind(kernel_versions_json)
        .bind(nic_iface)
        .bind(nic_rx_bytes.and_then(|n| i64::try_from(n).ok()))
        .bind(nic_tx_bytes.and_then(|n| i64::try_from(n).ok()))
        .bind(sing_box_nrestarts.and_then(|n| i64::try_from(n).ok()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Recent rows for one server in the look-back window, newest
    /// first. UI reads this for the server-detail page (chunk 3).
    pub async fn recent_node_health_for_server(
        &self,
        server_id: &ServerId,
        since_hours: u32,
    ) -> Result<Vec<NodeHealthRow>> {
        let rows = sqlx::query(
            "SELECT sample_seq, sample_id, ts, server_id, sing_box_active, fail2ban_active,
                    disk_used_mib, disk_total_mib,
                    mem_available_mib, mem_total_mib,
                    load_1min_x100, listening_ports_json, sing_box_log_bytes,
                    kernel_versions_json, nic_iface, nic_rx_bytes, nic_tx_bytes,
                    sing_box_nrestarts
             FROM node_health
             WHERE server_id = ?1
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
             ORDER BY ts DESC, sample_seq DESC",
        )
        .bind(&server_id.0)
        .bind(format!("-{since_hours} hours"))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_node_health).collect()
    }

    /// Most recent single row for a server. Convenience for the
    /// "current state" hero block on the server-detail page —
    /// callers that only need the latest snapshot don't have to
    /// pull a whole 24h Vec just to read the first element.
    pub async fn latest_node_health(&self, server_id: &ServerId) -> Result<Option<NodeHealthRow>> {
        let row_opt = sqlx::query(
            "SELECT sample_seq, sample_id, ts, server_id, sing_box_active, fail2ban_active,
                    disk_used_mib, disk_total_mib,
                    mem_available_mib, mem_total_mib,
                    load_1min_x100, listening_ports_json, sing_box_log_bytes,
                    kernel_versions_json, nic_iface, nic_rx_bytes, nic_tx_bytes,
                    sing_box_nrestarts
             FROM node_health
             WHERE server_id = ?1
             ORDER BY ts DESC, sample_seq DESC
             LIMIT 1",
        )
        .bind(&server_id.0)
        .fetch_optional(&self.pool)
        .await?;
        row_opt.map(row_to_node_health).transpose()
    }

    /// Map of `server_id -> most recent NodeHealthRow` for all servers with probe data.
    /// Exactly 1 query using SQLite window functions, eliminating N+1 loops across the fleet.
    pub async fn latest_node_health_fleet(&self) -> Result<HashMap<ServerId, NodeHealthRow>> {
        let rows = sqlx::query(
            "WITH ranked AS (
                SELECT sample_seq, sample_id, ts, server_id, sing_box_active, fail2ban_active,
                       disk_used_mib, disk_total_mib,
                       mem_available_mib, mem_total_mib,
                       load_1min_x100, listening_ports_json, sing_box_log_bytes,
                       kernel_versions_json, nic_iface, nic_rx_bytes, nic_tx_bytes,
                       sing_box_nrestarts,
                       ROW_NUMBER() OVER (PARTITION BY server_id ORDER BY ts DESC, sample_seq DESC) as rn
                FROM node_health
             )
             SELECT sample_seq, sample_id, ts, server_id, sing_box_active, fail2ban_active,
                    disk_used_mib, disk_total_mib,
                    mem_available_mib, mem_total_mib,
                    load_1min_x100, listening_ports_json, sing_box_log_bytes,
                    kernel_versions_json, nic_iface, nic_rx_bytes, nic_tx_bytes,
                    sing_box_nrestarts
             FROM ranked WHERE rn = 1",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut out = HashMap::with_capacity(rows.len());
        for r in rows {
            let row = row_to_node_health(r)?;
            out.insert(row.server_id.clone(), row);
        }
        Ok(out)
    }

    /// Traffic accounting breakdown for one server over the window:
    /// NIC ground-truth total (ALL protocols), the part attributed to
    /// sing-box via clash-api, and the GAP between them (non-sing-box
    /// protocols — naive/Caddy — plus protocol/OS
    /// overhead). Backs the «Traffic accounting» section on the
    /// server-detail page; the gap is THE signal the operator wants
    /// (how much real traffic vpnctl currently can't see per-user).
    ///
    /// NIC total = sum of per-interval deltas of the cumulative
    /// `node_health.nic_*` counters (reboot/reset-guarded via
    /// [`sum_nic_deltas`]). Attributed = `SUM(upload+download)` over ALL
    /// `vpn_connection_stats` rows (per-user + the server-wide remainder)
    /// — clash-api's total view of sing-box traffic.
    pub async fn server_traffic_breakdown(
        &self,
        server_id: &ServerId,
        since_hours: u32,
    ) -> Result<TrafficBreakdown> {
        // Cumulative NIC readings in the window, oldest→newest (need ≥2
        // for a delta). Only rows that actually captured the counters.
        let nic_rows = sqlx::query_as::<_, (Option<i64>, Option<i64>, Option<String>)>(
            "SELECT nic_rx_bytes, nic_tx_bytes, nic_iface
             FROM node_health
             WHERE server_id = ?1
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
               AND nic_rx_bytes IS NOT NULL AND nic_tx_bytes IS NOT NULL
             ORDER BY ts ASC, sample_seq ASC",
        )
        .bind(&server_id.0)
        .bind(format!("-{since_hours} hours"))
        .fetch_all(&self.pool)
        .await?;
        let nic_iface = nic_rows.last().and_then(|(_, _, i)| i.clone());
        // Carry the iface into each reading so sum_nic_deltas can break
        // continuity on an iface change (rename / failover) — diffing two
        // different counters would otherwise inflate the total.
        let readings: Vec<(String, u64, u64)> = nic_rows
            .iter()
            .filter_map(|(rx, tx, ifc)| {
                Some((
                    ifc.clone().unwrap_or_default(),
                    u64::try_from((*rx)?).ok()?,
                    u64::try_from((*tx)?).ok()?,
                ))
            })
            .collect();
        let (nic_rx_bytes, nic_tx_bytes) = sum_nic_deltas(&readings);
        let nic_total_bytes = nic_rx_bytes.saturating_add(nic_tx_bytes);

        // Attributed (clash-api / sing-box) — sum of up+dn over ALL rows
        // (per-user + the NULL server-wide remainder) in the window. These
        // are DISJOINT by the clash poller's design (it emits per-user
        // deltas plus a remainder = total − attributed), so summing both
        // yields clash's true total view — not a double-count.
        let (attributed,): (i64,) = sqlx::query_as(
            "SELECT COALESCE(SUM(upload_bytes + download_bytes), 0)
             FROM vpn_connection_stats
             WHERE server_id = ?1
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)",
        )
        .bind(&server_id.0)
        .bind(format!("-{since_hours} hours"))
        .fetch_one(&self.pool)
        .await?;
        let attributed_bytes = u64::try_from(attributed).unwrap_or(0);

        Ok(TrafficBreakdown {
            nic_total_bytes,
            nic_rx_bytes,
            nic_tx_bytes,
            attributed_bytes,
            // Saturating: clash can briefly exceed NIC at window edges
            // (sample boundaries don't align) — never show a negative gap.
            gap_bytes: nic_total_bytes.saturating_sub(attributed_bytes),
            nic_samples: readings.len(),
            nic_iface,
        })
    }

    /// Phase H+ — uptime aggregation for the per-server detail page.
    ///
    /// Single SQL round-trip returns the rolling-window counts +
    /// last-outage + last-probe timestamps over `window_hours`. The
    /// UI builds three of these (24h, 7d, 30d) for one server with
    /// effectively the cost of three indexed range scans against
    /// `(server_id, ts)` — cheap even on the 632-row/day production
    /// rate that the live `is` node generates today.
    ///
    /// Definitions:
    ///   * "up" = `sing_box_active=1` — what users care about (the
    ///     daemon serving VPN traffic).
    ///   * "down" = `sing_box_active=0` — sing-box.service in any
    ///     non-active state at probe time.
    ///   * "unknown" = `sing_box_active IS NULL` — probe ran but
    ///     couldn't decide (early-bootstrap row before sing-box was
    ///     installed, or SSH probe partial-failure).
    ///
    /// `uptime_pct` excludes "unknown" from the denominator. A
    /// freshly-added server whose only rows are unknown reports
    /// `uptime_pct = None` rather than `0%`, which would be a wrong
    /// alarm in the chip ("0% over 30d" looks dire — "no data"
    /// is the honest answer).
    pub async fn uptime_for_server(
        &self,
        server_id: &ServerId,
        window_hours: u32,
    ) -> Result<UptimeStat> {
        let row = sqlx::query(
            "SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN sing_box_active = 1 THEN 1 ELSE 0 END) AS up_count,
                SUM(CASE WHEN sing_box_active = 0 THEN 1 ELSE 0 END) AS down_count,
                SUM(CASE WHEN sing_box_active IS NULL THEN 1 ELSE 0 END) AS unknown_count,
                MAX(CASE WHEN sing_box_active = 0 THEN ts ELSE NULL END) AS last_outage,
                MAX(ts) AS last_probe
             FROM node_health
             WHERE server_id = ?1
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)",
        )
        .bind(&server_id.0)
        .bind(format!("-{window_hours} hours"))
        .fetch_one(&self.pool)
        .await?;

        // `COUNT(*)` is always non-null; `SUM(...)` returns NULL
        // when there are zero rows. `try_get` with default-on-NULL
        // semantics avoids panicking on the empty-window case
        // (server brand-new, no probes in this window).
        let total: i64 = row.try_get("total").unwrap_or(0);
        let up: i64 = row.try_get("up_count").unwrap_or(0);
        let down: i64 = row.try_get("down_count").unwrap_or(0);
        let unknown: i64 = row.try_get("unknown_count").unwrap_or(0);
        let last_outage_s: Option<String> = row.try_get("last_outage").ok();
        let last_probe_s: Option<String> = row.try_get("last_probe").ok();

        // uptime% over decidable rows. None when no up+down rows.
        let uptime_pct: Option<u8> = if up + down > 0 {
            // u8 fits 0..=100 even with i64 inputs since we clamp.
            Some(((up * 100) / (up + down)).clamp(0, 100) as u8)
        } else {
            None
        };

        // Strings from SQLite come back ISO-8601 UTC (the column is
        // written that way by the writer). Parse → DateTime<Utc>.
        let parse = |s: Option<String>| -> Option<DateTime<Utc>> {
            s.as_deref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&Utc))
        };

        Ok(UptimeStat {
            window_hours,
            total_rows: total.max(0) as u64,
            up_rows: up.max(0) as u64,
            down_rows: down.max(0) as u64,
            unknown_rows: unknown.max(0) as u64,
            uptime_pct,
            last_outage_at: parse(last_outage_s),
            last_probe_at: parse(last_probe_s),
        })
    }

    /// Drop rows older than `days`. Wired by chunk 3 into the
    /// existing retention scheduler.
    pub async fn purge_node_health_older_than(&self, days: u32) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM node_health
             WHERE ts < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
        )
        .bind(format!("-{days} days"))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    // ── Phase G admin_alerts ────────────────────────────────────────────

    // ── Service-path quality samples ─────────────────────────────────

    /// Persist one low-load TCP service-path poll batch. Telemetry rows are
    /// their own audit trail, matching `node_health` and VPN stats.
    pub async fn record_service_quality_sample(
        &self,
        sample: &crate::quality::ServiceQualitySample,
    ) -> Result<()> {
        self.record_quality_sample(sample, None).await
    }

    /// Persist a completed poll with its exact service/control TCP population.
    /// Sorting makes order irrelevant; vantage changes also start a new period.
    /// Pre-provisioning rows remain raw evidence, never eligible service quality.
    pub async fn record_service_quality_sample_for_targets(
        &self,
        sample: &crate::quality::ServiceQualitySample,
        service_targets: &[std::net::SocketAddr],
        control_targets: &[std::net::SocketAddr],
    ) -> Result<()> {
        let canonical = |targets: &[std::net::SocketAddr]| {
            targets
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
        };
        let service_targets = canonical(service_targets);
        let control_targets = canonical(control_targets);
        if service_targets.len() as u64 != u64::from(sample.target_count)
            || (service_targets.is_empty() && control_targets.is_empty())
        {
            return Err(SqliteInventoryError::Invalid(
                "quality target population missing or inconsistent with sample".into(),
            ));
        }
        let identity = serde_json::to_string(&(&sample.vantage, service_targets, control_targets))?;
        self.record_quality_sample(sample, Some(&identity)).await
    }

    async fn record_quality_sample(
        &self,
        sample: &crate::quality::ServiceQualitySample,
        identity: Option<&str>,
    ) -> Result<()> {
        let tcp_json = serde_json::to_string(&sample.tcp_rtt_ms)?;
        let control_json = serde_json::to_string(&sample.control_rtt_ms)?;
        let icmp_json = sample
            .icmp_rtt_ms
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        // Serialize population selection with insertion: two concurrent writers
        // cannot join an obsolete epoch. Only completed polls change periods.
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let provisioned: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM audit_log
             WHERE target = ?1 AND action = 'server.deploy'
               AND id > (SELECT quality_deploy_audit_floor FROM servers WHERE id = ?1)
               AND julianday(ts) <= julianday(?2))",
        )
        .bind(&sample.server_id.0)
        .bind(sample.ts.to_rfc3339())
        .fetch_one(&mut *tx)
        .await?;
        let epoch = if provisioned && identity.is_some() {
            let previous: Option<(String, String)> = sqlx::query_as(
                "SELECT target_identity, measurement_epoch FROM server_quality_samples
                 WHERE server_id = ?1 AND measurement_epoch IS NOT NULL
                 ORDER BY id DESC LIMIT 1",
            )
            .bind(&sample.server_id.0)
            .fetch_optional(&mut *tx)
            .await?;
            Some(match previous {
                Some((previous_identity, epoch))
                    if Some(previous_identity.as_str()) == identity =>
                {
                    epoch
                }
                _ => vpnctl_crypto::gen_uuid(),
            })
        } else {
            None
        };
        sqlx::query(
            "INSERT INTO server_quality_samples
             (ts, server_id, vantage, target_count, available_targets,
              attempts, successes, tcp_rtt_ms_json,
              control_attempts, control_successes, control_rtt_ms_json,
              icmp_attempts, icmp_successes, icmp_rtt_ms_json,
              target_identity, measurement_epoch)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        )
        .bind(
            sample
                .ts
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        )
        .bind(&sample.server_id.0)
        .bind(&sample.vantage)
        .bind(i64::from(sample.target_count))
        .bind(i64::from(sample.available_targets))
        .bind(i64::from(sample.attempts))
        .bind(i64::from(sample.successes))
        .bind(tcp_json)
        .bind(i64::from(sample.control_attempts))
        .bind(i64::from(sample.control_successes))
        .bind(control_json)
        .bind(sample.icmp_attempts.map(i64::from))
        .bind(sample.icmp_successes.map(i64::from))
        .bind(icmp_json)
        .bind(identity)
        .bind(epoch)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Raw retained evidence in chronological order, including legacy and
    /// pre-provisioning rows. Use the provisioned variant for current quality.
    pub async fn service_quality_samples_for_server(
        &self,
        server_id: &ServerId,
        window_hours: u32,
    ) -> Result<Vec<crate::quality::ServiceQualitySample>> {
        let rows = sqlx::query(
            "SELECT ts, server_id, vantage, target_count, available_targets,
                    attempts, successes, tcp_rtt_ms_json,
                    control_attempts, control_successes, control_rtt_ms_json,
                    icmp_attempts, icmp_successes, icmp_rtt_ms_json
             FROM server_quality_samples
             WHERE server_id = ?1
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
             ORDER BY ts ASC, id ASC",
        )
        .bind(&server_id.0)
        .bind(format!("-{window_hours} hours"))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(row_to_service_quality_sample)
            .collect()
    }

    /// Legacy raw-history aggregation. Its rows may have unknown populations;
    /// use `provisioned_service_quality_for_server` for current service quality.
    pub async fn service_quality_for_server(
        &self,
        server_id: &ServerId,
        window_hours: u32,
        min_samples: u64,
    ) -> Result<crate::quality::ServiceQualityScore> {
        let samples = self
            .service_quality_samples_for_server(server_id, window_hours)
            .await?;
        Ok(crate::quality::score_samples(
            &samples,
            window_hours,
            min_samples,
        ))
    }

    /// Current identified population only. Legacy and pre-provisioning rows
    /// remain available through `service_quality_samples_for_server`, but must
    /// not feed readiness, current charts, or quality alerts.
    pub async fn provisioned_service_quality_samples_for_server(
        &self,
        server_id: &ServerId,
        window_hours: u32,
    ) -> Result<Vec<crate::quality::ServiceQualitySample>> {
        let rows = sqlx::query(
            "SELECT * FROM server_quality_samples
             WHERE server_id = ?1
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
               AND measurement_epoch = (
                   SELECT measurement_epoch FROM server_quality_samples
                   WHERE server_id = ?1 AND measurement_epoch IS NOT NULL
                   ORDER BY id DESC LIMIT 1)
               AND EXISTS(SELECT 1 FROM audit_log
                          WHERE target = ?1 AND action = 'server.deploy'
                            AND id > (SELECT quality_deploy_audit_floor FROM servers WHERE id = ?1))
             ORDER BY ts ASC, id ASC",
        )
        .bind(&server_id.0)
        .bind(format!("-{window_hours} hours"))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(row_to_service_quality_sample)
            .collect()
    }

    /// Rolling score from a single provisioned measurement period.
    pub async fn provisioned_service_quality_for_server(
        &self,
        server_id: &ServerId,
        window_hours: u32,
        min_samples: u64,
    ) -> Result<crate::quality::ServiceQualityScore> {
        let samples = self
            .provisioned_service_quality_samples_for_server(server_id, window_hours)
            .await?;
        Ok(crate::quality::score_samples(
            &samples,
            window_hours,
            min_samples,
        ))
    }

    /// Canonical deploy is provisioning evidence, not external reachability.
    /// Query failures propagate; absence is explicitly unknown, never healthy.
    pub async fn service_quality_measurement_for_server(
        &self,
        server_id: &ServerId,
    ) -> Result<crate::quality::ServiceQualityMeasurement> {
        let row = sqlx::query(
            "WITH latest AS (
                SELECT target_identity, measurement_epoch FROM server_quality_samples
                WHERE server_id = ?1 AND measurement_epoch IS NOT NULL
                ORDER BY id DESC LIMIT 1
             )
             SELECT
               (SELECT ts FROM audit_log WHERE target = ?1 AND action = 'server.deploy'
                AND id > (SELECT quality_deploy_audit_floor FROM servers WHERE id = ?1)
                ORDER BY id ASC LIMIT 1) AS provisioned_at,
               (SELECT MIN(ts) FROM server_quality_samples
                WHERE server_id = ?1 AND measurement_epoch =
                    (SELECT measurement_epoch FROM latest)) AS measurement_started_at,
               (SELECT target_identity FROM latest) AS target_identity",
        )
        .bind(&server_id.0)
        .fetch_one(&self.pool)
        .await?;
        let parse = |column: &str| -> Result<Option<DateTime<Utc>>> {
            let value: Option<String> = row.try_get(column)?;
            value
                .map(|value| {
                    DateTime::parse_from_rfc3339(&value)
                        .map(|ts| ts.with_timezone(&Utc))
                        .map_err(|e| {
                            SqliteInventoryError::Invalid(format!("quality {column}: {e}"))
                        })
                })
                .transpose()
        };
        let provisioned_at = parse("provisioned_at")?;
        Ok(crate::quality::ServiceQualityMeasurement {
            provisioned_at,
            measurement_started_at: if provisioned_at.is_some() {
                parse("measurement_started_at")?
            } else {
                None
            },
            target_identity: if provisioned_at.is_some() {
                row.try_get("target_identity")?
            } else {
                None
            },
        })
    }

    pub async fn purge_service_quality_older_than(&self, days: u32) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM server_quality_samples
             WHERE ts < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
        )
        .bind(format!("-{days} days"))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod quality_tests {
    use super::*;
    use crate::quality::ServiceQualitySample;
    use std::net::SocketAddr;

    fn sample(ts: DateTime<Utc>, success: bool) -> ServiceQualitySample {
        ServiceQualitySample {
            ts,
            server_id: ServerId("quality-test".into()),
            vantage: "test-control".into(),
            target_count: 1,
            available_targets: u32::from(success),
            attempts: 3,
            successes: if success { 3 } else { 0 },
            tcp_rtt_ms: if success { vec![10, 10, 10] } else { vec![] },
            control_attempts: 3,
            control_successes: 3,
            control_rtt_ms: vec![1, 1, 1],
            icmp_attempts: None,
            icmp_successes: None,
            icmp_rtt_ms: None,
        }
    }

    async fn fixture() -> (tempfile::TempDir, SqliteInventory, DateTime<Utc>) {
        let dir = tempfile::tempdir().unwrap();
        let inv = SqliteInventory::open(&dir.path().join("inv.db"))
            .await
            .unwrap();
        inv.add_server(&vpnctl_core::Server {
            id: ServerId("quality-test".into()),
            address: "203.0.113.10".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
        // One captured clock and wide boundaries: no timing sleeps or races.
        let now = Utc::now();
        (dir, inv, now)
    }

    async fn deploy(inv: &SqliteInventory, ts: DateTime<Utc>, action: &str) {
        sqlx::query("INSERT INTO audit_log(ts, actor, action, target) VALUES (?1, 'test', ?2, 'quality-test')")
            .bind(ts.to_rfc3339()).bind(action).execute(&inv.pool).await.unwrap();
    }

    fn target(port: u16) -> [SocketAddr; 1] {
        [SocketAddr::from(([203, 0, 113, 10], port))]
    }

    #[tokio::test]
    async fn canonical_deploy_gates_quality_without_destroying_raw_evidence() {
        let (_dir, inv, now) = fixture().await;
        let sid = ServerId("quality-test".into());
        for action in [
            "server.deploy.failed",
            "server.deploy.stale",
            "server.deploy.skipped",
        ] {
            deploy(&inv, now - chrono::Duration::hours(4), action).await;
        }
        inv.record_service_quality_sample_for_targets(
            &sample(now - chrono::Duration::hours(3), false),
            &target(443),
            &target(22),
        )
        .await
        .unwrap();
        assert_eq!(
            inv.service_quality_measurement_for_server(&sid)
                .await
                .unwrap()
                .provisioned_at,
            None
        );
        assert_eq!(
            inv.provisioned_service_quality_for_server(&sid, 24, 1)
                .await
                .unwrap()
                .sample_count,
            0
        );
        deploy(&inv, now - chrono::Duration::hours(2), "server.deploy").await;
        // Old samples are not retroactively attached after provisioning.
        inv.record_service_quality_sample_for_targets(
            &sample(now - chrono::Duration::hours(3), false),
            &target(443),
            &target(22),
        )
        .await
        .unwrap();
        let mut failed = sample(now - chrono::Duration::hours(1), false);
        inv.record_service_quality_sample_for_targets(&failed, &target(443), &target(22))
            .await
            .unwrap();
        deploy(&inv, now - chrono::Duration::minutes(30), "server.deploy").await;
        failed.ts = now;
        inv.record_service_quality_sample_for_targets(&failed, &target(443), &target(22))
            .await
            .unwrap();
        for hours in [24, 168] {
            let score = inv
                .provisioned_service_quality_for_server(&sid, hours, 2)
                .await
                .unwrap();
            assert_eq!(score.sample_count, 2);
            assert_eq!(score.score, Some(0));
            assert_eq!(score.packet_loss_pct, Some(100.0));
        }
        assert_eq!(
            inv.service_quality_samples_for_server(&sid, 24)
                .await
                .unwrap()
                .len(),
            4
        );
        let period = inv
            .service_quality_measurement_for_server(&sid)
            .await
            .unwrap();
        assert_eq!(
            period.measurement_started_at.unwrap().timestamp_millis(),
            (now - chrono::Duration::hours(1)).timestamp_millis()
        );
    }

    #[tokio::test]
    async fn equal_time_population_changes_and_reopen_preserve_partition_boundaries() {
        let (dir, inv, now) = fixture().await;
        let sid = ServerId("quality-test".into());
        deploy(&inv, now - chrono::Duration::days(10), "server.deploy").await;
        let failed = sample(now, false);
        let good = sample(now, true);
        inv.record_service_quality_sample_for_targets(&failed, &target(443), &target(22))
            .await
            .unwrap();
        inv.record_service_quality_sample_for_targets(&good, &target(8443), &target(22))
            .await
            .unwrap();
        inv.record_service_quality_sample_for_targets(&failed, &target(443), &target(22))
            .await
            .unwrap();
        // A→B→A at the same timestamp starts a third epoch, not a reunion of A.
        assert_eq!(
            inv.provisioned_service_quality_for_server(&sid, 24, 1)
                .await
                .unwrap()
                .sample_count,
            1
        );
        let reopened = SqliteInventory::open(&dir.path().join("inv.db"))
            .await
            .unwrap();
        reopened
            .record_service_quality_sample_for_targets(&failed, &target(443), &target(22))
            .await
            .unwrap();
        let score = reopened
            .provisioned_service_quality_for_server(&sid, 168, 2)
            .await
            .unwrap();
        assert_eq!(score.sample_count, 2);
        assert_eq!(score.score, Some(0));
        assert_eq!(
            reopened
                .service_quality_samples_for_server(&sid, 168)
                .await
                .unwrap()
                .len(),
            4
        );
    }

    #[tokio::test]
    async fn invalid_or_unidentified_ticks_do_not_reset_current_failure_evidence() {
        let (_dir, inv, now) = fixture().await;
        let sid = ServerId("quality-test".into());
        deploy(&inv, now - chrono::Duration::days(10), "server.deploy").await;
        inv.record_service_quality_sample_for_targets(
            &sample(now, false),
            &target(443),
            &target(22),
        )
        .await
        .unwrap();
        let before = inv
            .service_quality_measurement_for_server(&sid)
            .await
            .unwrap();
        assert!(
            inv.record_service_quality_sample_for_targets(&sample(now, true), &[], &[])
                .await
                .is_err()
        );
        // A failed insertion for a changed population must roll back its epoch.
        let mut invalid = sample(now, true);
        invalid.successes = 100;
        assert!(
            inv.record_service_quality_sample_for_targets(&invalid, &target(8443), &target(22))
                .await
                .is_err()
        );
        inv.record_service_quality_sample(&sample(now, true))
            .await
            .unwrap();
        assert_eq!(
            inv.service_quality_measurement_for_server(&sid)
                .await
                .unwrap(),
            before
        );
        assert_eq!(
            inv.provisioned_service_quality_for_server(&sid, 24, 1)
                .await
                .unwrap()
                .score,
            Some(0)
        );
    }

    #[tokio::test]
    async fn rolling_windows_filter_within_one_population_not_across_populations() {
        let (_dir, inv, now) = fixture().await;
        let sid = ServerId("quality-test".into());
        deploy(&inv, now - chrono::Duration::days(10), "server.deploy").await;
        for (hours, good) in [(8 * 24, true), (25, false), (23, true)] {
            inv.record_service_quality_sample_for_targets(
                &sample(now - chrono::Duration::hours(hours), good),
                &target(443),
                &target(22),
            )
            .await
            .unwrap();
        }
        let day = inv
            .provisioned_service_quality_for_server(&sid, 24, 1)
            .await
            .unwrap();
        let week = inv
            .provisioned_service_quality_for_server(&sid, 168, 1)
            .await
            .unwrap();
        assert_eq!(day.sample_count, 1);
        assert_eq!(day.packet_loss_pct, Some(0.0));
        assert_eq!(week.sample_count, 2);
        assert_eq!(week.packet_loss_pct, Some(50.0));
        assert_eq!(inv.purge_service_quality_older_than(7).await.unwrap(), 1);
        assert_eq!(
            inv.provisioned_service_quality_for_server(&sid, 168, 1)
                .await
                .unwrap(),
            week
        );
    }

    #[tokio::test]
    async fn target_order_is_irrelevant_but_vantage_and_control_population_are_not() {
        let (_dir, inv, now) = fixture().await;
        let sid = ServerId("quality-test".into());
        deploy(&inv, now - chrono::Duration::days(1), "server.deploy").await;
        let mut tick = sample(now, false);
        tick.target_count = 2;
        tick.attempts = 6;
        let a = target(443)[0];
        let b = target(8443)[0];
        inv.record_service_quality_sample_for_targets(&tick, &[a, b], &target(22))
            .await
            .unwrap();
        inv.record_service_quality_sample_for_targets(&tick, &[b, a, a], &target(22))
            .await
            .unwrap();
        assert_eq!(
            inv.provisioned_service_quality_for_server(&sid, 24, 2)
                .await
                .unwrap()
                .sample_count,
            2
        );
        tick.vantage = "another-control-host".into();
        inv.record_service_quality_sample_for_targets(&tick, &[a, b], &target(22))
            .await
            .unwrap();
        assert_eq!(
            inv.provisioned_service_quality_for_server(&sid, 24, 2)
                .await
                .unwrap()
                .sample_count,
            1
        );
        inv.record_service_quality_sample_for_targets(&tick, &[a, b], &target(2222))
            .await
            .unwrap();
        assert_eq!(
            inv.provisioned_service_quality_for_server(&sid, 24, 2)
                .await
                .unwrap()
                .sample_count,
            1
        );
    }

    #[tokio::test]
    async fn recreated_id_requires_new_deploy_even_with_equal_audit_timestamps() {
        let (_dir, inv, now) = fixture().await;
        let sid = ServerId("quality-test".into());
        let server = inv.get_server(&sid).await.unwrap().unwrap();
        deploy(&inv, now, "server.deploy").await;
        inv.record_service_quality_sample_for_targets(
            &sample(now, false),
            &target(443),
            &target(22),
        )
        .await
        .unwrap();
        inv.remove_server(&sid).await.unwrap();
        inv.add_server(&server).await.unwrap();
        inv.record_service_quality_sample_for_targets(
            &sample(now, false),
            &target(443),
            &target(22),
        )
        .await
        .unwrap();
        assert_eq!(
            inv.service_quality_measurement_for_server(&sid)
                .await
                .unwrap()
                .provisioned_at,
            None
        );
        assert_eq!(
            inv.provisioned_service_quality_for_server(&sid, 24, 1)
                .await
                .unwrap()
                .sample_count,
            0
        );
        // Same timestamp as the previous incarnation; only its new audit ID matters.
        deploy(&inv, now, "server.deploy").await;
        inv.record_service_quality_sample_for_targets(
            &sample(now, false),
            &target(443),
            &target(22),
        )
        .await
        .unwrap();
        assert!(
            inv.service_quality_measurement_for_server(&sid)
                .await
                .unwrap()
                .provisioned_at
                .is_some()
        );
        assert_eq!(
            inv.provisioned_service_quality_for_server(&sid, 24, 1)
                .await
                .unwrap()
                .sample_count,
            1
        );
        assert_eq!(
            inv.service_quality_samples_for_server(&sid, 24)
                .await
                .unwrap()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn migration_adds_nullable_partitions_without_changing_legacy_samples() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::raw_sql("CREATE TABLE servers(id TEXT PRIMARY KEY, created_at TEXT); CREATE TABLE audit_log(id INTEGER PRIMARY KEY, ts TEXT, target TEXT); INSERT INTO servers VALUES ('quality-test', '2026-09-09T00:00:00Z'); INSERT INTO audit_log VALUES (1, '2026-09-08T00:00:00Z', 'quality-test'), (2, '2026-09-09T00:00:00Z', 'quality-test'), (3, '2026-09-09T01:00:00Z', 'quality-test');").execute(&pool).await.unwrap();
        sqlx::raw_sql(include_str!(
            "../../migrations/0048_server_quality_samples.sql"
        ))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::raw_sql("INSERT INTO server_quality_samples(ts, server_id, vantage, target_count, available_targets, attempts, successes, tcp_rtt_ms_json, control_attempts, control_successes, control_rtt_ms_json) VALUES ('2026-09-09T00:00:00Z','quality-test','legacy',1,0,3,0,'[]',3,3,'[1]');").execute(&pool).await.unwrap();
        sqlx::raw_sql(include_str!(
            "../../migrations/0056_quality_measurement_population.sql"
        ))
        .execute(&pool)
        .await
        .unwrap();
        let row: (i64, i64, Option<String>, Option<String>) = sqlx::query_as("SELECT attempts, successes, target_identity, measurement_epoch FROM server_quality_samples").fetch_one(&pool).await.unwrap();
        assert_eq!(row, (3, 0, None, None));
        let floor: i64 = sqlx::query_scalar(
            "SELECT quality_deploy_audit_floor FROM servers WHERE id = 'quality-test'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            floor, 2,
            "exclude older and ambiguous equal-time audits but preserve strictly later evidence"
        );
    }
}
