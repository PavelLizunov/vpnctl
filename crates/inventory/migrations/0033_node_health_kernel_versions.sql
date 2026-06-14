-- Informativeness query layer (PR-Q) — capture kernel versions per probe.
--
-- The node_probe poller already records service health, disk, memory,
-- load, listening ports and the sing-box log size per tick (0007). This
-- adds the *software versions* of the on-node kernels (sing-box, caddy,
-- …) so the admin UI's drift-detail card can show "node running
-- sing-box 1.13.12, fleet target 1.13.12" without an extra SSH round
-- trip.
--
-- `kernel_versions_json` carries the BTreeMap<String,String> the probe
-- builds (deterministic key order) serialised as a JSON object, e.g.
--   {"sing-box":"1.13.12","caddy":"2.8.4"}
-- One entry per kernel the probe could read a version for. The poller
-- passes NULL when the probe captured nothing (old nodes whose probe
-- script predates the VER lines, or a partial-probe tick where the
-- version commands all failed) — so the column is **nullable**, matching
-- the 0007 nullable-on-partial-success convention.
--
-- Additive + nullable: the ~1500 production node_health rows and the
-- explicit-column `record_node_health` INSERT keep working unchanged —
-- SQLite back-fills the new column as NULL on the existing rows and the
-- INSERT simply gains one more bound parameter.

ALTER TABLE node_health ADD COLUMN kernel_versions_json TEXT;

-- Expression index for the per-server audit timeline (`audit_for_server`,
-- PR-Q Q-4c). That query is
--
--     SELECT ... FROM audit_log
--     WHERE target = ?1 OR json_extract(payload,'$.server_id') = ?1
--     ORDER BY id DESC LIMIT ?
--
-- `target` is already indexed (idx_audit_target, 0001), but the second
-- OR arm — a `json_extract` on the payload — has no index, so SQLite's
-- OR-by-union (MULTI-INDEX OR) optimisation can't fire and it falls back
-- to a full SCAN of audit_log. audit_log has NO retention purge (it is
-- the permanent audit trail), so that scan grows without bound — exactly
-- the "SCAN of a large table" the PR forbids.
--
-- Indexing the SAME expression the query filters on lets SQLite use a
-- MULTI-INDEX OR plan (idx_audit_target for arm 1, this index for arm 2,
-- no table scan). EXPLAIN QUERY PLAN on a 5050-row audit_log confirmed
-- the flip from `SCAN audit_log` to `MULTI-INDEX OR` once this index
-- exists. Additive + idempotent, no data migration.
CREATE INDEX IF NOT EXISTS idx_audit_payload_server
    ON audit_log(json_extract(payload, '$.server_id'));

-- No OTHER new index is needed — EXPLAIN QUERY PLAN (see PR description)
-- showed every other PR-Q query already served by an existing index:
--   * top_users_by_traffic_for_server / user_traffic_by_server →
--     idx_vcs_server_ts / idx_vcs_user_ts (0006).
--   * kernel_versions_fleet → idx_node_health_server_ts (0007).
--   * today_digest → idx_audit_ts (0001).
--   * user_lifecycle → idx_sub_access_log_user_ts (0003).
--   * likely_shared_summary → idx_sub_access_log_user_id_real (0021).
--   * alerts_by_kind_severity → idx_admin_alerts_unacked (0011).
